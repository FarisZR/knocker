"""
Tests for firewalld integration in main endpoints.

This module tests the integration between the FastAPI endpoints and firewalld,
including error handling, startup behavior, and proper sequencing.
"""

import pytest
import time
import os
import tempfile
from unittest.mock import Mock, patch, MagicMock
from fastapi.testclient import TestClient
import json

from src import core


# Create separate test files for these integration tests
def create_temp_config_file(config_dict):
    """Create a temporary config file and return its path."""
    import yaml
    fd, path = tempfile.mkstemp(suffix='.yaml', text=True)
    try:
        with os.fdopen(fd, 'w') as f:
            yaml.dump(config_dict, f)
        return path
    except:
        os.unlink(path)
        raise


class TestCoreFirewalldIntegrationFunction:
    """Test the core add_ip_to_whitelist_with_firewalld function."""
    
    def setup_method(self):
        """Setup for each test."""
        # Clean up any existing whitelist file
        if os.path.exists("/tmp/test_whitelist.json"):
            os.remove("/tmp/test_whitelist.json")
    
    @patch('src.firewalld.get_firewalld_integration')
    def test_add_with_firewalld_success(self, mock_get_integration):
        """Test successful addition with firewalld enabled."""
        # Mock firewalld integration
        mock_integration = Mock()
        mock_integration.is_enabled.return_value = True
        mock_integration.add_whitelist_rule.return_value = True
        mock_get_integration.return_value = mock_integration
        
        settings = {"whitelist": {"storage_path": "/tmp/test_whitelist.json"}}
        
        result = core.add_ip_to_whitelist_with_firewalld("192.168.1.100", 1700000000, settings)
        
        assert result is True
        
        # Verify firewalld was called
        mock_integration.add_whitelist_rule.assert_called_once_with("192.168.1.100", 1700000000)
        
        # Verify whitelist.json was updated
        whitelist = core.load_whitelist(settings)
        assert "192.168.1.100" in whitelist
        assert whitelist["192.168.1.100"] == 1700000000
    
    @patch('src.firewalld.get_firewalld_integration')  
    def test_add_with_firewalld_failure(self, mock_get_integration):
        """Test addition failure when firewalld fails."""
        # Mock firewalld integration failure
        mock_integration = Mock()
        mock_integration.is_enabled.return_value = True
        mock_integration.add_whitelist_rule.return_value = False  # Firewalld failed
        mock_get_integration.return_value = mock_integration
        
        settings = {"whitelist": {"storage_path": "/tmp/test_whitelist.json"}}
        
        result = core.add_ip_to_whitelist_with_firewalld("192.168.1.100", 1700000000, settings)
        
        assert result is False
        
        # Verify firewalld was called
        mock_integration.add_whitelist_rule.assert_called_once_with("192.168.1.100", 1700000000)
        
        # Verify whitelist.json was NOT updated
        whitelist = core.load_whitelist(settings)
        assert "192.168.1.100" not in whitelist
    
    @patch('src.firewalld.get_firewalld_integration')
    def test_add_with_firewalld_disabled(self, mock_get_integration):
        """Test addition when firewalld is disabled."""
        # Mock disabled firewalld integration
        mock_integration = Mock()
        mock_integration.is_enabled.return_value = False
        mock_get_integration.return_value = mock_integration
        
        settings = {"whitelist": {"storage_path": "/tmp/test_whitelist.json"}}
        
        result = core.add_ip_to_whitelist_with_firewalld("192.168.1.100", 1700000000, settings)
        
        assert result is True
        
        # Verify firewalld add_whitelist_rule was NOT called (since disabled)
        mock_integration.add_whitelist_rule.assert_not_called()
        
        # Verify whitelist.json was still updated
        whitelist = core.load_whitelist(settings)
        assert "192.168.1.100" in whitelist
    
    @patch('src.firewalld.get_firewalld_integration')
    def test_add_with_no_firewalld_integration(self, mock_get_integration):
        """Test addition when firewalld integration is not available."""
        # Mock no firewalld integration
        mock_get_integration.return_value = None
        
        settings = {"whitelist": {"storage_path": "/tmp/test_whitelist.json"}}
        
        result = core.add_ip_to_whitelist_with_firewalld("192.168.1.100", 1700000000, settings)
        
        assert result is True
        
        # Verify whitelist.json was updated (fallback behavior)
        whitelist = core.load_whitelist(settings)
        assert "192.168.1.100" in whitelist

    @patch('src.firewalld.get_firewalld_integration')
    def test_add_with_firewalld_rollback_on_whitelist_failure(self, mock_get_integration):
        """Test rollback when whitelist.json update fails."""
        with patch('src.core.add_ip_to_whitelist') as mock_add_whitelist:
            # Mock firewalld integration success
            mock_integration = Mock()
            mock_integration.is_enabled.return_value = True
            mock_integration.add_whitelist_rule.return_value = True
            mock_integration.remove_whitelist_rule.return_value = True
            mock_get_integration.return_value = mock_integration
            
            # Mock whitelist.json update failure
            mock_add_whitelist.side_effect = Exception("Disk full")
            
            settings = {"whitelist": {"storage_path": "/tmp/test_whitelist.json"}}
            
            result = core.add_ip_to_whitelist_with_firewalld("192.168.1.100", 1700000000, settings)
            
            assert result is False
            
            # Verify firewalld rules were added then rolled back
            mock_integration.add_whitelist_rule.assert_called_once_with("192.168.1.100", 1700000000)
            mock_integration.remove_whitelist_rule.assert_called_once_with("192.168.1.100")
            
            # Verify whitelist.json update was attempted
            mock_add_whitelist.assert_called_once()


class TestEndpointFirewalldIntegration:
    """Test endpoint integration with firewalld using simpler approach."""
    
    def test_knock_endpoint_firewalld_success(self):
        """Test knock endpoint calls firewalld integration correctly."""
        # Create config with firewalld enabled
        config_dict = {
            "server": {"host": "0.0.0.0", "port": 8000, "trusted_proxies": ["127.0.0.0/8"]},
            "cors": {"allowed_origin": "*"},
            "whitelist": {"storage_path": "/tmp/test_whitelist.json"},
            "api_keys": [{"key": "test_key", "max_ttl": 3600, "allow_remote_whitelist": False}],
            "firewalld": {"enabled": True, "zone_name": "test", "monitored_ports": [{"port": 80, "protocol": "tcp"}]}
        }
        
        config_path = create_temp_config_file(config_dict)
        
        try:
            # Set environment variable for config
            os.environ["KNOCKER_CONFIG_PATH"] = config_path
            
            # Import and patch firewalld after setting config
            with patch('src.firewalld.FirewalldIntegration') as mock_firewalld_class:
                # Mock the FirewalldIntegration class
                mock_integration = Mock()
                mock_integration.is_enabled.return_value = True
                # Ensure version check passes in mocked integration
                mock_integration._check_firewalld_version.return_value = True
                mock_integration.setup_knocker_zone.return_value = True
                mock_integration.restore_missing_rules.return_value = True
                mock_integration.add_whitelist_rule.return_value = True
                mock_firewalld_class.return_value = mock_integration
                
                # Mock the global instance
                import src.firewalld as firewalld_module
                firewalld_module.firewalld_integration = mock_integration
                
                from src import main
                
                # Create test client
                client = TestClient(main.app)
                
                # Test successful knock
                response = client.post(
                    "/knock",
                    headers={
                        "X-Api-Key": "test_key",
                        "X-Forwarded-For": "192.168.1.100"
                    }
                )
                
                assert response.status_code == 200
                data = response.json()
                assert data["whitelisted_entry"] == "192.168.1.100"
                
        finally:
            # Cleanup
            if "KNOCKER_CONFIG_PATH" in os.environ:
                del os.environ["KNOCKER_CONFIG_PATH"]
            if os.path.exists(config_path):
                os.unlink(config_path)
            if os.path.exists("/tmp/test_whitelist.json"):
                os.unlink("/tmp/test_whitelist.json")
    
    def test_knock_endpoint_firewalld_disabled(self):
        """Test knock endpoint when firewalld is disabled."""
        config_dict = {
            "server": {"host": "0.0.0.0", "port": 8000, "trusted_proxies": ["127.0.0.0/8"]},
            "cors": {"allowed_origin": "*"},
            "whitelist": {"storage_path": "/tmp/test_whitelist.json"},
            "api_keys": [{"key": "test_key", "max_ttl": 3600, "allow_remote_whitelist": False}],
            "firewalld": {"enabled": False}
        }
        
        config_path = create_temp_config_file(config_dict)
        
        try:
            os.environ["KNOCKER_CONFIG_PATH"] = config_path
            
            with patch('src.firewalld.FirewalldIntegration') as mock_firewalld_class:
                # Mock disabled firewalld integration
                mock_integration = Mock()
                mock_integration.is_enabled.return_value = False
                # Provide compatible version check stub even if disabled (harmless)
                mock_integration._check_firewalld_version.return_value = True
                mock_firewalld_class.return_value = mock_integration
                
                import src.firewalld as firewalld_module
                firewalld_module.firewalld_integration = mock_integration
                
                from src import main
                
                client = TestClient(main.app)
                
                # Test successful knock with firewalld disabled
                response = client.post(
                    "/knock",
                    headers={
                        "X-Api-Key": "test_key",
                        "X-Forwarded-For": "192.168.1.100"
                    }
                )
                
                assert response.status_code == 200
                data = response.json()
                assert data["whitelisted_entry"] == "192.168.1.100"
                
        finally:
            if "KNOCKER_CONFIG_PATH" in os.environ:
                del os.environ["KNOCKER_CONFIG_PATH"]
            if os.path.exists(config_path):
                os.unlink(config_path)
            if os.path.exists("/tmp/test_whitelist.json"):
                os.unlink("/tmp/test_whitelist.json")


if __name__ == "__main__":
    pytest.main([__file__])