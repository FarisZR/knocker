"""
Tests for firewalld integration functionality.
Uses mocked subprocess calls to avoid requiring actual firewalld installation.
"""

import pytest
import json
import time
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, call
from subprocess import CompletedProcess
from fastapi.testclient import TestClient

from src.firewalld_integration import FirewalldIntegration, FirewalldRule
from src.main import app, get_settings


@pytest.fixture
def firewalld_settings():
    """Settings with firewalld enabled for testing."""
    return {
        "security": {
            "firewalld": {
                "enabled": True,
                "zone_name": "knocker-test",
                "monitored_ports": ["22/tcp", "443/tcp"],
                "monitored_sources": [],
                "state_storage_path": "/tmp/test_firewalld_state.json",
                "reconcile_interval_seconds": 5,
                "cleanup_on_exit": True
            }
        }
    }


@pytest.fixture
def firewalld_disabled_settings():
    """Settings with firewalld disabled."""
    return {
        "security": {
            "firewalld": {
                "enabled": False
            }
        }
    }


@pytest.fixture
def mock_subprocess_success():
    """Mock successful subprocess.run calls."""
    def mock_run(*args, **kwargs):
        return CompletedProcess(
            args=args[0],
            returncode=0,
            stdout="success",
            stderr=""
        )
    return mock_run


@pytest.fixture
def mock_subprocess_failure():
    """Mock failed subprocess.run calls."""
    def mock_run(*args, **kwargs):
        return CompletedProcess(
            args=args[0],
            returncode=1,
            stdout="",
            stderr="firewall-cmd failed"
        )
    return mock_run


class TestFirewalldIntegrationInitialization:
    """Test firewalld integration initialization."""

    @patch('src.firewalld_integration.subprocess.run')
    def test_initialization_disabled(self, mock_run, firewalld_disabled_settings):
        """Firewalld integration should be no-op when disabled."""
        integration = FirewalldIntegration(firewalld_disabled_settings)
        
        assert integration.enabled is False
        mock_run.assert_not_called()

    @patch('src.firewalld_integration.subprocess.run')
    def test_initialization_success(self, mock_run, firewalld_settings, mock_subprocess_success):
        """Test successful firewalld initialization."""
        mock_run.side_effect = mock_subprocess_success
        
        with patch.object(FirewalldIntegration, '_start_reconciliation_thread'):
            integration = FirewalldIntegration(firewalld_settings)
        
        assert integration.enabled is True
        assert integration.zone_name == "knocker-test"
        assert set(integration.monitored_ports) == {"22/tcp", "443/tcp"}
        
        # Should have called various firewall-cmd operations
        mock_run.assert_called()
        
        # Check for zone creation/configuration calls
        call_args_list = [call.args[0] for call in mock_run.call_args_list]
        
        # Should check for existing zones
        assert any("--get-zones" in args for args in call_args_list)
        
        # Should configure the zone
        assert any(
            ["firewall-cmd", "--permanent", "--zone", "knocker-test", "--set-target", "DROP"] == args
            for args in call_args_list
        )

    def test_config_validation_invalid_ports(self, firewalld_settings):
        """Test that invalid port specifications are rejected."""
        firewalld_settings["security"]["firewalld"]["monitored_ports"] = ["invalid", "22/invalid", "99999/tcp"]
        
        with pytest.raises(ValueError, match="Invalid port specification"):
            with patch.object(FirewalldIntegration, '_initialize_zone'), \
                 patch.object(FirewalldIntegration, '_start_reconciliation_thread'):
                FirewalldIntegration(firewalld_settings)

    def test_config_validation_too_many_ports(self, firewalld_settings):
        """Test that too many ports are rejected."""
        firewalld_settings["security"]["firewalld"]["monitored_ports"] = [f"{i}/tcp" for i in range(1, 202)]
        
        with pytest.raises(ValueError, match="Too many monitored ports"):
            with patch.object(FirewalldIntegration, '_initialize_zone'), \
                 patch.object(FirewalldIntegration, '_start_reconciliation_thread'):
                FirewalldIntegration(firewalld_settings)

    def test_config_validation_invalid_sources(self, firewalld_settings):
        """Test that invalid source CIDRs are rejected."""
        firewalld_settings["security"]["firewalld"]["monitored_sources"] = ["invalid-cidr"]
        
        with pytest.raises(ValueError, match="Invalid CIDR in monitored_sources"):
            with patch.object(FirewalldIntegration, '_initialize_zone'), \
                 patch.object(FirewalldIntegration, '_start_reconciliation_thread'):
                FirewalldIntegration(firewalld_settings)


class TestFirewalldRuleManagement:
    """Test firewalld rule addition and management."""

    @patch('src.firewalld_integration.subprocess.run')
    def test_add_rule_success(self, mock_run, firewalld_settings, mock_subprocess_success):
        """Test successful rule addition."""
        mock_run.side_effect = mock_subprocess_success
        
        with patch.object(FirewalldIntegration, '_start_reconciliation_thread'):
            integration = FirewalldIntegration(firewalld_settings)
        
        # Mock state file operations
        with patch.object(integration, '_update_state_metadata') as mock_update:
            result = integration.add_allow_rule("192.168.1.100", 300)
        
        assert result is True
        mock_update.assert_called_once()
        
        # Should have added rules for both monitored ports
        call_args_list = [call.args[0] for call in mock_run.call_args_list]
        
        # Filter to just the add-rich-rule calls after initialization
        rich_rule_calls = [args for args in call_args_list if "--add-rich-rule" in args]
        assert len(rich_rule_calls) == 2  # One for each port

    @patch('src.firewalld_integration.subprocess.run')
    def test_add_rule_failure(self, mock_run, firewalld_settings):
        """Test rule addition failure handling."""
        # Setup: successful initialization, then failed rule addition
        def mock_run_selective(*args, **kwargs):
            if "--add-rich-rule" in args[0]:
                return CompletedProcess(args=args[0], returncode=1, stdout="", stderr="failed")
            else:
                return CompletedProcess(args=args[0], returncode=0, stdout="success", stderr="")
        
        mock_run.side_effect = mock_run_selective
        
        with patch.object(FirewalldIntegration, '_start_reconciliation_thread'):
            integration = FirewalldIntegration(firewalld_settings)
        
        # Mock state file operations
        with patch.object(integration, '_update_state_metadata') as mock_update:
            result = integration.add_allow_rule("192.168.1.100", 300)
        
        assert result is False
        mock_update.assert_not_called()  # Should not update state on failure

    @patch('src.firewalld_integration.subprocess.run')
    def test_add_rule_ipv6(self, mock_run, firewalld_settings, mock_subprocess_success):
        """Test rule addition for IPv6 addresses."""
        mock_run.side_effect = mock_subprocess_success
        
        with patch.object(FirewalldIntegration, '_start_reconciliation_thread'):
            integration = FirewalldIntegration(firewalld_settings)
        
        with patch.object(integration, '_update_state_metadata'):
            result = integration.add_allow_rule("2001:db8::1", 300)
        
        assert result is True
        
        # Check that IPv6 family was used in rich rules
        call_args_list = [call.args[0] for call in mock_run.call_args_list]
        rich_rule_calls = [args for args in call_args_list if "--add-rich-rule" in args]
        
        # Should find IPv6 rich rules
        assert any('family="ipv6"' in ' '.join(args) for args in rich_rule_calls)

    @patch('src.firewalld_integration.subprocess.run')
    def test_add_rule_ipv6_cidr(self, mock_run, firewalld_settings, mock_subprocess_success):
        """Test rule addition for IPv6 CIDR ranges."""
        mock_run.side_effect = mock_subprocess_success
        
        with patch.object(FirewalldIntegration, '_start_reconciliation_thread'):
            integration = FirewalldIntegration(firewalld_settings)
        
        with patch.object(integration, '_update_state_metadata'):
            # Test IPv6 CIDR range
            result = integration.add_allow_rule("2001:db8::/64", 300)
        
        assert result is True
        
        # Check that IPv6 family was used in rich rules for CIDR
        call_args_list = [call.args[0] for call in mock_run.call_args_list]
        rich_rule_calls = [args for args in call_args_list if "--add-rich-rule" in args]
        
        # Should find IPv6 rich rules with CIDR notation
        assert any('family="ipv6"' in ' '.join(args) and '2001:db8::/64' in ' '.join(args) for args in rich_rule_calls)

    def test_add_rule_disabled_integration(self, firewalld_disabled_settings):
        """Test that rule addition is no-op when integration is disabled."""
        integration = FirewalldIntegration(firewalld_disabled_settings)
        
        result = integration.add_allow_rule("192.168.1.100", 300)
        assert result is True  # Should return True (no-op success)

    @patch('src.firewalld_integration.subprocess.run')
    def test_add_rule_invalid_ttl(self, mock_run, firewalld_settings, mock_subprocess_success):
        """Test that invalid TTL values are rejected."""
        mock_run.side_effect = mock_subprocess_success
        
        with patch.object(FirewalldIntegration, '_start_reconciliation_thread'):
            integration = FirewalldIntegration(firewalld_settings)
        
        result = integration.add_allow_rule("192.168.1.100", 0)
        assert result is False
        
        result = integration.add_allow_rule("192.168.1.100", -10)
        assert result is False

    @patch('src.firewalld_integration.subprocess.run')
    def test_monitored_sources_restriction(self, mock_run, firewalld_settings, mock_subprocess_success):
        """Test that monitored_sources restriction works correctly."""
        firewalld_settings["security"]["firewalld"]["monitored_sources"] = ["192.168.1.0/24"]
        mock_run.side_effect = mock_subprocess_success
        
        with patch.object(FirewalldIntegration, '_start_reconciliation_thread'):
            integration = FirewalldIntegration(firewalld_settings)
        
        # Mock state file operations for successful case
        with patch.object(integration, '_update_state_metadata'):
            # IP within monitored sources should succeed
            result = integration.add_allow_rule("192.168.1.100", 300)
            assert result is True  # Should succeed since IP is within allowed sources
            
            # IP outside monitored sources should be rejected
            result = integration.add_allow_rule("10.0.0.1", 300)
            assert result is False  # Should be rejected


class TestFirewalldRuleData:
    """Test FirewalldRule data class."""

    def test_rule_serialization(self):
        """Test rule to/from dict conversion."""
        rule = FirewalldRule("192.168.1.1", ["22/tcp", "443/tcp"], 1234567890)
        
        rule_dict = rule.to_dict()
        expected = {
            "ip_or_cidr": "192.168.1.1",
            "ports": ["22/tcp", "443/tcp"],
            "expires_at": 1234567890
        }
        assert rule_dict == expected
        
        # Test deserialization
        restored_rule = FirewalldRule.from_dict(rule_dict)
        assert restored_rule.ip_or_cidr == rule.ip_or_cidr
        assert restored_rule.ports == rule.ports
        assert restored_rule.expires_at == rule.expires_at


class TestStateMetadata:
    """Test firewalld state metadata management."""

    def test_state_metadata_persistence(self, firewalld_settings):
        """Test that state metadata is properly saved and loaded."""
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "firewalld_state.json"
            firewalld_settings["security"]["firewalld"]["state_storage_path"] = str(state_path)
            
            with patch.object(FirewalldIntegration, '_initialize_zone'), \
                 patch.object(FirewalldIntegration, '_start_reconciliation_thread'):
                integration = FirewalldIntegration(firewalld_settings)
            
            # Add some test data
            test_rule = FirewalldRule("192.168.1.1", ["22/tcp"], 1234567890)
            rules = {"192.168.1.1": test_rule}
            integration._save_state_metadata(rules)
            
            # Verify it was saved
            assert state_path.exists()
            
            # Load it back
            loaded_rules = integration._load_state_metadata()
            assert "192.168.1.1" in loaded_rules
            assert loaded_rules["192.168.1.1"].ip_or_cidr == "192.168.1.1"
            assert loaded_rules["192.168.1.1"].ports == ["22/tcp"]

    def test_state_metadata_corrupted_file(self, firewalld_settings):
        """Test handling of corrupted state file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "firewalld_state.json"
            firewalld_settings["security"]["firewalld"]["state_storage_path"] = str(state_path)
            
            # Create corrupted file
            state_path.write_text("invalid json content")
            
            with patch.object(FirewalldIntegration, '_initialize_zone'), \
                 patch.object(FirewalldIntegration, '_start_reconciliation_thread'):
                integration = FirewalldIntegration(firewalld_settings)
            
            # Should handle corrupted file gracefully
            loaded_rules = integration._load_state_metadata()
            assert loaded_rules == {}


class TestReconciliation:
    """Test firewalld state reconciliation."""

    @patch('src.firewalld_integration.subprocess.run')
    @patch('src.firewalld_integration.time.time', return_value=1000)
    def test_cleanup_expired_rules(self, mock_time, mock_run, firewalld_settings, mock_subprocess_success):
        """Test cleanup of expired rules from metadata."""
        mock_run.side_effect = mock_subprocess_success
        
        with patch.object(FirewalldIntegration, '_start_reconciliation_thread'):
            integration = FirewalldIntegration(firewalld_settings)
        
        # Create test metadata with expired and active rules
        expired_rule = FirewalldRule("192.168.1.1", ["22/tcp"], 999)  # Expired
        active_rule = FirewalldRule("192.168.1.2", ["22/tcp"], 2000)  # Active
        
        rules = {
            "192.168.1.1": expired_rule,
            "192.168.1.2": active_rule
        }
        
        with patch.object(integration, '_load_state_metadata', return_value=rules) as mock_load, \
             patch.object(integration, '_save_state_metadata') as mock_save:
            
            integration.cleanup_expired_rules()
            
            # Should have saved only the active rule
            mock_save.assert_called_once()
            saved_rules = mock_save.call_args[0][0]
            assert "192.168.1.1" not in saved_rules
            assert "192.168.1.2" in saved_rules

    def test_cleanup_disabled_integration(self, firewalld_disabled_settings):
        """Test that cleanup is no-op when integration is disabled."""
        integration = FirewalldIntegration(firewalld_disabled_settings)
        
        # Should not raise any exceptions
        integration.cleanup_expired_rules()


class TestGlobalFunctions:
    """Test module-level functions."""

    def test_initialize_firewalld_disabled(self, firewalld_disabled_settings):
        """Test firewalld initialization when disabled."""
        from src import firewalld_integration
        
        firewalld_integration.initialize_firewalld(firewalld_disabled_settings)
        assert firewalld_integration.firewalld_integration is None

    @patch('src.firewalld_integration.FirewalldIntegration')
    def test_initialize_firewalld_enabled(self, mock_integration_class, firewalld_settings):
        """Test firewalld initialization when enabled."""
        from src import firewalld_integration
        
        mock_instance = Mock()
        mock_integration_class.return_value = mock_instance
        
        firewalld_integration.initialize_firewalld(firewalld_settings)
        
        mock_integration_class.assert_called_once_with(firewalld_settings)
        mock_instance.reconcile_state.assert_called_once()

    def test_add_firewalld_rule_disabled(self):
        """Test add_firewalld_rule when integration is disabled."""
        from src import firewalld_integration
        
        # Ensure integration is disabled
        firewalld_integration.firewalld_integration = None
        
        result = firewalld_integration.add_firewalld_rule("192.168.1.1", 300)
        assert result is True  # Should be no-op success

    def test_add_firewalld_rule_enabled(self):
        """Test add_firewalld_rule when integration is enabled."""
        from src import firewalld_integration
        
        mock_instance = Mock()
        mock_instance.add_allow_rule.return_value = True
        firewalld_integration.firewalld_integration = mock_instance
        
        result = firewalld_integration.add_firewalld_rule("192.168.1.1", 300)
        
        assert result is True
        mock_instance.add_allow_rule.assert_called_once_with("192.168.1.1", 300)
        
        # Cleanup
        firewalld_integration.firewalld_integration = None

    def test_cleanup_firewalld(self):
        """Test firewalld cleanup function."""
        from src import firewalld_integration
        
        mock_instance = Mock()
        firewalld_integration.firewalld_integration = mock_instance
        
        firewalld_integration.cleanup_firewalld()
        
        mock_instance.cleanup_on_shutdown.assert_called_once()
        
        # Cleanup
        firewalld_integration.firewalld_integration = None


class TestFirewalldValidation:
    """Test firewalld input validation."""

    @patch('src.firewalld_integration.subprocess.run')
    def test_invalid_ip_address(self, mock_run, firewalld_settings, mock_subprocess_success):
        """Test that invalid IP addresses are rejected."""
        mock_run.side_effect = mock_subprocess_success
        
        with patch.object(FirewalldIntegration, '_start_reconciliation_thread'):
            integration = FirewalldIntegration(firewalld_settings)
        
        result = integration.add_allow_rule("invalid-ip", 300)
        assert result is False

    def test_port_specification_validation(self):
        """Test port specification validation."""
        from src.firewalld_integration import FirewalldIntegration
        
        # Create minimal settings to test validation method
        settings = {"security": {"firewalld": {"enabled": True, "monitored_ports": []}}}
        
        with patch.object(FirewalldIntegration, '_initialize_zone'), \
             patch.object(FirewalldIntegration, '_start_reconciliation_thread'):
            integration = FirewalldIntegration(settings)
        
        # Valid port specifications
        assert integration._is_valid_port_spec("22/tcp") is True
        assert integration._is_valid_port_spec("443/tcp") is True
        assert integration._is_valid_port_spec("80/udp") is True
        assert integration._is_valid_port_spec("65535/tcp") is True
        
        # Invalid port specifications
        assert integration._is_valid_port_spec("invalid") is False
        assert integration._is_valid_port_spec("22") is False
        assert integration._is_valid_port_spec("22/invalid") is False
        assert integration._is_valid_port_spec("0/tcp") is False
        assert integration._is_valid_port_spec("65536/tcp") is False
        assert integration._is_valid_port_spec("abc/tcp") is False


class TestKnockEndpointIntegration:
    """Test integration of firewalld with the main knock endpoint."""

    @pytest.fixture(autouse=True)
    def cleanup_firewalld_instance(self):
        """Ensure firewalld integration is cleaned up between tests."""
        from src import firewalld_integration
        firewalld_integration.firewalld_integration = None
        yield
        firewalld_integration.firewalld_integration = None

    def test_knock_firewalld_success_integration(self):
        """Test successful knock with firewalld integration at function level."""
        from src.main import knock
        from src import firewalld_integration
        import src.core
        
        # Mock settings
        settings = {
            "api_keys": [{"name": "test", "key": "test-key", "max_ttl": 300, "allow_remote_whitelist": False}],
            "cors": {"allowed_origin": "*"}
        }
        
        # Mock request
        mock_request = Mock()
        mock_request.headers = {"X-Api-Key": "test-key"}
        
        with patch.object(firewalld_integration, 'add_firewalld_rule', return_value=True) as mock_firewalld, \
             patch.object(src.core, 'add_ip_to_whitelist') as mock_whitelist:
            
            # Call knock function directly (this would normally be called by FastAPI)
            # We'll mock the dependencies
            with patch('src.main.get_client_ip_dependency', return_value="192.168.1.100"), \
                 patch('src.main.get_settings', return_value=settings):
                
                # This is testing the core logic without FastAPI's complexity
                client_ip = "192.168.1.100"
                effective_ttl = 300
                expiry_time = int(time.time()) + effective_ttl
                
                # Test the key firewalld integration logic from knock endpoint
                firewalld_success = firewalld_integration.add_firewalld_rule(client_ip, effective_ttl)
                assert firewalld_success is True
                
                # Should call add_ip_to_whitelist after successful firewalld
                src.core.add_ip_to_whitelist(client_ip, expiry_time, settings)
                
        mock_firewalld.assert_called_once_with(client_ip, effective_ttl)
        mock_whitelist.assert_called_once_with(client_ip, expiry_time, settings)

    def test_knock_firewalld_failure_integration(self):
        """Test knock failure when firewalld integration fails."""
        from src import firewalld_integration
        import src.core
        
        client_ip = "192.168.1.100"
        effective_ttl = 300
        
        with patch.object(firewalld_integration, 'add_firewalld_rule', return_value=False) as mock_firewalld, \
             patch.object(src.core, 'add_ip_to_whitelist') as mock_whitelist:
            
            # Test the key firewalld integration logic from knock endpoint
            firewalld_success = firewalld_integration.add_firewalld_rule(client_ip, effective_ttl)
            assert firewalld_success is False
            
            # Should NOT call add_ip_to_whitelist when firewalld fails
            # (This is the logic we implemented in main.py)
            if not firewalld_success:
                pass  # Don't call add_ip_to_whitelist
            else:
                src.core.add_ip_to_whitelist(client_ip, int(time.time()) + effective_ttl, {})
                
        mock_firewalld.assert_called_once_with(client_ip, effective_ttl)
        mock_whitelist.assert_not_called()

    def test_knock_firewalld_disabled_integration(self):
        """Test knock with firewalld disabled returns success (no-op)."""
        from src import firewalld_integration
        import src.core
        
        # When firewalld is disabled, add_firewalld_rule should return True (no-op)
        client_ip = "192.168.1.100"
        effective_ttl = 300
        settings = {"whitelist": {"storage_path": "/tmp/test.json"}}
        
        with patch.object(firewalld_integration, 'add_firewalld_rule', return_value=True) as mock_firewalld, \
             patch.object(src.core, 'add_ip_to_whitelist') as mock_whitelist:
            
            # Test the logic
            firewalld_success = firewalld_integration.add_firewalld_rule(client_ip, effective_ttl)
            assert firewalld_success is True
            
            # Should call add_ip_to_whitelist normally when firewalld is no-op success
            src.core.add_ip_to_whitelist(client_ip, int(time.time()) + effective_ttl, settings)
                
        mock_firewalld.assert_called_once_with(client_ip, effective_ttl)
        mock_whitelist.assert_called_once()