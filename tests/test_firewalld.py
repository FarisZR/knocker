"""
Tests for the firewalld integration module.

This module tests all firewalld operations including:
- Zone creation and management
- Rule addition and removal
- Startup rule recovery
- Error handling and edge cases
"""

import pytest
import time
from unittest.mock import Mock, patch, call
from src import firewalld


@pytest.fixture
def mock_settings():
    """Provides test settings with firewalld configuration."""
    return {
        "firewalld": {
            "enabled": True,
            "zone_name": "knocker-test",
            "zone_priority": -100,
            "monitored_ports": [
                {"port": 80, "protocol": "tcp"},
                {"port": 443, "protocol": "tcp"},
                {"port": 22, "protocol": "tcp"}
            ],
            "monitored_ips": [
                "0.0.0.0/0",
                "::/0"
            ]
        }
    }


@pytest.fixture
def mock_settings_disabled():
    """Provides test settings with firewalld disabled."""
    return {
        "firewalld": {
            "enabled": False
        }
    }


@pytest.fixture
def firewalld_integration(mock_settings):
    """Creates a FirewalldIntegration instance for testing."""
    return firewalld.FirewalldIntegration(mock_settings)


@pytest.fixture
def firewalld_disabled(mock_settings_disabled):
    """Creates a disabled FirewalldIntegration instance for testing."""
    return firewalld.FirewalldIntegration(mock_settings_disabled)


class TestFirewalldIntegrationInit:
    """Test initialization and configuration parsing."""
    
    def test_initialization_with_full_config(self, firewalld_integration):
        """Test proper initialization with full configuration."""
        assert firewalld_integration.enabled is True
        assert firewalld_integration.zone_name == "knocker-test"
        assert firewalld_integration.zone_priority == -100
        assert len(firewalld_integration.monitored_ports) == 3
        assert len(firewalld_integration.monitored_ips) == 2
    
    def test_initialization_disabled(self, firewalld_disabled):
        """Test initialization when firewalld is disabled."""
        assert firewalld_disabled.enabled is False
        assert firewalld_disabled.zone_name == "knocker"  # Default value
    
    def test_initialization_with_defaults(self):
        """Test initialization with minimal configuration (defaults)."""
        settings = {"firewalld": {"enabled": True}}
        integration = firewalld.FirewalldIntegration(settings)
        
        assert integration.enabled is True
        assert integration.zone_name == "knocker"
        assert integration.zone_priority == -100
        assert integration.monitored_ports == []
        assert integration.monitored_ips == []
    
    def test_is_enabled(self, firewalld_integration, firewalld_disabled):
        """Test is_enabled method."""
        assert firewalld_integration.is_enabled() is True
        assert firewalld_disabled.is_enabled() is False
    
    def test_cidr_validation_success(self):
        """Test successful CIDR validation."""
        settings = {
            "firewalld": {
                "enabled": True,
                "monitored_ips": ["192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32"]
            }
        }
        # Should not raise exception
        integration = firewalld.FirewalldIntegration(settings)
        assert integration.enabled is True
    
    def test_cidr_validation_ipv4_missing_mask(self):
        """Test CIDR validation fails for IPv4 without mask."""
        settings = {
            "firewalld": {
                "enabled": True,
                "monitored_ips": ["192.168.1.1"]  # Missing /32
            }
        }
        with pytest.raises(ValueError, match="IPv4 address.*must include network mask"):
            firewalld.FirewalldIntegration(settings)
    
    def test_cidr_validation_ipv6_missing_mask(self):
        """Test CIDR validation fails for IPv6 without mask."""
        settings = {
            "firewalld": {
                "enabled": True,
                "monitored_ips": ["2001:db8::1"]  # Missing /128
            }
        }
        with pytest.raises(ValueError, match="IPv6 address.*must include network mask"):
            firewalld.FirewalldIntegration(settings)
    
    def test_cidr_validation_invalid_ip(self):
        """Test CIDR validation fails for invalid IP."""
        settings = {
            "firewalld": {
                "enabled": True,
                "monitored_ips": ["not.an.ip/24"]
            }
        }
        with pytest.raises(ValueError, match="Invalid monitored IP configuration"):
            firewalld.FirewalldIntegration(settings)
    
    def test_cidr_validation_disabled_skips_check(self):
        """Test CIDR validation is skipped when firewalld is disabled."""
        settings = {
            "firewalld": {
                "enabled": False,
                "monitored_ips": ["192.168.1.1"]  # Invalid but should be ignored
            }
        }
        # Should not raise exception when disabled
        integration = firewalld.FirewalldIntegration(settings)
        assert integration.enabled is False


class TestFirewalldCommands:
    """Test firewall command execution."""
    
    @patch('subprocess.run')
    def test_run_firewall_cmd_success(self, mock_run, firewalld_integration):
        """Test successful firewall command execution."""
        mock_run.return_value.stdout = "success output"
        mock_run.return_value.stderr = ""
        mock_run.return_value.returncode = 0
        
        success, stdout, stderr = firewalld_integration._run_firewall_cmd(["--state"])
        
        assert success is True
        assert stdout == "success output"
        assert stderr == ""
        mock_run.assert_called_once()
    
    @patch('subprocess.run')
    def test_run_firewall_cmd_failure(self, mock_run, firewalld_integration):
        """Test failed firewall command execution."""
        from subprocess import CalledProcessError
        mock_run.side_effect = CalledProcessError(1, "firewall-cmd", stderr="error message")
        
        success, stdout, stderr = firewalld_integration._run_firewall_cmd(["--invalid"])
        
        assert success is False
        assert stderr == "error message"
    
    @patch('subprocess.run')
    def test_run_firewall_cmd_timeout(self, mock_run, firewalld_integration):
        """Test firewall command timeout."""
        from subprocess import TimeoutExpired
        mock_run.side_effect = TimeoutExpired("firewall-cmd", 30)
        
        success, stdout, stderr = firewalld_integration._run_firewall_cmd(["--slow-command"])
        
        assert success is False
        assert stderr == "Command timed out"


class TestFirewalldAvailability:
    """Test firewalld availability checking."""
    
    @patch.object(firewalld.FirewalldIntegration, '_run_firewall_cmd')
    def test_is_firewalld_available_running(self, mock_cmd, firewalld_integration):
        """Test firewalld availability when running."""
        mock_cmd.return_value = (True, "running", "")
        
        assert firewalld_integration.is_firewalld_available() is True
        mock_cmd.assert_called_once_with(["--state"], check=False)
    
    @patch.object(firewalld.FirewalldIntegration, '_run_firewall_cmd')
    def test_is_firewalld_available_not_running(self, mock_cmd, firewalld_integration):
        """Test firewalld availability when not running."""
        mock_cmd.return_value = (False, "", "not running")
        
        assert firewalld_integration.is_firewalld_available() is False


class TestZoneSetup:
    """Test knocker zone creation and setup."""
    
    @patch.object(firewalld.FirewalldIntegration, 'is_firewalld_available')
    @patch.object(firewalld.FirewalldIntegration, '_run_firewall_cmd')
    def test_setup_zone_new_zone(self, mock_cmd, mock_available, firewalld_integration):
        """Test creating a new knocker zone."""
        mock_available.return_value = True
        
        # Simulate zone doesn't exist, then successful creation
        # New behavior: adds DROP rules for each monitored port (3 ports) x 2 IP families = 6 rules
        mock_cmd.side_effect = [
            (False, "", "zone not found"),  # Zone check
            (True, "", ""),  # Create zone
            (True, "", ""),  # Set priority
            (True, "", ""),  # Add source 1 (0.0.0.0/0)
            (True, "", ""),  # Add source 2 (::/0)
            (True, "", ""),  # DROP rule port 80 IPv4
            (True, "", ""),  # DROP rule port 80 IPv6
            (True, "", ""),  # DROP rule port 443 IPv4
            (True, "", ""),  # DROP rule port 443 IPv6
            (True, "", ""),  # DROP rule port 22 IPv4
            (True, "", ""),  # DROP rule port 22 IPv6
            (True, "", "")   # Reload
        ]
        
        result = firewalld_integration.setup_knocker_zone()
        
        assert result is True
        assert mock_cmd.call_count == 12
    
    @patch.object(firewalld.FirewalldIntegration, 'is_firewalld_available')
    @patch.object(firewalld.FirewalldIntegration, '_run_firewall_cmd')
    def test_setup_zone_existing_zone(self, mock_cmd, mock_available, firewalld_integration):
        """Test setup with existing zone."""
        mock_available.return_value = True
        
        # Zone exists, so skip creation but still add DROP rules
        mock_cmd.side_effect = [
            (True, "knocker-test zone info", ""),  # Zone exists
            (True, "", ""),  # Set priority
            (True, "", ""),  # Add source 1 (0.0.0.0/0)
            (True, "", ""),  # Add source 2 (::/0)
            (True, "", ""),  # DROP rule port 80 IPv4
            (True, "", ""),  # DROP rule port 80 IPv6
            (True, "", ""),  # DROP rule port 443 IPv4
            (True, "", ""),  # DROP rule port 443 IPv6
            (True, "", ""),  # DROP rule port 22 IPv4
            (True, "", ""),  # DROP rule port 22 IPv6
            (True, "", "")   # Reload
        ]
        
        result = firewalld_integration.setup_knocker_zone()
        
        assert result is True
        assert mock_cmd.call_count == 11
    
    @patch.object(firewalld.FirewalldIntegration, 'is_firewalld_available')
    def test_setup_zone_firewalld_unavailable(self, mock_available, firewalld_integration):
        """Test zone setup when firewalld is unavailable."""
        mock_available.return_value = False
        
        result = firewalld_integration.setup_knocker_zone()
        
        assert result is False
    
    def test_setup_zone_disabled(self, firewalld_disabled):
        """Test zone setup when firewalld is disabled."""
        result = firewalld_disabled.setup_knocker_zone()
        
        assert result is True  # Returns True when disabled (no-op)


class TestWhitelistRules:
    """Test adding and removing whitelist rules."""
    
    @patch.object(firewalld.FirewalldIntegration, 'is_firewalld_available')
    @patch.object(firewalld.FirewalldIntegration, '_run_firewall_cmd')
    @patch('time.time')
    def test_add_whitelist_rule_success(self, mock_time, mock_cmd, mock_available, firewalld_integration):
        """Test successful addition of whitelist rules."""
        mock_available.return_value = True
        mock_time.return_value = 1000
        
        # Success for all three monitored ports
        mock_cmd.side_effect = [
            (True, "", ""),  # Port 80
            (True, "", ""),  # Port 443
            (True, "", "")   # Port 22
        ]
        
        result = firewalld_integration.add_whitelist_rule("192.168.1.100", 1600)
        
        assert result is True
        assert mock_cmd.call_count == 3
        
        # Verify rich rule format
        expected_calls = [
            call(['--zone=knocker-test', '--add-rich-rule=rule family="ipv4" source address="192.168.1.100" port protocol="tcp" port="80" accept priority="1000"', '--timeout=600']),
            call(['--zone=knocker-test', '--add-rich-rule=rule family="ipv4" source address="192.168.1.100" port protocol="tcp" port="443" accept priority="1000"', '--timeout=600']),
            call(['--zone=knocker-test', '--add-rich-rule=rule family="ipv4" source address="192.168.1.100" port protocol="tcp" port="22" accept priority="1000"', '--timeout=600'])
        ]
        mock_cmd.assert_has_calls(expected_calls)
    
    @patch.object(firewalld.FirewalldIntegration, 'is_firewalld_available')
    @patch.object(firewalld.FirewalldIntegration, '_run_firewall_cmd')
    @patch('time.time')
    def test_add_whitelist_rule_partial_failure(self, mock_time, mock_cmd, mock_available, firewalld_integration):
        """Test partial failure when adding whitelist rules."""
        mock_available.return_value = True
        mock_time.return_value = 1000
        
        # Failure for one port, success for others, plus rollback calls
        mock_cmd.side_effect = [
            (True, "", ""),   # Port 80 success
            (False, "", "error"),  # Port 443 failure
            (True, "", ""),   # Port 22 success
            (True, "", ""),   # Rollback Port 80 success
            (True, "", "")    # Rollback Port 22 success  
        ]
        
        result = firewalld_integration.add_whitelist_rule("192.168.1.100", 1600)
        
        assert result is False  # Should fail if not all rules added
        assert mock_cmd.call_count == 5  # 3 adds + 2 rollbacks
    
    @patch.object(firewalld.FirewalldIntegration, 'is_firewalld_available')
    def test_add_whitelist_rule_firewalld_unavailable(self, mock_available, firewalld_integration):
        """Test adding whitelist rule when firewalld is unavailable."""
        mock_available.return_value = False
        
        result = firewalld_integration.add_whitelist_rule("192.168.1.100", 1600)
        
        assert result is False
    
    def test_add_whitelist_rule_disabled(self, firewalld_disabled):
        """Test adding whitelist rule when firewalld is disabled."""
        result = firewalld_disabled.add_whitelist_rule("192.168.1.100", 1600)
        
        assert result is True  # Returns True when disabled (no-op)
    
    @patch.object(firewalld.FirewalldIntegration, 'is_firewalld_available')
    @patch.object(firewalld.FirewalldIntegration, '_run_firewall_cmd')
    def test_remove_whitelist_rule_success(self, mock_cmd, mock_available, firewalld_integration):
        """Test successful removal of whitelist rules."""
        mock_available.return_value = True
        
        # Success for all three monitored ports
        mock_cmd.side_effect = [
            (True, "", ""),  # Port 80
            (True, "", ""),  # Port 443
            (True, "", "")   # Port 22
        ]
        
        result = firewalld_integration.remove_whitelist_rule("192.168.1.100")
        
        assert result is True
        assert mock_cmd.call_count == 3
    
    @patch.object(firewalld.FirewalldIntegration, 'is_firewalld_available')
    @patch.object(firewalld.FirewalldIntegration, '_run_firewall_cmd')
    def test_remove_whitelist_rule_not_found(self, mock_cmd, mock_available, firewalld_integration):
        """Test removing rules that don't exist (should not fail)."""
        mock_available.return_value = True
        
        # All removals fail (rules not found)
        mock_cmd.side_effect = [
            (False, "", "not found"),  # Port 80
            (False, "", "not found"),  # Port 443
            (False, "", "not found")   # Port 22
        ]
        
        result = firewalld_integration.remove_whitelist_rule("192.168.1.100")
        
        assert result is True  # Should still return True (rules may have expired)


class TestRuleRecovery:
    """Test startup rule recovery functionality."""
    
    @patch.object(firewalld.FirewalldIntegration, 'is_firewalld_available')
    @patch.object(firewalld.FirewalldIntegration, '_run_firewall_cmd')
    def test_get_active_rules(self, mock_cmd, mock_available, firewalld_integration):
        """Test getting active firewalld rules."""
        mock_available.return_value = True
        
        # Mock rich rules output
        rich_rules_output = '''rule family="ipv4" source address="192.168.1.100" port protocol="tcp" port="80" accept
rule family="ipv4" source address="192.168.1.100" port protocol="tcp" port="443" accept
rule family="ipv4" source address="10.0.0.50" port protocol="tcp" port="22" accept'''
        
        mock_cmd.return_value = (True, rich_rules_output, "")
        
        rules = firewalld_integration.get_active_rules()
        
        assert len(rules) == 3
        assert rules[0].ip_address == "192.168.1.100"
        assert rules[0].port == 80
        assert rules[0].protocol == "tcp"
        assert rules[1].port == 443
        assert rules[2].ip_address == "10.0.0.50"
    
    @patch.object(firewalld.FirewalldIntegration, 'is_firewalld_available')
    @patch.object(firewalld.FirewalldIntegration, '_run_firewall_cmd')
    def test_get_active_rules_empty(self, mock_cmd, mock_available, firewalld_integration):
        """Test getting active rules when none exist."""
        mock_available.return_value = True
        mock_cmd.return_value = (True, "", "")
        
        rules = firewalld_integration.get_active_rules()
        
        assert len(rules) == 0
    
    @patch.object(firewalld.FirewalldIntegration, 'get_active_rules')
    @patch.object(firewalld.FirewalldIntegration, '_add_single_rule')
    @patch('time.time')
    def test_restore_missing_rules_success(self, mock_time, mock_add_rule, mock_get_rules, firewalld_integration):
        """Test successful restoration of missing rules."""
        mock_time.return_value = 1000
        
        # Whitelist has two IPs, but only one has active rules
        whitelist = {
            "192.168.1.100": 2000,  # Valid, expires in future
            "192.168.1.101": 2000,  # Valid, but missing from firewalld
            "192.168.1.102": 500    # Expired, should be ignored
        }
        
        # Mock active rules for only first IP and port 80
        active_rules = [
            firewalld.FirewalldRule("192.168.1.100", 80, "tcp", 2000),
            firewalld.FirewalldRule("192.168.1.100", 443, "tcp", 2000),
            firewalld.FirewalldRule("192.168.1.100", 22, "tcp", 2000)
        ]
        mock_get_rules.return_value = active_rules
        
        # Mock successful rule addition
        mock_add_rule.return_value = True
        
        result = firewalld_integration.restore_missing_rules(whitelist)
        
        assert result is True
        # Should restore 3 rules for the missing IP (192.168.1.101)
        assert mock_add_rule.call_count == 3
    
    @patch.object(firewalld.FirewalldIntegration, 'get_active_rules')
    @patch.object(firewalld.FirewalldIntegration, '_add_single_rule')
    @patch('time.time')
    def test_restore_missing_rules_no_missing(self, mock_time, mock_add_rule, mock_get_rules, firewalld_integration):
        """Test restoration when no rules are missing."""
        mock_time.return_value = 1000
        
        # Whitelist matches active rules exactly
        whitelist = {
            "192.168.1.100": 2000
        }
        
        # Mock complete active rules
        active_rules = [
            firewalld.FirewalldRule("192.168.1.100", 80, "tcp", 2000),
            firewalld.FirewalldRule("192.168.1.100", 443, "tcp", 2000),
            firewalld.FirewalldRule("192.168.1.100", 22, "tcp", 2000)
        ]
        mock_get_rules.return_value = active_rules
        
        result = firewalld_integration.restore_missing_rules(whitelist)
        
        assert result is True
        assert mock_add_rule.call_count == 0  # No rules to restore
    
    def test_restore_missing_rules_disabled(self, firewalld_disabled):
        """Test restoration when firewalld is disabled."""
        result = firewalld_disabled.restore_missing_rules({"192.168.1.100": 2000})
        
        assert result is True  # Returns True when disabled (no-op)


class TestRichRuleBuilder:
    """Test the _build_rich_rule helper function."""
    
    def test_build_rich_rule_ipv4_single_host(self, firewalld_integration):
        """Test building rich rule for IPv4 single host."""
        rule = firewalld_integration._build_rich_rule("192.168.1.100", 80, "tcp")
        expected = 'rule family="ipv4" source address="192.168.1.100" port protocol="tcp" port="80" accept priority="1000"'
        assert rule == expected
    
    def test_build_rich_rule_ipv4_cidr(self, firewalld_integration):
        """Test building rich rule for IPv4 CIDR."""
        rule = firewalld_integration._build_rich_rule("192.168.1.0/24", 443, "tcp")
        expected = 'rule family="ipv4" source address="192.168.1.0/24" port protocol="tcp" port="443" accept priority="1000"'
        assert rule == expected
    
    def test_build_rich_rule_ipv6_single_host(self, firewalld_integration):
        """Test building rich rule for IPv6 single host."""
        rule = firewalld_integration._build_rich_rule("2001:db8::1", 22, "tcp")
        expected = 'rule family="ipv6" source address="2001:db8::1" port protocol="tcp" port="22" accept priority="1000"'
        assert rule == expected
    
    def test_build_rich_rule_ipv6_cidr(self, firewalld_integration):
        """Test building rich rule for IPv6 CIDR."""
        rule = firewalld_integration._build_rich_rule("2001:db8::/32", 8080, "udp")
        expected = 'rule family="ipv6" source address="2001:db8::/32" port protocol="udp" port="8080" accept priority="1000"'
        assert rule == expected
    
    def test_build_rich_rule_invalid_ip(self, firewalld_integration):
        """Test building rich rule with invalid IP address."""
        rule = firewalld_integration._build_rich_rule("not.an.ip", 80, "tcp")
        assert rule is None
    
    def test_build_rich_rule_invalid_port(self, firewalld_integration):
        """Test building rich rule with invalid port."""
        rule = firewalld_integration._build_rich_rule("192.168.1.100", 70000, "tcp")
        assert rule is None
        
        rule = firewalld_integration._build_rich_rule("192.168.1.100", 0, "tcp")
        assert rule is None
    
    def test_build_rich_rule_invalid_protocol(self, firewalld_integration):
        """Test building rich rule with invalid protocol."""
        rule = firewalld_integration._build_rich_rule("192.168.1.100", 80, "invalid")
        assert rule is None


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_firewalld_rule_str_representation(self):
        """Test string representation of FirewalldRule."""
        rule = firewalld.FirewalldRule("192.168.1.100", 80, "tcp", 1600)
        expected = "192.168.1.100:80/tcp (expires: 1600)"
        
        assert str(rule) == expected
    
    @patch.object(firewalld.FirewalldIntegration, 'is_firewalld_available')
    @patch.object(firewalld.FirewalldIntegration, '_run_firewall_cmd')
    def test_get_active_rules_malformed_output(self, mock_cmd, mock_available, firewalld_integration):
        """Test parsing malformed rich rules output."""
        mock_available.return_value = True
        
        # Malformed rich rules output
        malformed_output = '''rule family="ipv4" source address="192.168.1.100" INVALID
invalid line
rule family="ipv4" source address="10.0.0.1" port protocol="tcp" port="invalid_port" accept'''
        
        mock_cmd.return_value = (True, malformed_output, "")
        
        rules = firewalld_integration.get_active_rules()
        
        # Should handle malformed lines gracefully
        assert len(rules) == 0  # No valid rules parsed
    
    @patch('time.time')
    def test_add_single_rule_calculation(self, mock_time, firewalld_integration):
        """Test timeout calculation in _add_single_rule."""
        mock_time.return_value = 1000
        
        with patch.object(firewalld_integration, '_run_firewall_cmd') as mock_cmd:
            mock_cmd.return_value = (True, "", "")
            
            firewalld_integration._add_single_rule("192.168.1.100", 80, "tcp", 600)
            
            # Verify timeout parameter
            call_args = mock_cmd.call_args[0][0]
            assert "--timeout=600" in call_args


class TestGlobalFunctions:
    """Test module-level functions."""
    
    def test_initialize_firewalld(self, mock_settings):
        """Test global firewalld initialization."""
        integration = firewalld.initialize_firewalld(mock_settings)
        
        assert integration is not None
        assert integration.enabled is True
        assert firewalld.get_firewalld_integration() is integration
    
    def test_get_firewalld_integration_none(self):
        """Test getting firewalld integration when not initialized."""
        firewalld.firewalld_integration = None
        
        result = firewalld.get_firewalld_integration()
        
        assert result is None


class TestSecurityAndValidation:
    """Test security considerations and input validation."""
    
    @patch.object(firewalld.FirewalldIntegration, 'is_firewalld_available')
    @patch.object(firewalld.FirewalldIntegration, '_run_firewall_cmd')
    @patch('time.time')
    def test_ip_injection_protection(self, mock_time, mock_cmd, mock_available, firewalld_integration):
        """Test that malicious IP addresses are properly rejected."""
        mock_available.return_value = True
        mock_time.return_value = 1000
        mock_cmd.return_value = (True, "", "")
        
        # Test with potentially malicious IP (command injection attempt)
        malicious_ip = "192.168.1.1; rm -rf /"
        
        result = firewalld_integration.add_whitelist_rule(malicious_ip, 1600)
        
        # Verify that the malicious IP is rejected (result should be False)
        assert result is False
        
        # Verify that _run_firewall_cmd was never called due to input validation
        mock_cmd.assert_not_called()
    
    @patch.object(firewalld.FirewalldIntegration, 'is_firewalld_available')
    @patch.object(firewalld.FirewalldIntegration, '_run_firewall_cmd')
    @patch('time.time')
    def test_zone_name_injection_protection(self, mock_time, mock_cmd, mock_available):
        """Test that zone names are handled safely (passed as-is to subprocess)."""
        mock_available.return_value = True
        mock_time.return_value = 1000
        mock_cmd.return_value = (True, "", "")
        
        # Create integration with potentially malicious zone name
        malicious_settings = {
            "firewalld": {
                "enabled": True,
                "zone_name": "test; rm -rf /",
                "monitored_ports": [{"port": 80, "protocol": "tcp"}]
            }
        }
        
        integration = firewalld.FirewalldIntegration(malicious_settings)
        result = integration.add_whitelist_rule("192.168.1.1", 1600)
        
        # Should succeed because valid IP and subprocess handles escaping
        assert result is True
        
        # Verify zone name is passed as-is (subprocess handles escaping)
        call_args = mock_cmd.call_args[0][0]
        assert "--zone=test; rm -rf /" in call_args


if __name__ == "__main__":
    pytest.main([__file__])