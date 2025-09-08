"""
Tests for Firewalld integration functionality.
"""
import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from src.firewalld_integration import FirewalldManager, FirewalldError


class TestFirewalldManager:
    """Test the FirewalldManager class."""

    def setup_method(self):
        """Setup test configuration."""
        self.config = {
            "firewalld": {
                "enabled": True,
                "monitored_ports": [80, 443, 8080],
                "zone_name": "KNOCKER",
                "priority": 100
            },
            "security": {
                "always_allowed_ips": ["192.168.1.0/24", "10.0.0.1"]
            }
        }

    def _setup_firewalld_mocks(self, mock_dbus, zone_exists=False):
        """Helper to setup firewalld mocks consistently."""
        mock_bus = Mock()
        mock_firewalld = Mock()
        mock_bus.get_object.return_value = mock_firewalld
        mock_dbus.SystemBus.return_value = mock_bus
        
        # Default mock responses
        mock_firewalld.state.return_value = "RUNNING"
        existing_zones = ["public", "internal"]
        if zone_exists:
            existing_zones.append("KNOCKER")
        mock_firewalld.getZones.return_value = existing_zones
        mock_firewalld.addZone.return_value = None
        mock_firewalld.addRichRule.return_value = None
        mock_firewalld.removeRichRule.return_value = None
        mock_firewalld.getRichRules.return_value = []
        
        return mock_bus, mock_firewalld

    @patch('src.firewalld_integration.dbus')
    def test_firewalld_manager_initialization(self, mock_dbus):
        """Test FirewalldManager initializes correctly."""
        mock_bus, mock_firewalld = self._setup_firewalld_mocks(mock_dbus)
        
        manager = FirewalldManager(self.config)
        
        assert manager.enabled is True
        assert manager.zone_name == "KNOCKER"
        assert manager.monitored_ports == [80, 443, 8080]
        assert manager.priority == 100
        mock_dbus.SystemBus.assert_called_once()

    @patch('src.firewalld_integration.dbus')
    def test_firewalld_disabled_when_config_false(self, mock_dbus):
        """Test FirewalldManager is disabled when config is false."""
        config = self.config.copy()
        config["firewalld"]["enabled"] = False
        
        manager = FirewalldManager(config)
        
        assert manager.enabled is False
        mock_dbus.SystemBus.assert_not_called()

    @patch('src.firewalld_integration.dbus')
    def test_zone_creation(self, mock_dbus):
        """Test KNOCKER zone is created with correct settings."""
        mock_bus, mock_firewalld = self._setup_firewalld_mocks(mock_dbus, zone_exists=False)
        
        manager = FirewalldManager(self.config)
        
        # Verify zone creation was attempted
        mock_firewalld.addZone.assert_called_once()
        call_args = mock_firewalld.addZone.call_args[0]
        assert call_args[0] == "KNOCKER"  # zone name
        
    @patch('src.firewalld_integration.dbus')
    def test_zone_exists_no_creation(self, mock_dbus):
        """Test no zone creation when zone already exists."""
        mock_bus, mock_firewalld = self._setup_firewalld_mocks(mock_dbus, zone_exists=True)
        
        manager = FirewalldManager(self.config)
        
        # Verify zone creation was not attempted
        mock_firewalld.addZone.assert_not_called()

    @patch('src.firewalld_integration.dbus')
    def test_add_timed_rule_ipv4(self, mock_dbus):
        """Test adding a timed firewall rule for IPv4."""
        mock_bus, mock_firewalld = self._setup_firewalld_mocks(mock_dbus)
        
        manager = FirewalldManager(self.config)
        
        # Reset call count after zone setup
        mock_firewalld.addRichRule.reset_mock()
        
        ttl = 300  # 5 minutes
        # Use an IP that's NOT in always_allowed_ips
        rule_id = manager.add_timed_rule("203.0.113.100", ttl)
        
        # Verify rich rule was added for each monitored port
        assert mock_firewalld.addRichRule.call_count == len(self.config["firewalld"]["monitored_ports"])
        
        # Check one of the calls to verify IP is in rich rule
        call_args = mock_firewalld.addRichRule.call_args_list[0][0]
        assert "203.0.113.100" in call_args[1]  # IP in rich rule
        assert "accept" in call_args[1]  # allow action
        
        # Verify rule is tracked
        assert rule_id in manager.active_rules
        assert manager.active_rules[rule_id]["ip"] == "203.0.113.100"
        assert manager.active_rules[rule_id]["expires_at"] > time.time()

    @patch('src.firewalld_integration.dbus')
    def test_add_timed_rule_ipv6(self, mock_dbus):
        """Test adding a timed firewall rule for IPv6."""
        mock_bus, mock_firewalld = self._setup_firewalld_mocks(mock_dbus)
        
        manager = FirewalldManager(self.config)
        
        # Reset call count after zone setup
        mock_firewalld.addRichRule.reset_mock()
        
        ttl = 300
        rule_id = manager.add_timed_rule("2001:db8::1", ttl)
        
        # Verify rich rule was added
        assert mock_firewalld.addRichRule.call_count > 0
        call_args = mock_firewalld.addRichRule.call_args_list[0][0]
        assert "2001:db8::1" in call_args[1]  # IPv6 in rich rule
        
        # Verify rule is tracked
        assert rule_id in manager.active_rules
        assert manager.active_rules[rule_id]["ip"] == "2001:db8::1"

    @patch('src.firewalld_integration.dbus')
    def test_add_timed_rule_cidr(self, mock_dbus):
        """Test adding a timed firewall rule for CIDR range."""
        mock_bus, mock_firewalld = self._setup_firewalld_mocks(mock_dbus)
        
        manager = FirewalldManager(self.config)
        
        # Reset call count after zone setup
        mock_firewalld.addRichRule.reset_mock()
        
        ttl = 300
        rule_id = manager.add_timed_rule("10.0.1.0/24", ttl)  # Use different CIDR not in always_allowed
        
        # Verify rich rule was added
        assert mock_firewalld.addRichRule.call_count > 0
        call_args = mock_firewalld.addRichRule.call_args_list[0][0]
        assert "10.0.1.0/24" in call_args[1]  # CIDR in rich rule
        
        # Verify rule is tracked
        assert rule_id in manager.active_rules

    @patch('src.firewalld_integration.dbus')
    def test_cleanup_expired_rules(self, mock_dbus):
        """Test cleanup of expired firewall rules."""
        mock_bus, mock_firewalld = self._setup_firewalld_mocks(mock_dbus)
        
        manager = FirewalldManager(self.config)
        
        # Add a rule that's already expired
        expired_time = int(time.time()) - 100
        rule_id = "test-rule-1"
        manager.active_rules[rule_id] = {
            "ip": "192.168.1.100",
            "expires_at": expired_time,
            "rich_rules": ['rule family="ipv4" source address="192.168.1.100" accept'],
            "created_at": expired_time - 300
        }
        
        manager.cleanup_expired_rules()
        
        # Verify expired rule was removed
        mock_firewalld.removeRichRule.assert_called()
        assert rule_id not in manager.active_rules

    @patch('src.firewalld_integration.dbus')
    def test_startup_synchronization(self, mock_dbus):
        """Test synchronization of existing rules on startup."""
        mock_bus, mock_firewalld = self._setup_firewalld_mocks(mock_dbus)
        
        # Mock existing rich rules in firewalld
        existing_rules = [
            'rule family="ipv4" source address="192.168.1.100" port port="80" protocol="tcp" accept'
        ]
        mock_firewalld.getRichRules.return_value = existing_rules
        
        manager = FirewalldManager(self.config)
        manager.synchronize_on_startup()
        
        # Should attempt to synchronize with existing rules
        mock_firewalld.getRichRules.assert_called_with("KNOCKER")

    def test_firewalld_disabled_operations_noop(self):
        """Test that operations are no-op when firewalld is disabled."""
        config = self.config.copy()
        config["firewalld"]["enabled"] = False
        
        manager = FirewalldManager(config)
        
        # These should not raise exceptions
        assert manager.add_timed_rule("192.168.1.1", 300) is None
        manager.cleanup_expired_rules()  # Should not crash
        manager.synchronize_on_startup()  # Should not crash

    @patch('src.firewalld_integration.dbus')
    def test_dbus_connection_error(self, mock_dbus):
        """Test handling of D-Bus connection errors."""
        mock_dbus.SystemBus.side_effect = Exception("D-Bus connection failed")
        
        with pytest.raises(FirewalldError):
            FirewalldManager(self.config)

    @patch('src.firewalld_integration.dbus')
    def test_firewalld_service_unavailable(self, mock_dbus):
        """Test handling when firewalld service is unavailable."""
        mock_bus = Mock()
        mock_bus.get_object.side_effect = Exception("Service unavailable")
        mock_dbus.SystemBus.return_value = mock_bus
        
        with pytest.raises(FirewalldError):
            FirewalldManager(self.config)

    @patch('src.firewalld_integration.dbus')
    def test_rule_creation_failure(self, mock_dbus):
        """Test handling of rule creation failures during timed rule addition."""
        mock_bus, mock_firewalld = self._setup_firewalld_mocks(mock_dbus)
        
        manager = FirewalldManager(self.config)
        
        # Clear the side_effect and set up a new one that fails for timed rules
        mock_firewalld.addRichRule.side_effect = None
        mock_firewalld.addRichRule.reset_mock()
        
        # Now set side effect to always fail
        mock_firewalld.addRichRule.side_effect = Exception("Rule creation failed")
        
        with pytest.raises(FirewalldError):
            manager.add_timed_rule("203.0.113.100", 300)

    @patch('src.firewalld_integration.dbus')
    def test_always_allowed_ips_bypass(self, mock_dbus):
        """Test that always allowed IPs don't get firewalld rules."""
        mock_bus, mock_firewalld = self._setup_firewalld_mocks(mock_dbus)
        
        manager = FirewalldManager(self.config)
        
        # Reset call count after zone setup
        call_count_before = mock_firewalld.addRichRule.call_count
        
        # Try to add rule for always allowed IP
        result = manager.add_timed_rule("192.168.1.100", 300)  # In always_allowed_ips CIDR
        
        call_count_after = mock_firewalld.addRichRule.call_count
        
        # Should return None (no rule created) since IP is always allowed
        assert result is None
        assert call_count_before == call_count_after  # No new calls for always allowed IP

    @patch('src.firewalld_integration.dbus')
    def test_port_specific_rules(self, mock_dbus):
        """Test that rules are created for specific monitored ports only."""
        mock_bus, mock_firewalld = self._setup_firewalld_mocks(mock_dbus)
        
        manager = FirewalldManager(self.config)
        
        # Reset call count after zone setup to focus on timed rule calls
        mock_firewalld.addRichRule.reset_mock()
        
        rule_id = manager.add_timed_rule("203.0.113.100", 300)
        
        # Should have one call per monitored port for the timed rule
        assert mock_firewalld.addRichRule.call_count == len(self.config["firewalld"]["monitored_ports"])
        
        # Each call should specify a port and contain the IP
        for call in mock_firewalld.addRichRule.call_args_list:
            rich_rule = call[0][1]
            assert "port=" in rich_rule
            assert "203.0.113.100" in rich_rule
            assert "accept" in rich_rule