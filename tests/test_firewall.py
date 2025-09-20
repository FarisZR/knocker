"""
Tests for the firewall module.
"""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from src import fw_integration as firewall

# Test configuration fixtures

@pytest.fixture
def firewall_enabled_settings():
    """Settings with firewall integration enabled."""
    return {
        "firewall": {
            "enabled": True,
            "monitored_ports": ["80/tcp", "443/tcp", "22/tcp"]
        },
        "security": {
            "always_allowed_ips": ["192.168.1.0/24", "10.0.0.1"]
        },
        "whitelist": {
            "storage_path": "/tmp/test_whitelist.json"
        }
    }

@pytest.fixture
def firewall_disabled_settings():
    """Settings with firewall integration disabled."""
    return {
        "firewall": {
            "enabled": False,
            "monitored_ports": ["80/tcp", "443/tcp"]
        }
    }

@pytest.fixture
def minimal_settings():
    """Minimal settings without firewall configuration."""
    return {
        "security": {},
        "whitelist": {
            "storage_path": "/tmp/test_whitelist.json"
        }
    }

# Test Configuration Functions

def test_is_firewalld_enabled_true(firewall_enabled_settings):
    """Test that firewall enabled detection works when enabled."""
    assert firewall.is_firewalld_enabled(firewall_enabled_settings) == True

def test_is_firewalld_enabled_false(firewall_disabled_settings):
    """Test that firewall enabled detection works when disabled."""
    assert firewall.is_firewalld_enabled(firewall_disabled_settings) == False

def test_is_firewalld_enabled_default(minimal_settings):
    """Test that firewall is disabled by default when not configured."""
    assert firewall.is_firewalld_enabled(minimal_settings) == False

def test_get_monitored_ports(firewall_enabled_settings):
    """Test getting monitored ports from configuration."""
    ports = firewall.get_monitored_ports(firewall_enabled_settings)
    assert ports == ["80/tcp", "443/tcp", "22/tcp"]

def test_get_monitored_ports_default(minimal_settings):
    """Test getting monitored ports when not configured."""
    ports = firewall.get_monitored_ports(minimal_settings)
    assert ports == []

def test_get_knocker_zone_name():
    """Test that zone name is consistent."""
    assert firewall.get_knocker_zone_name() == "knocker"

# Test Firewalld Availability Checking

def test_check_firewalld_availability_import_error():
    """Test firewalld availability check when import fails."""
    # Reset global state
    firewall._firewalld_available = None
    firewall._fw = None
    
    with patch('builtins.__import__', side_effect=ImportError("No module named 'firewall'")):
        assert firewall._check_firewalld_availability() == False
        assert firewall._firewalld_available == False

def test_check_firewalld_availability_cached():
    """Test that availability check is cached."""
    # Set cached value
    firewall._firewalld_available = True
    firewall._fw = Mock()
    
    # Should return cached value without importing
    with patch('builtins.__import__') as mock_import:
        result = firewall._check_firewalld_availability()
        assert result == True
        mock_import.assert_not_called()

def test_check_firewalld_availability_cached_false():
    """Test that cached False value is returned."""
    # Set cached value
    firewall._firewalld_available = False
    firewall._fw = None
    
    # Should return cached value without importing
    with patch('builtins.__import__') as mock_import:
        result = firewall._check_firewalld_availability()
        assert result == False
        mock_import.assert_not_called()

# Test Firewall Initialization

@patch('src.fw_integration._check_firewalld_availability')
@patch('src.fw_integration._zone_exists')
@patch('src.fw_integration._create_knocker_zone')
@patch('src.fw_integration._sync_firewall_rules_with_whitelist')
def test_initialize_firewall_success(mock_sync, mock_create, mock_exists, mock_avail, firewall_enabled_settings):
    """Test successful firewall initialization."""
    mock_avail.return_value = True
    mock_exists.return_value = False
    
    result = firewall.initialize_firewall(firewall_enabled_settings)
    
    assert result == True
    mock_avail.assert_called_once()
    mock_exists.assert_called_once_with("knocker")
    mock_create.assert_called_once()
    mock_sync.assert_called_once_with(firewall_enabled_settings)

@patch('src.fw_integration._check_firewalld_availability')
def test_initialize_firewall_disabled(mock_avail, firewall_disabled_settings):
    """Test firewall initialization when disabled."""
    result = firewall.initialize_firewall(firewall_disabled_settings)
    
    assert result == False
    mock_avail.assert_not_called()

@patch('src.fw_integration._check_firewalld_availability')
def test_initialize_firewall_unavailable(mock_avail, firewall_enabled_settings):
    """Test firewall initialization when firewalld is unavailable."""
    mock_avail.return_value = False
    
    result = firewall.initialize_firewall(firewall_enabled_settings)
    
    assert result == False

@patch('src.fw_integration._check_firewalld_availability')
@patch('src.fw_integration._zone_exists')
@patch('src.fw_integration._sync_firewall_rules_with_whitelist')
def test_initialize_firewall_existing_zone(mock_sync, mock_exists, mock_avail, firewall_enabled_settings):
    """Test firewall initialization with existing zone."""
    mock_avail.return_value = True
    mock_exists.return_value = True
    
    result = firewall.initialize_firewall(firewall_enabled_settings)
    
    assert result == True
    mock_sync.assert_called_once_with(firewall_enabled_settings)

# Test Add IP to Firewall

@patch('src.fw_integration._check_firewalld_availability')
@patch('src.fw_integration._add_rich_rule_for_ip_port')
def test_add_ip_to_firewall_success(mock_add_rule, mock_avail, firewall_enabled_settings):
    """Test successfully adding IP to firewall."""
    mock_avail.return_value = True
    
    result = firewall.add_ip_to_firewall("192.168.1.100", 1234567890, firewall_enabled_settings)
    
    assert result == True
    # Should be called once for each monitored port
    assert mock_add_rule.call_count == 3
    mock_add_rule.assert_any_call("knocker", "192.168.1.100", "80/tcp", 1234567890)
    mock_add_rule.assert_any_call("knocker", "192.168.1.100", "443/tcp", 1234567890)
    mock_add_rule.assert_any_call("knocker", "192.168.1.100", "22/tcp", 1234567890)

@patch('src.fw_integration._check_firewalld_availability')
def test_add_ip_to_firewall_disabled(mock_avail, firewall_disabled_settings):
    """Test adding IP when firewall is disabled."""
    result = firewall.add_ip_to_firewall("192.168.1.100", 1234567890, firewall_disabled_settings)
    
    assert result == False
    mock_avail.assert_not_called()

@patch('src.fw_integration._check_firewalld_availability')
def test_add_ip_to_firewall_unavailable(mock_avail, firewall_enabled_settings):
    """Test adding IP when firewalld is unavailable."""
    mock_avail.return_value = False
    
    result = firewall.add_ip_to_firewall("192.168.1.100", 1234567890, firewall_enabled_settings)
    
    assert result == False

@patch('src.fw_integration._check_firewalld_availability')
@patch('src.fw_integration._add_rich_rule_for_ip_port')
def test_add_ip_to_firewall_exception(mock_add_rule, mock_avail, firewall_enabled_settings):
    """Test adding IP when rule creation fails."""
    mock_avail.return_value = True
    mock_add_rule.side_effect = Exception("Rule creation failed")
    
    result = firewall.add_ip_to_firewall("192.168.1.100", 1234567890, firewall_enabled_settings)
    
    assert result == False

# Test Remove IP from Firewall

@patch('src.fw_integration._check_firewalld_availability')
@patch('src.fw_integration._remove_rich_rule_for_ip_port')
def test_remove_ip_from_firewall_success(mock_remove_rule, mock_avail, firewall_enabled_settings):
    """Test successfully removing IP from firewall."""
    mock_avail.return_value = True
    
    result = firewall.remove_ip_from_firewall("192.168.1.100", firewall_enabled_settings)
    
    assert result == True
    # Should be called once for each monitored port
    assert mock_remove_rule.call_count == 3
    mock_remove_rule.assert_any_call("knocker", "192.168.1.100", "80/tcp")
    mock_remove_rule.assert_any_call("knocker", "192.168.1.100", "443/tcp")
    mock_remove_rule.assert_any_call("knocker", "192.168.1.100", "22/tcp")

@patch('src.fw_integration._check_firewalld_availability')
def test_remove_ip_from_firewall_disabled(mock_avail, firewall_disabled_settings):
    """Test removing IP when firewall is disabled."""
    result = firewall.remove_ip_from_firewall("192.168.1.100", firewall_disabled_settings)
    
    assert result == False

# Test Cleanup Expired Rules

@patch('src.fw_integration._check_firewalld_availability')
@patch('src.fw_integration._sync_firewall_rules_with_whitelist')
def test_cleanup_expired_firewall_rules_success(mock_sync, mock_avail, firewall_enabled_settings):
    """Test successful cleanup of expired rules."""
    mock_avail.return_value = True
    
    result = firewall.cleanup_expired_firewall_rules(firewall_enabled_settings)
    
    assert result == True
    mock_sync.assert_called_once_with(firewall_enabled_settings)

@patch('src.fw_integration._check_firewalld_availability')
def test_cleanup_expired_firewall_rules_disabled(mock_avail, firewall_disabled_settings):
    """Test cleanup when firewall is disabled."""
    result = firewall.cleanup_expired_firewall_rules(firewall_disabled_settings)
    
    assert result == False

# Test Private Helper Functions

def test_zone_exists_true():
    """Test zone existence check when zone exists."""
    firewall._fw = Mock()
    firewall._fw.getZones.return_value = ["public", "knocker", "internal"]
    
    assert firewall._zone_exists("knocker") == True

def test_zone_exists_false():
    """Test zone existence check when zone doesn't exist."""
    firewall._fw = Mock()
    firewall._fw.getZones.return_value = ["public", "internal"]
    
    assert firewall._zone_exists("knocker") == False

def test_zone_exists_exception():
    """Test zone existence check when firewalld call fails."""
    firewall._fw = Mock()
    firewall._fw.getZones.side_effect = Exception("D-Bus error")
    
    assert firewall._zone_exists("knocker") == False

def test_add_rich_rule_for_ip_port_ipv4():
    """Test adding rich rule for IPv4 address."""
    firewall._fw = Mock()
    
    firewall._add_rich_rule_for_ip_port("knocker", "192.168.1.100", "80/tcp", 1234567890)
    
    expected_rule = 'rule family="ipv4" source address="192.168.1.100" port port="80" protocol="tcp" accept'
    firewall._fw.addRichRule.assert_called_once_with("knocker", expected_rule)

def test_add_rich_rule_for_ip_port_ipv6():
    """Test adding rich rule for IPv6 address."""
    firewall._fw = Mock()
    
    firewall._add_rich_rule_for_ip_port("knocker", "2001:db8::1", "443/tcp", 1234567890)
    
    expected_rule = 'rule family="ipv6" source address="2001:db8::1" port port="443" protocol="tcp" accept'
    firewall._fw.addRichRule.assert_called_once_with("knocker", expected_rule)

def test_add_rich_rule_for_ip_port_default_protocol():
    """Test adding rich rule with default protocol."""
    firewall._fw = Mock()
    
    firewall._add_rich_rule_for_ip_port("knocker", "192.168.1.100", "80", 1234567890)
    
    expected_rule = 'rule family="ipv4" source address="192.168.1.100" port port="80" protocol="tcp" accept'
    firewall._fw.addRichRule.assert_called_once_with("knocker", expected_rule)

def test_remove_rich_rule_for_ip_port():
    """Test removing rich rule."""
    firewall._fw = Mock()
    
    firewall._remove_rich_rule_for_ip_port("knocker", "192.168.1.100", "80/tcp")
    
    expected_rule = 'rule family="ipv4" source address="192.168.1.100" port port="80" protocol="tcp" accept'
    firewall._fw.removeRichRule.assert_called_once_with("knocker", expected_rule)

def test_remove_rich_rule_for_ip_port_not_exists():
    """Test removing rich rule that doesn't exist."""
    firewall._fw = Mock()
    firewall._fw.removeRichRule.side_effect = Exception("Rule not found")
    
    # Should not raise exception
    firewall._remove_rich_rule_for_ip_port("knocker", "192.168.1.100", "80/tcp")

def test_get_existing_firewall_rules():
    """Test getting existing firewall rules."""
    firewall._fw = Mock()
    firewall._fw.getRichRules.return_value = [
        'rule family="ipv4" source address="192.168.1.100" port port="80" protocol="tcp" accept',
        'rule family="ipv4" source address="10.0.0.1" port port="443" protocol="tcp" accept',
        'rule family="ipv6" source address="2001:db8::1" port port="22" protocol="tcp" accept',
        'rule family="ipv4" target="REJECT"'  # Should be ignored
    ]
    
    result = firewall._get_existing_firewall_rules("knocker", ["80/tcp", "443/tcp", "22/tcp"])
    
    expected = {"192.168.1.100", "10.0.0.1", "2001:db8::1"}
    assert result == expected

def test_get_existing_firewall_rules_exception():
    """Test getting existing rules when firewalld call fails."""
    firewall._fw = Mock()
    firewall._fw.getRichRules.side_effect = Exception("D-Bus error")
    
    result = firewall._get_existing_firewall_rules("knocker", ["80/tcp"])
    
    assert result == set()

# Test IPv6 Support

def test_ipv6_cidr_support():
    """Test that IPv6 CIDR ranges are handled correctly."""
    firewall._fw = Mock()
    
    firewall._add_rich_rule_for_ip_port("knocker", "2001:db8::/32", "80/tcp", 1234567890)
    
    expected_rule = 'rule family="ipv6" source address="2001:db8::/32" port port="80" protocol="tcp" accept'
    firewall._fw.addRichRule.assert_called_once_with("knocker", expected_rule)

# Test Error Handling

@patch('src.fw_integration._check_firewalld_availability')
@patch('src.fw_integration._add_rich_rule_for_ip_port')
def test_add_ip_partial_failure(mock_add_rule, mock_avail, firewall_enabled_settings):
    """Test adding IP when some rules fail to create."""
    mock_avail.return_value = True
    # First call succeeds, second fails, third succeeds
    mock_add_rule.side_effect = [None, Exception("Rule failed"), None]
    
    result = firewall.add_ip_to_firewall("192.168.1.100", 1234567890, firewall_enabled_settings)
    
    # Should return False even if some rules succeed
    assert result == False