import pytest
import time
from src import core

# --- Test IP/CIDR Validation ---

@pytest.mark.parametrize("address, expected", [
    ("192.168.1.1", True),
    ("2001:db8::1", True),
    ("10.0.0.0/8", True),
    ("2001:db8:abcd::/48", True),
    ("not-an-ip", False),
    ("192.168.1.1/33", False),
    ("2001:db8::/129", False),
])
def test_is_valid_ip_or_cidr(address, expected):
    """Tests validation for various IPv4, IPv6, and CIDR formats."""
    assert core.is_valid_ip_or_cidr(address) == expected

# --- Test Whitelist Logic ---

def test_ip_is_whitelisted(mock_settings):
    """Tests if an IP is correctly identified within a whitelisted CIDR."""
    now = int(time.time())
    whitelist = {"192.168.1.0/24": now + 3600}
    assert core.is_ip_whitelisted("192.168.1.100", whitelist, mock_settings) == True

def test_ip_is_not_whitelisted(mock_settings):
    """Tests if an IP outside a whitelisted CIDR is correctly rejected."""
    now = int(time.time())
    whitelist = {"192.168.1.0/24": now + 3600}
    assert core.is_ip_whitelisted("10.10.10.10", whitelist, mock_settings) == False

def test_ipv6_is_whitelisted(mock_settings):
    """Tests if an IPv6 address is correctly identified within a whitelisted CIDR."""
    now = int(time.time())
    whitelist = {"2001:db8:abcd::/48": now + 3600}
    assert core.is_ip_whitelisted("2001:db8:abcd:0001::1", whitelist, mock_settings) == True

def test_expired_ip_is_not_whitelisted(mock_settings):
    """Tests if an IP with an expired timestamp is correctly rejected."""
    now = int(time.time())
    whitelist = {"1.1.1.1/32": now - 100} # Expired
    assert core.is_ip_whitelisted("1.1.1.1", whitelist, mock_settings) == False

def test_is_ip_whitelisted_with_invalid_ip_input(mock_settings):
    """Tests that the function handles invalid IP input gracefully."""
    now = int(time.time())
    whitelist = {"192.168.1.0/24": now + 3600}
    assert core.is_ip_whitelisted("not-a-real-ip", whitelist, mock_settings) == False

def test_always_allowed_ip_is_whitelisted(mock_settings):
    """Tests that an IP in the always-allowed list is always whitelisted."""
    mock_settings["security"] = {"always_allowed_ips": ["10.20.30.40"]}
    whitelist = {} # Empty dynamic whitelist
    assert core.is_ip_whitelisted("10.20.30.40", whitelist, mock_settings) == True

def test_always_allowed_cidr_is_whitelisted(mock_settings):
    """Tests that an IP within an always-allowed CIDR is always whitelisted."""
    mock_settings["security"] = {"always_allowed_ips": ["10.20.30.0/24"]}
    whitelist = {}
    assert core.is_ip_whitelisted("10.20.30.50", whitelist, mock_settings) == True

# --- Test Path Exclusion ---

def test_path_is_excluded(mock_settings):
    """Tests that a path in the excluded list is correctly identified."""
    mock_settings["security"] = {"excluded_paths": ["/api/health", "/metrics"]}
    assert core.is_path_excluded("/api/health/check", mock_settings) == True
    assert core.is_path_excluded("/metrics", mock_settings) == True

def test_path_is_not_excluded(mock_settings):
    """Tests that a path not in the excluded list is correctly rejected."""
    mock_settings["security"] = {"excluded_paths": ["/api/health"]}
    assert core.is_path_excluded("/api/v1/status", mock_settings) == False

# --- Test Permissions & Key Helpers ---

@pytest.fixture
def mock_settings():
    """Provides a standard settings object for tests."""
    return {
        "api_keys": [
            {"key": "admin_key", "ttl": 3600, "allow_remote_whitelist": True},
            {"key": "user_key", "ttl": 600, "allow_remote_whitelist": False},
        ]
    }

def test_can_whitelist_remote_with_permission(mock_settings):
    """Tests that a key with permission returns True."""
    assert core.can_whitelist_remote("admin_key", mock_settings) == True

def test_can_whitelist_remote_without_permission(mock_settings):
    """Tests that a key without permission returns False."""
    assert core.can_whitelist_remote("user_key", mock_settings) == False

def test_can_whitelist_remote_with_nonexistent_key(mock_settings):
    """Tests that a non-existent key returns False."""
    assert core.can_whitelist_remote("fake_key", mock_settings) == False

def test_get_ttl_for_key(mock_settings):
    """Tests that the correct TTL is returned for a given key."""
    assert core.get_ttl_for_key("admin_key", mock_settings) == 3600
    assert core.get_ttl_for_key("user_key", mock_settings) == 600

def test_get_ttl_for_nonexistent_key(mock_settings):
    """Tests that a non-existent key returns a TTL of 0."""
    assert core.get_ttl_for_key("fake_key", mock_settings) == 0

def test_is_valid_api_key(mock_settings):
    """Tests that valid keys are recognized."""
    assert core.is_valid_api_key("admin_key", mock_settings) == True
    assert core.is_valid_api_key("user_key", mock_settings) == True

def test_is_invalid_api_key(mock_settings):
    """Tests that an invalid key is rejected."""
    assert core.is_valid_api_key("fake_key", mock_settings) == False