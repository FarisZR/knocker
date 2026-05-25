import pytest
import time
import ipaddress
from src import core

# --- Test IP/CIDR Validation ---

@pytest.mark.parametrize(("address", "expected"), [
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
            {"key": "admin_key", "max_ttl": 3600, "allow_remote_whitelist": True},
            {"key": "user_key", "max_ttl": 600, "allow_remote_whitelist": False},
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

def test_get_max_ttl_for_key(mock_settings):
    """Tests that the correct max_ttl is returned for a given key."""
    assert core.get_max_ttl_for_key("admin_key", mock_settings) == 3600
    assert core.get_max_ttl_for_key("user_key", mock_settings) == 600

def test_get_max_ttl_for_nonexistent_key(mock_settings):
    """Tests that a non-existent key returns a max_ttl of 0."""
    assert core.get_max_ttl_for_key("fake_key", mock_settings) == 0

def test_is_valid_api_key(mock_settings):
    """Tests that valid keys are recognized."""
    assert core.is_valid_api_key("admin_key", mock_settings) == True
    assert core.is_valid_api_key("user_key", mock_settings) == True

def test_is_invalid_api_key(mock_settings):
    """Tests that an invalid key is rejected."""
    assert core.is_valid_api_key("fake_key", mock_settings) == False

def test_duplicate_api_key_material_detected_across_plaintext_and_hash():
    """The same secret must be rejected even across key and key_hash forms."""
    with pytest.raises(ValueError, match="Duplicate API key material"):
        core.APIKeyRegistry.from_settings([
            {"key": "duplicate_key", "max_ttl": 3600, "allow_remote_whitelist": True},
            {
                "key_hash": core.hash_api_key("duplicate_key"),
                "max_ttl": 600,
                "allow_remote_whitelist": False,
            },
        ])

def test_allow_remote_whitelist_must_be_boolean():
    with pytest.raises(ValueError, match="must define boolean allow_remote_whitelist"):
        core.APIKeyRegistry.from_settings([
            {"key": "admin_key", "max_ttl": 3600, "allow_remote_whitelist": "false"},
        ])

def test_rate_limiter_reservation_can_be_released():
    """A released reservation should free the success slot immediately."""
    limiter = core.SlidingWindowRateLimiter(window_seconds=60, successful_requests=1, failed_requests=1)

    reservation = limiter.reserve("actor", "success", now=100)

    assert reservation is not None
    assert limiter.reserve("actor", "success", now=100) is None

    limiter.release("actor", "success", reservation)

    assert limiter.reserve("actor", "success", now=100) is not None

def test_rate_limiter_prunes_stale_actor_buckets():
    limiter = core.SlidingWindowRateLimiter(window_seconds=10, successful_requests=1, failed_requests=1)

    assert limiter.reserve("actor-a", "success", now=10) is not None

    assert limiter.can_allow("actor-b", "success", now=25) is True
    assert ("success", "actor-a") not in limiter._events

def test_replay_guard_prunes_using_server_receive_time():
    """Nonce reuse should be allowed once the server-side max age window has passed."""
    guard = core.ReplayGuard(enabled=True, max_age_seconds=10)

    assert guard.validate("actor", "nonce", "110", now=100) == (True, None)
    assert guard.validate("actor", "nonce", "111", now=111) == (True, None)

def test_whitelist_store_contains_reloads_shared_state(tmp_path):
    whitelist_path = tmp_path / "whitelist.json"
    store = core.WhitelistStore(storage_path=whitelist_path, max_entries=10)
    address = ipaddress.ip_address("203.0.113.10")
    now = int(time.time())

    assert store.contains(address, now=now) is False

    core._write_whitelist_file(whitelist_path, {"203.0.113.10": now + 60})

    assert store.contains(address, now=now) is True

def test_whitelist_store_contains_skips_reload_when_storage_unchanged(tmp_path, monkeypatch):
    whitelist_path = tmp_path / "whitelist.json"
    store = core.WhitelistStore(storage_path=whitelist_path, max_entries=10)
    address = ipaddress.ip_address("203.0.113.10")

    def unexpected_read(_: object) -> dict[str, int]:
        pytest.fail("contains reloaded whitelist without a storage change")

    monkeypatch.setattr(core, "_read_whitelist_file", unexpected_read)

    assert store.contains(address, now=int(time.time())) is False
    assert store.contains(address, now=int(time.time())) is False


@pytest.mark.parametrize(
    ("helper", "expected_message"),
    [
        (core.is_valid_api_key, "Configuration must contain at least one API key"),
        (core.can_whitelist_remote, "Configuration must contain at least one API key"),
        (core.get_max_ttl_for_key, "Configuration must contain at least one API key"),
        (core.get_api_key_name, "Configuration must contain at least one API key"),
    ],
)
def test_api_key_helpers_propagate_configuration_errors(helper, expected_message):
    with pytest.raises(ValueError, match=expected_message):
        helper("any_key", {"api_keys": []})

def test_ensure_runtime_state_is_initialized_once(tmp_path):
    settings = {
        "server": {"trusted_proxies": ["127.0.0.1"]},
        "api_keys": [{"key": "admin_key", "max_ttl": 3600, "allow_remote_whitelist": True}],
        "whitelist": {"storage_path": str(tmp_path / "whitelist.json")},
        "security": {"always_allowed_ips": []},
    }

    states = []
    import threading

    def worker():
        states.append(core.ensure_runtime_state(settings))

    first = threading.Thread(target=worker)
    second = threading.Thread(target=worker)
    first.start()
    second.start()
    first.join()
    second.join()

    assert len(states) == 2
    assert states[0] is states[1]
