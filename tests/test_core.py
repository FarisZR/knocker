import pytest
import time
import ipaddress
from src import config, core

# --- Test IP/CIDR Validation ---


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("192.168.1.1", True),
        ("2001:db8::1", True),
        ("10.0.0.0/8", True),
        ("2001:db8:abcd::/48", True),
        ("not-an-ip", False),
        ("192.168.1.1/33", False),
        ("2001:db8::/129", False),
    ],
)
def test_is_valid_ip_or_cidr(address, expected):
    """Tests validation for various IPv4, IPv6, and CIDR formats."""
    assert core.is_valid_ip_or_cidr(address) == expected


# --- Test Whitelist Logic ---


def test_runtime_whitelist_authorizes_cidr(mock_settings, tmp_path):
    """The runtime whitelist index authorizes addresses within a CIDR."""
    now = int(time.time())
    whitelist = {"192.168.1.0/24": now + 3600}
    mock_settings["whitelist"] = {"storage_path": str(tmp_path / "whitelist.json")}
    state = core.ensure_runtime_state(mock_settings)
    state.whitelist.replace(whitelist)
    assert state.is_authorized_ip("192.168.1.100") is True


def test_runtime_whitelist_rejects_outside_cidr(mock_settings, tmp_path):
    """The runtime whitelist index rejects addresses outside a CIDR."""
    now = int(time.time())
    whitelist = {"192.168.1.0/24": now + 3600}
    mock_settings["whitelist"] = {"storage_path": str(tmp_path / "whitelist.json")}
    state = core.ensure_runtime_state(mock_settings)
    state.whitelist.replace(whitelist)
    assert state.is_authorized_ip("10.10.10.10") is False


def test_runtime_whitelist_authorizes_ipv6_cidr(mock_settings, tmp_path):
    """The runtime whitelist index supports IPv6 CIDRs."""
    now = int(time.time())
    whitelist = {"2001:db8:abcd::/48": now + 3600}
    mock_settings["whitelist"] = {"storage_path": str(tmp_path / "whitelist.json")}
    state = core.ensure_runtime_state(mock_settings)
    state.whitelist.replace(whitelist)
    assert state.is_authorized_ip("2001:db8:abcd:0001::1") is True


def test_runtime_whitelist_rejects_expired_entry(mock_settings, tmp_path):
    """The runtime whitelist index rejects expired entries."""
    now = int(time.time())
    whitelist = {"1.1.1.1/32": now - 100}  # Expired
    mock_settings["whitelist"] = {"storage_path": str(tmp_path / "whitelist.json")}
    state = core.ensure_runtime_state(mock_settings)
    state.whitelist.replace(whitelist)
    assert state.is_authorized_ip("1.1.1.1") is False


def test_runtime_whitelist_rejects_invalid_ip_input(mock_settings, tmp_path):
    """Tests that the function handles invalid IP input gracefully."""
    now = int(time.time())
    whitelist = {"192.168.1.0/24": now + 3600}
    mock_settings["whitelist"] = {"storage_path": str(tmp_path / "whitelist.json")}
    state = core.ensure_runtime_state(mock_settings)
    state.whitelist.replace(whitelist)
    assert state.is_authorized_ip("not-a-real-ip") is False


def test_always_allowed_ip_is_authorized(mock_settings, tmp_path):
    """Tests that an IP in the always-allowed list is always whitelisted."""
    mock_settings["security"] = {"always_allowed_ips": ["10.20.30.40"]}
    mock_settings["whitelist"] = {"storage_path": str(tmp_path / "whitelist.json")}
    state = core.ensure_runtime_state(mock_settings)
    assert state.is_authorized_ip("10.20.30.40") is True


def test_always_allowed_cidr_is_authorized(mock_settings, tmp_path):
    """Tests that an IP within an always-allowed CIDR is always whitelisted."""
    mock_settings["security"] = {"always_allowed_ips": ["10.20.30.0/24"]}
    mock_settings["whitelist"] = {"storage_path": str(tmp_path / "whitelist.json")}
    state = core.ensure_runtime_state(mock_settings)
    assert state.is_authorized_ip("10.20.30.50") is True


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


def test_allow_remote_whitelist_must_be_boolean():
    with pytest.raises(ValueError, match="must define boolean allow_remote_whitelist"):
        config.validate_settings(
            {"api_keys": [{"key": "admin_key", "max_ttl": 3600, "allow_remote_whitelist": "false"}]}
        )


def test_rate_limiter_reservation_can_be_released():
    """A released reservation should free the success slot immediately."""
    limiter = core.SlidingWindowRateLimiter(
        window_seconds=60, successful_requests=1, failed_requests=1
    )

    reservation = limiter.reserve("actor", "success", now=100)

    assert reservation is not None
    assert limiter.reserve("actor", "success", now=100) is None

    limiter.release("actor", "success", reservation)

    assert limiter.reserve("actor", "success", now=100) is not None


def test_rate_limiter_prunes_stale_actor_buckets():
    limiter = core.SlidingWindowRateLimiter(
        window_seconds=10, successful_requests=1, failed_requests=1
    )

    assert limiter.reserve("actor-a", "success", now=10) is not None

    assert limiter.can_allow("actor-b", "success", now=25) is True
    assert ("success", "actor-a") not in limiter._events


def test_whitelist_store_mutations_refresh_in_memory_index(tmp_path):
    whitelist_path = tmp_path / "whitelist.json"
    store = core.WhitelistStore(storage_path=whitelist_path, max_entries=10)
    address = ipaddress.ip_address("203.0.113.10")
    replacement = ipaddress.ip_address("203.0.113.11")
    now = int(time.time())

    assert store.contains(address, now=now) is False

    store.add("203.0.113.10", now + 60)

    assert store.contains(address, now=now) is True

    store.replace({"203.0.113.11": now + 60})

    assert store.contains(address, now=now) is False
    assert store.contains(replacement, now=now) is True


def test_whitelist_store_contains_does_not_stat_filesystem(tmp_path, monkeypatch):
    whitelist_path = tmp_path / "whitelist.json"
    store = core.WhitelistStore(storage_path=whitelist_path, max_entries=10)
    address = ipaddress.ip_address("203.0.113.10")

    monkeypatch.setattr(type(whitelist_path), "stat", lambda *_args, **_kwargs: pytest.fail())

    assert store.contains(address, now=int(time.time())) is False
    assert store.contains(address, now=int(time.time())) is False


def test_whitelist_store_compaction_preserves_entries_added_by_other_processes(tmp_path):
    whitelist_path = tmp_path / "whitelist.json"
    now = int(time.time())

    core._write_whitelist_file(whitelist_path, {"192.0.2.10": now - 60})
    store = core.WhitelistStore(storage_path=whitelist_path, max_entries=10)

    assert store._pending_compaction is True
    assert store.active_snapshot() == {}

    core._write_whitelist_file(whitelist_path, {"198.51.100.20": now + 60})

    assert store.compact_expired(now=now) is False
    assert core._read_whitelist_file(whitelist_path) == {"198.51.100.20": now + 60}
    assert store.active_snapshot() == {"198.51.100.20": now + 60}


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


@pytest.mark.parametrize(
    "forwarded_for",
    [
        ", ,",
        "not-an-ip",
        ",1.2.3.4",
        ",".join(["1.2.3.4"] * 21),
    ],
)
def test_resolve_client_ip_rejects_malformed_forwarded_chain_from_trusted_proxy(forwarded_for):
    trusted_proxies = core.ParsedNetworkSet.from_entries(["127.0.0.1"], "trusted_proxies")

    assert core.resolve_client_ip("127.0.0.1", forwarded_for, trusted_proxies) == (None, True)


def test_resolve_client_ip_rejects_chain_with_only_trusted_hops():
    trusted_proxies = core.ParsedNetworkSet.from_entries(["127.0.0.0/8"], "trusted_proxies")

    assert core.resolve_client_ip("127.0.0.1", "127.0.0.2, 127.0.0.3", trusted_proxies) == (
        None,
        True,
    )


def test_settings_accepts_empty_host_exclusions_as_yaml_null(tmp_path):
    settings = config.validate_settings(
        {
            "api_keys": [{"key": "test-key", "max_ttl": 3600}],
            "security": {"excluded_paths_by_host": None},
            "whitelist": {"storage_path": str(tmp_path / "whitelist.json")},
        }
    )

    assert settings.security.excluded_paths_by_host == {}


def test_disabled_firewalld_still_validates_shared_mutation_capacity():
    with pytest.raises(ValueError, match="mutation_queue_capacity must be a positive integer"):
        config.validate_settings(
            {
                "api_keys": [{"key": "test-key", "max_ttl": 3600}],
                "firewalld": {"enabled": False, "mutation_queue_capacity": 0},
            }
        )
