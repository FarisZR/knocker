import pytest
import time
import tempfile
import json
from pathlib import Path
from src import core


@pytest.fixture
def legacy_whitelist_file():
    """Creates a temporary whitelist.json with legacy integer format."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        # Create a mixed file:
        # 1. Legacy IP (valid)
        # 2. Legacy IP (expired)
        # 3. New format IP (valid) - simulating partial migration
        data = {
            "1.1.1.1": int(time.time()) + 3600,  # Legacy valid
            "2.2.2.2": int(time.time()) - 3600,  # Legacy expired
            "3.3.3.3": {
                "expiry": int(time.time()) + 3600,
                "token_id": "existing-token",
            },  # New format
        }
        json.dump(data, f)
        path = Path(f.name)
    yield path
    if path.exists():
        path.unlink()


@pytest.fixture
def mock_settings(legacy_whitelist_file):
    return {
        "whitelist": {"storage_path": str(legacy_whitelist_file)},
        "security": {
            "max_whitelist_entries": 100,
            "always_allowed_ips": [],
            "excluded_paths": [],
        },
        "api_keys": [{"key": "test-key", "allow_remote_whitelist": True}],
    }


def test_legacy_migration_loading(mock_settings):
    """Test that we can correctly load and verify IPs from a legacy/mixed file."""
    whitelist = core.load_whitelist(mock_settings)

    # Check raw loading
    assert whitelist["1.1.1.1"] > 0
    assert isinstance(whitelist["1.1.1.1"], int)
    assert isinstance(whitelist["3.3.3.3"], dict)

    # Check is_ip_whitelisted helper
    assert core.is_ip_whitelisted("1.1.1.1", whitelist, mock_settings) is True
    assert core.is_ip_whitelisted("3.3.3.3", whitelist, mock_settings) is True
    # 2.2.2.2 is expired
    assert core.is_ip_whitelisted("2.2.2.2", whitelist, mock_settings) is False


def test_legacy_cleanup(mock_settings):
    """Test that cleanup_expired_ips handles mixed formats correctly."""
    core.cleanup_expired_ips(mock_settings)
    whitelist = core.load_whitelist(mock_settings)

    # 1.1.1.1 (valid legacy) should remain
    assert "1.1.1.1" in whitelist
    # 2.2.2.2 (expired legacy) should be removed
    assert "2.2.2.2" not in whitelist
    # 3.3.3.3 (valid new) should remain
    assert "3.3.3.3" in whitelist


def test_legacy_overwrite_migration(mock_settings):
    """
    Test that knocking with a token on a legacy IP 'adopts' it into the new format.
    """
    token_id = "new-token-id"
    expiry = int(time.time()) + 3600

    # Overwrite legacy 1.1.1.1 with new token-based entry
    core.add_ip_to_whitelist("1.1.1.1", expiry, mock_settings, token_id=token_id)

    whitelist = core.load_whitelist(mock_settings)
    entry = whitelist["1.1.1.1"]

    # Verify it's now a dict with the token_id
    assert isinstance(entry, dict)
    assert entry["token_id"] == token_id
    assert entry["expiry"] == expiry


def test_rolling_migration_behavior(mock_settings):
    """
    Test the full lifecycle:
    1. Legacy IP exists (unowned)
    2. New knock creates new IP (owned) -> Legacy IP stays (correct, as it wasn't owned by this token)
    3. Knock on Legacy IP -> Updates to Owned
    4. New knock creates newer IP -> Previously legacy (now owned) IP gets removed
    """
    token_id = "my-token"
    expiry = int(time.time()) + 3600

    # 1. Legacy 1.1.1.1 exists (from fixture)

    # 2. Add 4.4.4.4 with token
    core.add_ip_to_whitelist("4.4.4.4", expiry, mock_settings, token_id=token_id)
    whitelist = core.load_whitelist(mock_settings)

    # Legacy should still be there (it's unowned, so we don't touch it)
    assert "1.1.1.1" in whitelist
    assert isinstance(whitelist["1.1.1.1"], int)
    # New one is there
    assert "4.4.4.4" in whitelist
    assert whitelist["4.4.4.4"]["token_id"] == token_id

    # 3. Knock on 1.1.1.1 with token (Adoption)
    # This should ADD 1.1.1.1 (owned) and REMOVE 4.4.4.4 (since token can only have one)
    core.add_ip_to_whitelist("1.1.1.1", expiry, mock_settings, token_id=token_id)

    whitelist = core.load_whitelist(mock_settings)

    # 4.4.4.4 should be gone (replaced by 1.1.1.1 for this token)
    assert "4.4.4.4" not in whitelist

    # 1.1.1.1 should be there and OWNED now
    assert "1.1.1.1" in whitelist
    assert isinstance(whitelist["1.1.1.1"], dict)
    assert whitelist["1.1.1.1"]["token_id"] == token_id
