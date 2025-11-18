import pytest
import time
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from src import core, main


# Mock settings
@pytest.fixture
def mock_settings():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        whitelist_path = Path(f.name)

    settings = {
        "whitelist": {"storage_path": str(whitelist_path)},
        "security": {"max_whitelist_entries": 100},
        "api_keys": [{"key": "test-key", "allow_remote_whitelist": True}],
    }
    yield settings
    if whitelist_path.exists():
        whitelist_path.unlink()


def test_legacy_behavior_without_token_id(mock_settings):
    """
    Verifies that if no token_id is provided, multiple IPs are allowed (legacy behavior).
    """
    ip1 = "192.168.1.100"
    expiry = int(time.time()) + 3600
    core.add_ip_to_whitelist(ip1, expiry, mock_settings)

    ip2 = "192.168.1.200"
    core.add_ip_to_whitelist(ip2, expiry, mock_settings)

    whitelist = core.load_whitelist(mock_settings)

    assert ip1 in whitelist
    assert ip2 in whitelist


def test_one_whitelist_per_token(mock_settings):
    """
    Verifies that when token_id is provided, old IPs associated with the same token
    are removed.
    """
    token_id = "hash-of-api-key-123"
    expiry = int(time.time()) + 3600

    # 1. Add first IP
    ip1 = "192.168.1.100"
    core.add_ip_to_whitelist(ip1, expiry, mock_settings, token_id=token_id)

    # Check it exists and has token_id
    whitelist = core.load_whitelist(mock_settings)
    assert ip1 in whitelist
    entry = whitelist[ip1]
    assert isinstance(entry, dict)
    assert entry["token_id"] == token_id

    # 2. Add second IP with same token
    ip2 = "192.168.1.200"
    removed_ip = core.add_ip_to_whitelist(ip2, expiry, mock_settings, token_id=token_id)

    # 3. Assert removals and additions
    whitelist = core.load_whitelist(mock_settings)

    assert ip1 not in whitelist
    assert ip2 in whitelist
    assert removed_ip == ip1

    # 4. Add a third IP with DIFFERENT token
    other_token = "other-token"
    ip3 = "192.168.1.250"
    core.add_ip_to_whitelist(ip3, expiry, mock_settings, token_id=other_token)

    whitelist = core.load_whitelist(mock_settings)
    assert ip2 in whitelist
    assert ip3 in whitelist
