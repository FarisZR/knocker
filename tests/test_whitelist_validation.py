"""
Tests for whitelist input validation and cross-process locking.
"""

import pytest
import time
import os
from pathlib import Path
from src import core


@pytest.fixture
def test_settings():
    """Test settings with temporary whitelist path."""
    return {
        "server": {"trusted_proxies": []},
        "api_keys": [{"key": "test-key", "max_ttl": 3600}],
        "whitelist": {"storage_path": "/tmp/test_validation_whitelist.json"},
        "security": {"max_whitelist_entries": 100},
    }


@pytest.fixture
def whitelist_store(test_settings):
    return core.ensure_runtime_state(test_settings).whitelist


@pytest.fixture(autouse=True)
def cleanup_whitelist(test_settings):
    """Clean up test whitelist files."""
    path = test_settings["whitelist"]["storage_path"]
    lock_path = Path(path).with_suffix(".lock")

    for p in [path, str(lock_path)]:
        if os.path.exists(p):
            os.remove(p)

    yield

    for p in [path, str(lock_path)]:
        if os.path.exists(p):
            os.remove(p)


class TestInputValidation:
    """Test input validation owned by the runtime whitelist store."""

    def test_accept_valid_storage_path_in_worktree(self, test_settings):
        settings = {"whitelist": {"storage_path": "test_validation_whitelist.json"}}
        path = core.get_whitelist_storage_path(settings)
        assert path == (Path.cwd() / "test_validation_whitelist.json").resolve()

    def test_accept_valid_storage_path_in_tmp(self):
        settings = {"whitelist": {"storage_path": "/tmp/test_validation_whitelist.json"}}
        path = core.get_whitelist_storage_path(settings)
        assert path == Path("/tmp/test_validation_whitelist.json")

    def test_reject_storage_path_outside_allowed_roots(self):
        settings = {"whitelist": {"storage_path": "/etc/test_validation_whitelist.json"}}
        with pytest.raises(ValueError, match="must stay within"):
            core.get_whitelist_storage_path(settings)

    def test_reject_storage_path_traversal(self):
        settings = {"whitelist": {"storage_path": "../../escape.json"}}
        with pytest.raises(ValueError, match="must stay within"):
            core.get_whitelist_storage_path(settings)

    def test_reject_storage_path_when_cwd_is_root(self, monkeypatch):
        monkeypatch.setattr(core.os, "getcwd", lambda: "/")
        settings = {"whitelist": {"storage_path": "/etc/test_validation_whitelist.json"}}

        with pytest.raises(ValueError, match="must stay within"):
            core.get_whitelist_storage_path(settings)

    def test_reject_storage_path_with_wrong_suffix(self):
        settings = {"whitelist": {"storage_path": "/tmp/test_validation_whitelist.txt"}}
        with pytest.raises(ValueError, match="must use one of these suffixes"):
            core.get_whitelist_storage_path(settings)

    def test_reject_invalid_ip_address(self, whitelist_store):
        """Invalid IP addresses should be rejected."""
        future_time = int(time.time()) + 3600

        with pytest.raises(ValueError, match="Invalid IP address or CIDR notation"):
            whitelist_store.add("not-an-ip", future_time)

    def test_reject_invalid_cidr_notation(self, whitelist_store):
        """Invalid CIDR notation should be rejected."""
        future_time = int(time.time()) + 3600

        with pytest.raises(ValueError, match="Invalid IP address or CIDR notation"):
            whitelist_store.add("192.168.1.1/33", future_time)

    def test_reject_past_expiry_time(self, whitelist_store):
        """Expiry time in the past should be rejected."""
        past_time = int(time.time()) - 3600

        with pytest.raises(ValueError, match="not in the future"):
            whitelist_store.add("192.168.1.100", past_time)

    def test_reject_current_time_expiry(self, whitelist_store):
        """Expiry time equal to current time should be rejected."""
        current_time = int(time.time())

        with pytest.raises(ValueError, match="not in the future"):
            whitelist_store.add("192.168.1.100", current_time)

    def test_accept_valid_ipv4(self, whitelist_store):
        """Valid IPv4 address should be accepted."""
        future_time = int(time.time()) + 3600

        # Should not raise
        whitelist_store.add("192.168.1.100", future_time)

        whitelist = whitelist_store.active_snapshot()
        assert "192.168.1.100" in whitelist
        assert whitelist["192.168.1.100"] == future_time

    def test_accept_valid_ipv6(self, whitelist_store):
        """Valid IPv6 address should be accepted."""
        future_time = int(time.time()) + 3600

        # Should not raise
        whitelist_store.add("2001:db8::1", future_time)

        whitelist = whitelist_store.active_snapshot()
        assert "2001:db8::1" in whitelist

    def test_accept_valid_cidr(self, whitelist_store):
        """Valid CIDR notation should be accepted."""
        future_time = int(time.time()) + 3600

        # Should not raise
        whitelist_store.add("192.168.1.0/24", future_time)

        whitelist = whitelist_store.active_snapshot()
        assert "192.168.1.0/24" in whitelist


class TestCrossProcessLocking:
    """Test cross-process locking functionality."""

    def test_lock_file_created(self, test_settings, whitelist_store):
        """Lock file should be created during operations."""
        future_time = int(time.time()) + 3600
        whitelist_path = Path(test_settings["whitelist"]["storage_path"])
        lock_file_path = whitelist_path.with_suffix(".lock")

        # Perform an operation
        whitelist_store.add("192.168.1.100", future_time)

        # Lock file should exist after operation
        assert lock_file_path.exists()

    def test_concurrent_operations_safe(self, whitelist_store):
        """Concurrent operations should not corrupt the whitelist."""
        import threading

        future_time = int(time.time()) + 3600
        errors = []

        def add_ip(ip_suffix):
            try:
                whitelist_store.add(f"192.168.1.{ip_suffix}", future_time)
            except Exception as e:
                errors.append(e)

        # Create multiple threads adding different IPs
        threads = []
        for i in range(10):
            t = threading.Thread(target=add_ip, args=(i,))
            threads.append(t)
            t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join()

        # No errors should have occurred
        assert len(errors) == 0

        # All IPs should be in the whitelist
        whitelist = whitelist_store.active_snapshot()
        for i in range(10):
            assert f"192.168.1.{i}" in whitelist

    def test_cleanup_with_cross_process_lock(self, whitelist_store):
        """Cleanup operation should use cross-process lock."""
        # Add some entries
        now = int(time.time())
        future_time = now + 3600
        past_time = now - 3600

        # Manually create whitelist with mixed entries
        whitelist = {
            "192.168.1.1": future_time,
            "192.168.1.2": past_time,  # Expired
            "192.168.1.3": future_time,
        }
        whitelist_store.replace(whitelist)

        # Run cleanup
        whitelist_store.compact_expired()

        # Verify only non-expired entries remain
        cleaned_whitelist = whitelist_store.active_snapshot()
        assert "192.168.1.1" in cleaned_whitelist
        assert "192.168.1.2" not in cleaned_whitelist
        assert "192.168.1.3" in cleaned_whitelist


class TestCleanupImprovement:
    """Test improved cleanup with direct comparison."""

    def test_no_save_when_no_expired_entries(self, test_settings, whitelist_store):
        """Cleanup should not save if no entries expired."""
        future_time = int(time.time()) + 3600

        # Add non-expired entry
        whitelist_store.add("192.168.1.100", future_time)

        # Get the file's modification time
        whitelist_path = Path(test_settings["whitelist"]["storage_path"])
        mtime_before = time.time() - 10
        os.utime(whitelist_path, (mtime_before, mtime_before))

        # Run cleanup
        whitelist_store.compact_expired()

        # File should not have been modified
        mtime_after = whitelist_path.stat().st_mtime
        assert mtime_before == mtime_after

    def test_save_when_entries_expired(self, test_settings, whitelist_store):
        """Cleanup should save if entries expired."""
        now = int(time.time())

        # Manually create whitelist with expired entry
        whitelist = {
            "192.168.1.1": now + 3600,  # Future
            "192.168.1.2": now - 3600,  # Past (expired)
        }
        whitelist_store.replace(whitelist)

        # Get the file's modification time
        whitelist_path = Path(test_settings["whitelist"]["storage_path"])
        mtime_before = time.time() - 10
        os.utime(whitelist_path, (mtime_before, mtime_before))

        # Run cleanup
        whitelist_store.compact_expired()

        # File should have been modified
        mtime_after = whitelist_path.stat().st_mtime
        assert mtime_after > mtime_before

        # Verify expired entry was removed
        cleaned_whitelist = whitelist_store.active_snapshot()
        assert "192.168.1.1" in cleaned_whitelist
        assert "192.168.1.2" not in cleaned_whitelist
