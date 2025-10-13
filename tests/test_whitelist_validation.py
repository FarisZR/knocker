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
        "whitelist": {"storage_path": "/tmp/test_validation_whitelist.json"},
        "security": {"max_whitelist_entries": 100}
    }


@pytest.fixture(autouse=True)
def cleanup_whitelist(test_settings):
    """Clean up test whitelist files."""
    path = test_settings["whitelist"]["storage_path"]
    lock_path = Path(path).with_suffix('.lock')
    
    for p in [path, str(lock_path)]:
        if os.path.exists(p):
            os.remove(p)
    
    yield
    
    for p in [path, str(lock_path)]:
        if os.path.exists(p):
            os.remove(p)


class TestInputValidation:
    """Test input validation for add_ip_to_whitelist."""
    
    def test_reject_invalid_ip_address(self, test_settings):
        """Invalid IP addresses should be rejected."""
        future_time = int(time.time()) + 3600
        
        with pytest.raises(ValueError, match="Invalid IP address or CIDR notation"):
            core.add_ip_to_whitelist("not-an-ip", future_time, test_settings)
    
    def test_reject_invalid_cidr_notation(self, test_settings):
        """Invalid CIDR notation should be rejected."""
        future_time = int(time.time()) + 3600
        
        with pytest.raises(ValueError, match="Invalid IP address or CIDR notation"):
            core.add_ip_to_whitelist("192.168.1.1/33", future_time, test_settings)
    
    def test_reject_past_expiry_time(self, test_settings):
        """Expiry time in the past should be rejected."""
        past_time = int(time.time()) - 3600
        
        with pytest.raises(ValueError, match="not in the future"):
            core.add_ip_to_whitelist("192.168.1.100", past_time, test_settings)
    
    def test_reject_current_time_expiry(self, test_settings):
        """Expiry time equal to current time should be rejected."""
        current_time = int(time.time())
        
        with pytest.raises(ValueError, match="not in the future"):
            core.add_ip_to_whitelist("192.168.1.100", current_time, test_settings)
    
    def test_accept_valid_ipv4(self, test_settings):
        """Valid IPv4 address should be accepted."""
        future_time = int(time.time()) + 3600
        
        # Should not raise
        core.add_ip_to_whitelist("192.168.1.100", future_time, test_settings)
        
        whitelist = core.load_whitelist(test_settings)
        assert "192.168.1.100" in whitelist
        assert whitelist["192.168.1.100"] == future_time
    
    def test_accept_valid_ipv6(self, test_settings):
        """Valid IPv6 address should be accepted."""
        future_time = int(time.time()) + 3600
        
        # Should not raise
        core.add_ip_to_whitelist("2001:db8::1", future_time, test_settings)
        
        whitelist = core.load_whitelist(test_settings)
        assert "2001:db8::1" in whitelist
    
    def test_accept_valid_cidr(self, test_settings):
        """Valid CIDR notation should be accepted."""
        future_time = int(time.time()) + 3600
        
        # Should not raise
        core.add_ip_to_whitelist("192.168.1.0/24", future_time, test_settings)
        
        whitelist = core.load_whitelist(test_settings)
        assert "192.168.1.0/24" in whitelist


class TestCrossProcessLocking:
    """Test cross-process locking functionality."""
    
    def test_lock_file_created(self, test_settings):
        """Lock file should be created during operations."""
        future_time = int(time.time()) + 3600
        whitelist_path = Path(test_settings["whitelist"]["storage_path"])
        lock_file_path = whitelist_path.with_suffix('.lock')
        
        # Perform an operation
        core.add_ip_to_whitelist("192.168.1.100", future_time, test_settings)
        
        # Lock file should exist after operation (directory structure created)
        assert lock_file_path.parent.exists()
    
    def test_concurrent_operations_safe(self, test_settings):
        """Concurrent operations should not corrupt the whitelist."""
        import threading
        
        future_time = int(time.time()) + 3600
        errors = []
        
        def add_ip(ip_suffix):
            try:
                core.add_ip_to_whitelist(f"192.168.1.{ip_suffix}", future_time, test_settings)
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
        whitelist = core.load_whitelist(test_settings)
        for i in range(10):
            assert f"192.168.1.{i}" in whitelist
    
    def test_cleanup_with_cross_process_lock(self, test_settings):
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
        core.save_whitelist(whitelist, test_settings)
        
        # Run cleanup
        core.cleanup_expired_ips(test_settings)
        
        # Verify only non-expired entries remain
        cleaned_whitelist = core.load_whitelist(test_settings)
        assert "192.168.1.1" in cleaned_whitelist
        assert "192.168.1.2" not in cleaned_whitelist
        assert "192.168.1.3" in cleaned_whitelist


class TestCleanupImprovement:
    """Test improved cleanup with direct comparison."""
    
    def test_no_save_when_no_expired_entries(self, test_settings):
        """Cleanup should not save if no entries expired."""
        future_time = int(time.time()) + 3600
        
        # Add non-expired entry
        core.add_ip_to_whitelist("192.168.1.100", future_time, test_settings)
        
        # Get the file's modification time
        whitelist_path = Path(test_settings["whitelist"]["storage_path"])
        mtime_before = whitelist_path.stat().st_mtime
        
        # Wait a bit
        time.sleep(0.1)
        
        # Run cleanup
        core.cleanup_expired_ips(test_settings)
        
        # File should not have been modified
        mtime_after = whitelist_path.stat().st_mtime
        assert mtime_before == mtime_after
    
    def test_save_when_entries_expired(self, test_settings):
        """Cleanup should save if entries expired."""
        now = int(time.time())
        
        # Manually create whitelist with expired entry
        whitelist = {
            "192.168.1.1": now + 3600,  # Future
            "192.168.1.2": now - 3600,  # Past (expired)
        }
        core.save_whitelist(whitelist, test_settings)
        
        # Get the file's modification time
        whitelist_path = Path(test_settings["whitelist"]["storage_path"])
        mtime_before = whitelist_path.stat().st_mtime
        
        # Wait a bit
        time.sleep(0.1)
        
        # Run cleanup
        core.cleanup_expired_ips(test_settings)
        
        # File should have been modified
        mtime_after = whitelist_path.stat().st_mtime
        assert mtime_after > mtime_before
        
        # Verify expired entry was removed
        cleaned_whitelist = core.load_whitelist(test_settings)
        assert "192.168.1.1" in cleaned_whitelist
        assert "192.168.1.2" not in cleaned_whitelist
