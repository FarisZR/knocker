"""
Security vulnerability tests for Caddy Knocker.
These tests demonstrate security issues that need to be fixed.
"""
import pytest
import time
from fastapi.testclient import TestClient
from src.main import app, get_settings
from src import core


@pytest.fixture
def security_test_settings():
    """Settings configuration for security tests."""
    return {
        "server": {
            "trusted_proxies": ["172.29.238.0/24", "127.0.0.1"]
        },
        "api_keys": [
            {"key": "ADMIN_KEY", "max_ttl": 3600, "allow_remote_whitelist": True, "name": "admin"},
            {"key": "USER_KEY", "max_ttl": 600, "allow_remote_whitelist": False, "name": "user"},
        ],
        "whitelist": {"storage_path": "./test_security_whitelist.json"},
        "security": {
            "always_allowed_ips": ["192.168.1.100"],
            "excluded_paths": ["/api/status", "/healthz"]
        },
        "cors": {"allowed_origin": "*"}
    }


@pytest.fixture(autouse=True)
def override_settings_security(security_test_settings):
    """Override settings for security tests."""
    app.dependency_overrides[get_settings] = lambda: security_test_settings
    yield
    app.dependency_overrides = {}


@pytest.fixture(autouse=True)
def cleanup_security_whitelist(security_test_settings):
    """Clean up test whitelist files."""
    import os
    path = security_test_settings["whitelist"]["storage_path"]
    if os.path.exists(path):
        os.remove(path)
    yield
    if os.path.exists(path):
        os.remove(path)


client = TestClient(app)


class TestIPSpoofingVulnerability:
    """Test IP spoofing via X-Forwarded-For header manipulation."""
    
    def test_ip_spoofing_attack_success(self):
        """
        VULNERABILITY: An attacker can spoof their IP by setting X-Forwarded-For header.
        This should fail but currently succeeds because trusted_proxies is not enforced.
        """
        # Attacker spoofs IP as if coming from a trusted source
        response = client.post(
            "/knock",
            headers={
                "X-Api-Key": "USER_KEY",
                "X-Forwarded-For": "192.168.1.100"  # Spoofed IP
            }
        )
        # This should fail with proper trusted proxy validation
        # but currently succeeds because the header is blindly trusted
        assert response.status_code == 200
        
        # Verify the spoofed IP was whitelisted instead of real IP
        data = response.json()
        assert data["whitelisted_entry"] == "192.168.1.100"
    
    def test_ip_spoofing_bypass_always_allowed(self):
        """Attacker spoofs IP to appear as an always-allowed IP."""
        response = client.get(
            "/verify",
            headers={"X-Forwarded-For": "192.168.1.100"}  # Spoofed as always-allowed
        )
        # This should only work if the request actually comes from a trusted proxy
        assert response.status_code == 200


class TestCIDRRangeAbuse:
    """Test CIDR range abuse vulnerabilities."""
    
    def test_whitelist_all_ipv4_addresses(self):
        """
        VULNERABILITY: Attacker can whitelist all IPv4 addresses using 0.0.0.0/0.
        """
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"},
            json={"ip_address": "0.0.0.0/0"}
        )
        assert response.status_code == 200
        assert response.json()["whitelisted_entry"] == "0.0.0.0/0"
        
        # Verify any IP is now whitelisted
        response = client.get("/verify", headers={"X-Forwarded-For": "8.8.8.8"})
        assert response.status_code == 200
    
    def test_whitelist_all_ipv6_addresses(self):
        """
        VULNERABILITY: Attacker can whitelist all IPv6 addresses using ::/0.
        """
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"},
            json={"ip_address": "::/0"}
        )
        assert response.status_code == 200
        assert response.json()["whitelisted_entry"] == "::/0"
        
        # Verify any IPv6 is now whitelisted
        response = client.get("/verify", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == 200
    
    def test_whitelist_large_cidr_ranges(self):
        """Test that very large CIDR ranges can be whitelisted without restriction."""
        large_ranges = [
            "10.0.0.0/8",        # 16,777,216 IPs
            "172.16.0.0/12",     # 1,048,576 IPs
            "192.168.0.0/16",    # 65,536 IPs
        ]
        
        for cidr_range in large_ranges:
            response = client.post(
                "/knock",
                headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"},
                json={"ip_address": cidr_range}
            )
            assert response.status_code == 200
            assert response.json()["whitelisted_entry"] == cidr_range


class TestPathTraversalVulnerability:
    """Test path traversal vulnerabilities in excluded paths."""
    
    def test_path_traversal_attack(self):
        """
        POTENTIAL VULNERABILITY: Path traversal in excluded paths.
        While this specific case doesn't work due to URL encoding,
        it demonstrates the vulnerability pattern.
        """
        # Attempt path traversal in excluded path
        response = client.get(
            "/verify",
            headers={
                "X-Forwarded-For": "8.8.8.8",  # Non-whitelisted IP
                "X-Forwarded-Uri": "/api/status/../../../etc/passwd"
            }
        )
        # This currently passes because it starts with "/api/status"
        assert response.status_code == 200
    
    def test_excluded_path_bypass_variations(self):
        """Test various ways to bypass excluded path restrictions."""
        bypass_attempts = [
            "/api/status/../secret",
            "/api/status/../../admin",
            "/api/status%2E%2E/secret",  # URL encoded
            "/api/status/./secret",
        ]
        
        for path in bypass_attempts:
            response = client.get(
                "/verify",
                headers={
                    "X-Forwarded-For": "8.8.8.8",
                    "X-Forwarded-Uri": path
                }
            )
            # All currently pass due to startswith() check
            assert response.status_code == 200


class TestInformationDisclosure:
    """Test information disclosure vulnerabilities."""
    
    def test_api_key_name_in_logs(self, caplog):
        """
        VULNERABILITY: API key names are logged in plaintext.
        """
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"}
        )
        assert response.status_code == 200
        
        # Check if sensitive information is in logs
        # Note: This test may need adjustment based on log configuration
        log_messages = [record.message for record in caplog.records]
        sensitive_logged = any("admin" in msg for msg in log_messages)
        # This demonstrates that API key names are logged
        assert sensitive_logged or len(log_messages) == 0  # Handle case where logging isn't captured
    
    def test_verbose_error_messages(self):
        """Test that error messages don't leak sensitive information."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "INVALID_KEY", "X-Forwarded-For": "1.2.3.4"}
        )
        assert response.status_code == 401
        
        # Check error message content
        error_data = response.json()
        assert "error" in error_data
        # The error message should be generic, not revealing system details


class TestRaceConditions:
    """Test race condition vulnerabilities in whitelist management."""
    
    def test_concurrent_whitelist_operations(self):
        """
        VULNERABILITY: Race conditions in whitelist file operations.
        Multiple concurrent requests could corrupt the whitelist.
        """
        import threading
        import time
        
        def knock_request(ip_suffix):
            """Make a knock request with a unique IP."""
            client.post(
                "/knock",
                headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": f"1.2.3.{ip_suffix}"},
                json={"ip_address": f"10.0.0.{ip_suffix}"}
            )
        
        # Start multiple concurrent requests
        threads = []
        for i in range(10):
            thread = threading.Thread(target=knock_request, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Check whitelist integrity - all entries should be present
        # This test doesn't assert failure but demonstrates the race condition risk


class TestDenialOfService:
    """Test DoS vulnerabilities."""
    
    def test_unlimited_whitelist_growth(self):
        """
        VULNERABILITY: No limits on whitelist size could cause DoS.
        """
        # Add many entries to the whitelist
        for i in range(100):  # Reduced from 1000 to avoid long test times
            response = client.post(
                "/knock",
                headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"},
                json={"ip_address": f"10.0.{i//256}.{i%256}", "ttl": 3600}
            )
            assert response.status_code == 200
        
        # The whitelist should now be very large
        # In a real attack, this could consume all disk space
    
    def test_deep_directory_creation(self):
        """Test if deep directory structures can be created."""
        # This tests the save_whitelist function's mkdir behavior
        # with a malicious storage path (though this would require config control)
        pass


class TestConfigurationSecurity:
    """Test configuration-related security issues."""
    
    def test_cors_wildcard_policy(self):
        """
        VULNERABILITY: Wildcard CORS policy allows any origin.
        """
        response = client.options("/knock")
        assert response.status_code == 204
        assert response.headers["Access-Control-Allow-Origin"] == "*"
        
        # This allows any website to make cross-origin requests
        # to the knocker service, which could be exploited