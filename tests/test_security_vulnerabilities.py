"""
Security vulnerability tests for the Knocker service.
These tests demonstrate security issues that need to be fixed.
"""
import pytest
from fastapi.testclient import TestClient
from src.main import app, get_settings
from src import core


@pytest.fixture
def mock_settings_with_trusted_proxies():
    """Provides settings with specific trusted proxies configured."""
    return {
        "server": {
            "trusted_proxies": ["192.168.1.0/24", "10.0.0.0/8"]  # Only trust these networks
        },
        "api_keys": [
            {"key": "ADMIN_KEY", "max_ttl": 3600, "allow_remote_whitelist": True},
            {"key": "USER_KEY_1", "max_ttl": 600, "allow_remote_whitelist": False},
        ],
        "whitelist": {"storage_path": "./test_whitelist.json"},
        "security": {
            "always_allowed_ips": ["100.100.100.100"],
            "excluded_paths": ["/health", "/api/v1/public"]
        }
    }


@pytest.fixture(autouse=True)
def override_settings_security(mock_settings_with_trusted_proxies):
    """Override settings for security tests."""
    app.dependency_overrides[get_settings] = lambda: mock_settings_with_trusted_proxies
    yield
    app.dependency_overrides = {}


@pytest.fixture(autouse=True)
def cleanup_whitelist_security(mock_settings_with_trusted_proxies):
    """Ensure the test whitelist is clean before and after each test."""
    import os
    path = mock_settings_with_trusted_proxies["whitelist"]["storage_path"]
    if os.path.exists(path):
        os.remove(path)
    yield
    if os.path.exists(path):
        os.remove(path)


client = TestClient(app)


class TestIPSpoofingVulnerability:
    """Tests for IP spoofing vulnerabilities."""

    def test_ip_spoofing_via_x_forwarded_for_from_untrusted_source(self):
        """
        VULNERABILITY: Attacker can spoof their IP by setting X-Forwarded-For header
        even when request doesn't come from a trusted proxy.
        
        This test demonstrates that the current implementation blindly trusts
        X-Forwarded-For header regardless of the source IP.
        """
        # Simulate request from untrusted IP (1.2.3.4) trying to spoof as admin IP
        response = client.post(
            "/knock",
            headers={
                "X-Api-Key": "USER_KEY_1",
                "X-Forwarded-For": "100.100.100.100"  # Spoofing as always-allowed IP
            }
        )
        
        # This should fail because request comes from untrusted source
        # but currently it succeeds because trusted proxy validation is missing
        assert response.status_code == 200  # This shows the vulnerability
        assert response.json()["whitelisted_entry"] == "100.100.100.100"

    def test_ip_spoofing_allows_unauthorized_remote_whitelist(self):
        """
        VULNERABILITY: Attacker can spoof their IP to bypass remote whitelist restrictions.
        """
        # Simulate attacker spoofing IP to make it look like the request comes from allowed source
        response = client.post(
            "/knock",
            headers={
                "X-Api-Key": "USER_KEY_1",  # Key without remote whitelist permission
                "X-Forwarded-For": "192.168.1.100"  # Spoofed IP in trusted range
            },
            json={"ip_address": "8.8.8.8"}  # Trying to whitelist external IP
        )
        
        # Should fail because USER_KEY_1 doesn't have remote whitelist permission
        # But attacker could manipulate this by IP spoofing
        assert response.status_code == 403  # Correct behavior, but vulnerable to spoofing

    def test_valid_request_from_trusted_proxy_should_work(self):
        """
        This test shows how requests should work when properly implemented.
        """
        # Request that appears to come from trusted proxy
        response = client.post(
            "/knock",
            headers={
                "X-Api-Key": "ADMIN_KEY",
                "X-Forwarded-For": "5.6.7.8"
            }
        )
        
        # This should work
        assert response.status_code == 200
        assert response.json()["whitelisted_entry"] == "5.6.7.8"


class TestPathTraversalVulnerability:
    """Tests for path traversal vulnerabilities in excluded paths."""

    def test_path_traversal_in_excluded_paths(self):
        """
        VULNERABILITY: Path traversal could bypass authentication.
        """
        # Test various path traversal attempts
        test_cases = [
            "/health/../admin",
            "/api/v1/public/../secret", 
            "/health/../../sensitive",
            "/api/v1/public/./../../admin"
        ]
        
        for malicious_path in test_cases:
            response = client.get(
                "/verify",
                headers={
                    "X-Forwarded-For": "1.2.3.4",  # Unauthorized IP
                    "X-Forwarded-Uri": malicious_path
                }
            )
            
            # These might incorrectly pass due to simple startswith() check
            # Should be 401 for unauthorized IP, but might be 200 due to path traversal
            print(f"Path: {malicious_path}, Status: {response.status_code}")

    def test_url_encoding_bypass_in_excluded_paths(self):
        """
        VULNERABILITY: URL encoding might bypass path exclusion.
        """
        encoded_paths = [
            "/health%2F..%2Fadmin",
            "/api%2Fv1%2Fpublic%2F..%2Fsecret"
        ]
        
        for encoded_path in encoded_paths:
            response = client.get(
                "/verify", 
                headers={
                    "X-Forwarded-For": "1.2.3.4",
                    "X-Forwarded-Uri": encoded_path
                }
            )
            print(f"Encoded path: {encoded_path}, Status: {response.status_code}")


class TestInformationDisclosureVulnerability:
    """Tests for information disclosure in error messages."""

    def test_api_key_existence_disclosure(self):
        """
        VULNERABILITY: Different error messages could reveal if API key exists.
        """
        # Test with completely invalid key
        response1 = client.post(
            "/knock",
            headers={"X-Api-Key": "TOTALLY_FAKE_KEY", "X-Forwarded-For": "1.2.3.4"}
        )
        
        # Test with missing key
        response2 = client.post(
            "/knock",
            headers={"X-Forwarded-For": "1.2.3.4"}
        )
        
        # Both should return same error to prevent information disclosure
        assert response1.status_code == 401
        assert response2.status_code == 401
        
        # Error messages should be identical to prevent enumeration
        print(f"Invalid key error: {response1.json()}")
        print(f"Missing key error: {response2.json()}")


class TestConfigurationValidationVulnerability:
    """Tests for missing input validation."""

    def test_malicious_excluded_paths_config(self):
        """
        VULNERABILITY: No validation of excluded paths in configuration.
        """
        malicious_settings = {
            "server": {"trusted_proxies": ["127.0.0.1"]},
            "api_keys": [{"key": "TEST_KEY", "max_ttl": 600, "allow_remote_whitelist": False}],
            "whitelist": {"storage_path": "./test_whitelist.json"},
            "security": {
                "excluded_paths": [
                    "../../../etc/passwd",  # Path traversal
                    "//admin",              # Double slash
                    "",                     # Empty string could match everything
                    None                    # None value
                ]
            }
        }
        
        # Test if malicious paths cause issues
        try:
            for path in ["normal_path", "../sensitive", "//admin"]:
                result = core.is_path_excluded(path, malicious_settings)
                print(f"Path '{path}' excluded: {result}")
        except Exception as e:
            print(f"Error with malicious config: {e}")

    def test_invalid_trusted_proxies_config(self):
        """
        VULNERABILITY: No validation of trusted_proxies configuration.
        """
        malicious_settings = {
            "server": {
                "trusted_proxies": [
                    "not-an-ip",      # Invalid IP
                    "999.999.999.999", # Invalid IP format
                    "",               # Empty string
                    None              # None value
                ]
            }
        }
        
        # Test how system handles invalid trusted proxy config
        # This should be validated during configuration load
        print(f"Malicious trusted_proxies: {malicious_settings['server']['trusted_proxies']}")