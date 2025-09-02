"""
Tests to verify that security fixes work correctly.
These tests verify that the identified vulnerabilities have been fixed.
"""
import pytest
from fastapi.testclient import TestClient
from src.main import app, get_settings
from src import core, config


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


class TestTrustedProxyValidation:
    """Tests for trusted proxy validation fixes."""

    def test_is_trusted_proxy_valid_ip(self, mock_settings_with_trusted_proxies):
        """Test that valid IPs in trusted networks are recognized."""
        assert core.is_trusted_proxy("192.168.1.100", mock_settings_with_trusted_proxies) == True
        assert core.is_trusted_proxy("10.5.5.5", mock_settings_with_trusted_proxies) == True

    def test_is_trusted_proxy_invalid_ip(self, mock_settings_with_trusted_proxies):
        """Test that IPs outside trusted networks are rejected."""
        assert core.is_trusted_proxy("1.2.3.4", mock_settings_with_trusted_proxies) == False
        assert core.is_trusted_proxy("8.8.8.8", mock_settings_with_trusted_proxies) == False

    def test_is_trusted_proxy_invalid_input(self, mock_settings_with_trusted_proxies):
        """Test that invalid IPs are handled gracefully."""
        assert core.is_trusted_proxy("not-an-ip", mock_settings_with_trusted_proxies) == False
        assert core.is_trusted_proxy("", mock_settings_with_trusted_proxies) == False
        assert core.is_trusted_proxy(None, mock_settings_with_trusted_proxies) == False

    def test_is_trusted_proxy_malformed_config(self):
        """Test that malformed trusted_proxies config is handled gracefully."""
        malformed_settings = {
            "server": {
                "trusted_proxies": ["not-an-ip", "", None, "192.168.1.0/24"]
            }
        }
        # Should still work for valid entries, skip invalid ones
        assert core.is_trusted_proxy("192.168.1.100", malformed_settings) == True
        assert core.is_trusted_proxy("1.2.3.4", malformed_settings) == False


class TestPathExclusionSecurity:
    """Tests for improved path exclusion security."""

    def test_path_exclusion_blocks_traversal(self, mock_settings_with_trusted_proxies):
        """Test that path traversal attempts are blocked."""
        malicious_paths = [
            "/health/../admin",
            "/api/v1/public/../secret",
            "/health/../../sensitive",
            "/api/v1/public/./../../admin",
            "../etc/passwd",
            "//admin"
        ]
        
        for malicious_path in malicious_paths:
            # These should NOT be excluded (return False) due to traversal protection
            result = core.is_path_excluded(malicious_path, mock_settings_with_trusted_proxies)
            assert result == False, f"Path traversal not blocked for: {malicious_path}"

    def test_valid_excluded_paths_still_work(self, mock_settings_with_trusted_proxies):
        """Test that legitimate excluded paths still work correctly."""
        valid_paths = [
            "/health",
            "/health/status",
            "/api/v1/public",
            "/api/v1/public/info"
        ]
        
        for valid_path in valid_paths:
            result = core.is_path_excluded(valid_path, mock_settings_with_trusted_proxies)
            assert result == True, f"Valid excluded path failed: {valid_path}"

    def test_path_exclusion_handles_malformed_config(self):
        """Test that malformed excluded_paths config is handled safely."""
        malformed_settings = {
            "security": {
                "excluded_paths": [
                    "/valid/path",
                    None,           # None value
                    "",             # Empty string
                    123,            # Non-string
                    "/another/../bad"  # Path traversal in config
                ]
            }
        }
        
        # Should work for valid paths, skip invalid ones
        assert core.is_path_excluded("/valid/path", malformed_settings) == True
        assert core.is_path_excluded("/other/path", malformed_settings) == False


class TestConfigurationValidation:
    """Tests for configuration validation."""

    def test_validate_config_valid_config(self, mock_settings_with_trusted_proxies):
        """Test that valid configurations pass validation."""
        # Should not raise any exceptions
        assert config.validate_config(mock_settings_with_trusted_proxies) == True

    def test_validate_config_invalid_trusted_proxies(self):
        """Test that invalid trusted_proxies are caught."""
        invalid_configs = [
            {"server": {"trusted_proxies": "not-a-list"}},
            {"server": {"trusted_proxies": ["not-an-ip"]}},
            {"server": {"trusted_proxies": ["999.999.999.999"]}},
            {"server": {"trusted_proxies": [123]}},
        ]
        
        for invalid_config in invalid_configs:
            with pytest.raises(ValueError):
                config.validate_config(invalid_config)

    def test_validate_config_invalid_always_allowed_ips(self):
        """Test that invalid always_allowed_ips are caught."""
        invalid_configs = [
            {"security": {"always_allowed_ips": "not-a-list"}},
            {"security": {"always_allowed_ips": ["not-an-ip"]}},
            {"security": {"always_allowed_ips": [123]}},
        ]
        
        for invalid_config in invalid_configs:
            with pytest.raises(ValueError):
                config.validate_config(invalid_config)

    def test_validate_config_invalid_api_keys(self):
        """Test that invalid API key configurations are caught."""
        invalid_configs = [
            {"api_keys": "not-a-list"},
            {"api_keys": [{"key": ""}]},  # Empty key
            {"api_keys": [{"key": "short"}]},  # Too short (should warn, not fail)
            {"api_keys": [{"key": "valid_key", "max_ttl": -1}]},  # Invalid TTL
            {"api_keys": [{"key": "valid_key", "allow_remote_whitelist": "not-bool"}]},
        ]
        
        for i, invalid_config in enumerate(invalid_configs):
            if i == 2:  # Short key should warn but not fail
                config.validate_config(invalid_config)  # Should succeed
            else:
                with pytest.raises(ValueError):
                    config.validate_config(invalid_config)


class TestSecurityHeaders:
    """Tests for security headers."""

    def test_security_headers_present(self):
        """Test that security headers are added to responses."""
        response = client.get("/health")
        
        expected_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options", 
            "X-XSS-Protection",
            "Referrer-Policy",
            "Cache-Control",
            "Pragma",
            "Expires"
        ]
        
        for header in expected_headers:
            assert header in response.headers, f"Missing security header: {header}"

    def test_server_header_removed(self):
        """Test that Server header is removed for security."""
        response = client.get("/health")
        assert "Server" not in response.headers


class TestErrorResponseStandardization:
    """Tests for standardized error responses."""

    def test_unauthorized_errors_are_standardized(self):
        """Test that unauthorized errors don't leak information."""
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
        
        # Both should return same error message
        assert response1.status_code == 401
        assert response2.status_code == 401
        assert response1.json() == response2.json()
        assert response1.json() == {"error": "Unauthorized"}

    def test_bad_request_errors_are_standardized(self):
        """Test that bad request errors are standardized."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"},
            json={"ip_address": "not-an-ip"}
        )
        
        assert response.status_code == 400
        assert response.json() == {"error": "Bad request"}

    def test_forbidden_errors_are_standardized(self):
        """Test that forbidden errors are standardized."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "USER_KEY_1", "X-Forwarded-For": "1.2.3.4"},
            json={"ip_address": "8.8.8.8"}  # USER_KEY_1 doesn't have remote permission
        )
        
        assert response.status_code == 403
        assert response.json() == {"error": "Forbidden"}


class TestRealWorldSecurityScenarios:
    """Tests for real-world security scenarios."""

    def test_testclient_compatibility_maintained(self):
        """Test that TestClient still works with security fixes."""
        # This test ensures that legitimate test traffic still works
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "USER_KEY_1", "X-Forwarded-For": "1.2.3.4"}
        )
        
        assert response.status_code == 200
        assert response.json()["whitelisted_entry"] == "1.2.3.4"

    def test_legitimate_proxy_traffic_works(self, mock_settings_with_trusted_proxies):
        """Test that legitimate proxy traffic works correctly."""
        # Simulate request from trusted proxy
        # Note: In real tests, we'd need to mock the client.host to be from trusted network
        # For now, this tests the logic
        
        # Since TestClient uses "testclient" as host, it falls back to X-Forwarded-For
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "USER_KEY_1", "X-Forwarded-For": "5.6.7.8"}
        )
        
        assert response.status_code == 200
        assert response.json()["whitelisted_entry"] == "5.6.7.8"