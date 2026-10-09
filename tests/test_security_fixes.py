"""
Tests to verify that security vulnerabilities have been fixed.
"""

import pytest
import logging
from fastapi.testclient import TestClient
from src.main import app, get_settings
from src.config import SecuritySettings, validate_settings
from src import core


@pytest.fixture
def secure_settings():
    """Settings configuration with security features enabled."""
    return {
        "server": {"trusted_proxies": ["127.0.0.1", "172.29.238.0/24"]},
        "api_keys": [
            {"key": "ADMIN_KEY", "max_ttl": 3600, "allow_remote_whitelist": True, "name": "admin"},
            {"key": "USER_KEY", "max_ttl": 600, "allow_remote_whitelist": False, "name": "user"},
        ],
        "whitelist": {"storage_path": "./test_secure_whitelist.json"},
        "security": {
            "always_allowed_ips": ["192.168.1.100"],
            "excluded_paths": ["/api/status", "/healthz"],
            "max_whitelist_entries": 100,
        },
        "cors": {"allowed_origin": "https://trusted.example.com"},
    }


@pytest.fixture(autouse=True)
def override_settings_secure(secure_settings):
    """Override settings for security fix tests."""
    app.dependency_overrides[get_settings] = lambda: secure_settings
    yield
    app.dependency_overrides = {}


@pytest.fixture(autouse=True)
def cleanup_secure_whitelist(secure_settings):
    """Clean up test whitelist files."""
    import os

    path = secure_settings["whitelist"]["storage_path"]
    if os.path.exists(path):
        os.remove(path)
    yield
    if os.path.exists(path):
        os.remove(path)


client = TestClient(app)


class TestTrustedProxyValidation:
    """Test that trusted proxy validation prevents IP spoofing."""

    @pytest.mark.skip(
        reason="TestClient doesn't simulate network layers - requires network-level proxy behavior"
    )
    def test_trusted_proxy_allows_forwarded_header(self):
        """Requests from trusted proxies should honor X-Forwarded-For."""
        # This test simulates a request from a trusted proxy
        # In real deployment, this would be enforced at the network level
        pass  # Skip for now as TestClient doesn't simulate network layers

    @pytest.mark.skip(
        reason="TestClient doesn't simulate network layers - requires network-level proxy behavior"
    )
    def test_untrusted_source_ignores_forwarded_header(self):
        """Requests from untrusted sources should ignore X-Forwarded-For."""
        # This test would require mocking the client.host to simulate untrusted IP
        pass  # Skip for now as TestClient doesn't simulate network layers


class TestCIDRRangeValidation:
    """Test that CIDR range validation prevents abuse."""

    def test_reject_overly_broad_ipv4_range(self):
        """Overly broad IPv4 ranges should be rejected."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"},
            json={"ip_address": "0.0.0.0/0"},
        )
        assert response.status_code == 400
        assert "too broad" in response.json()["error"]

    def test_reject_overly_broad_ipv6_range(self):
        """Overly broad IPv6 ranges should be rejected."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"},
            json={"ip_address": "::/0"},
        )
        assert response.status_code == 400
        assert "too broad" in response.json()["error"]

    def test_accept_reasonable_cidr_ranges(self):
        """Reasonable CIDR ranges should be accepted."""
        reasonable_ranges = [
            "192.168.1.0/24",  # 256 IPs
            "10.0.0.0/20",  # 4096 IPs
            "2001:db8::/120",  # 256 IPv6 addresses
        ]

        for cidr_range in reasonable_ranges:
            response = client.post(
                "/knock",
                headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"},
                json={"ip_address": cidr_range},
            )
            assert response.status_code == 200, f"Failed for {cidr_range}"

    def test_reject_large_ipv4_range(self):
        """Large IPv4 ranges exceeding the limit should be rejected."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"},
            json={"ip_address": "10.0.0.0/8"},  # 16M+ addresses
        )
        assert response.status_code == 400
        assert "too broad" in response.json()["error"]


class TestPathTraversalPrevention:
    """Test that path traversal attacks are prevented."""

    def test_path_traversal_blocked(self):
        """Path traversal attempts should be blocked."""
        response = client.get(
            "/verify",
            headers={
                "X-Forwarded-For": "8.8.8.8",  # Non-whitelisted IP
                "X-Forwarded-Uri": "/api/status/../../../etc/passwd",
            },
        )
        # Should be blocked now due to path normalization
        assert response.status_code == 401

    def test_legitimate_excluded_paths_work(self):
        """Legitimate excluded paths should still work."""
        response = client.get(
            "/verify", headers={"X-Forwarded-For": "8.8.8.8", "X-Forwarded-Uri": "/api/status"}
        )
        assert response.status_code == 200

        response = client.get(
            "/verify",
            headers={"X-Forwarded-For": "8.8.8.8", "X-Forwarded-Uri": "/api/status/health"},
        )
        assert response.status_code == 200

    def test_normalized_paths_work(self):
        """Properly normalized paths should work correctly."""
        test_cases = [
            ("/api/status", True),  # Exact match
            ("/api/status/", True),  # With trailing slash
            ("/api/status/health", True),  # Subpath
            ("/api/status/../status", True),  # Normalized to /api/status
            ("/api/statusfake", False),  # Not a proper subpath
            ("/different/path", False),  # Different path
        ]

        for path, should_be_excluded in test_cases:
            response = client.get(
                "/verify", headers={"X-Forwarded-For": "8.8.8.8", "X-Forwarded-Uri": path}
            )
            expected_status = 200 if should_be_excluded else 401
            assert response.status_code == expected_status, f"Failed for path: {path}"


class TestAmbiguousPathExclusionGuard:
    """Request paths a backend may re-normalize must not use the exclusion shortcut."""

    # Families that survive knocker's single-decode normalization while staying
    # under the excluded prefix, yet resolve onto /admin on re-normalizing stacks.
    ambiguous_request_paths = [
        "/api/status/..;/admin",  # ;path-parameters stripped by Tomcat/Jetty/Spring
        "/api/status/%252e%252e/admin",  # double-encoded dot segments
        "/api/status/%252f..%252fadmin",  # double-encoded separators
        "/api/status/..%5C..%5Cadmin",  # backslash separator translation
        "/api/status/..%00/admin",  # NUL truncation on legacy stacks
        "/api/status/%c0%ae%c0%ae/admin",  # overlong UTF-8 decoding to "."
    ]

    def test_exclusion_refused_for_ambiguous_paths(self, secure_settings):
        """Ambiguous request paths never match an exclusion for a non-whitelisted IP."""
        for path in self.ambiguous_request_paths:
            assert core.is_path_excluded(path, secure_settings) is False, (
                f"Exclusion should be refused for: {path}"
            )

    def test_ambiguous_path_prefix_match_returns_false(self):
        """PathExclusions.matches() refuses ambiguous request paths outright."""
        security_settings = SecuritySettings.model_validate({"excluded_paths": ["/public"]})
        exclusions = core.PathExclusions.from_config(security_settings)

        for path in ("/public/..;/admin", "/public/%252e%252e/admin"):
            assert exclusions.matches(None, path) is False

        # Host-scoped exclusions inherit the same guard.
        scoped = SecuritySettings.model_validate(
            {"excluded_paths_by_host": {"files.example.com": ["/share"]}}
        )
        scoped_exclusions = core.PathExclusions.from_config(scoped)
        assert scoped_exclusions.matches("files.example.com", "/share/..;/admin") is False

    def test_ambiguous_paths_still_fall_through_to_whitelist(self):
        """Fail closed only drops the shortcut; a whitelisted IP is still allowed."""
        response = client.get(
            "/verify",
            headers={"X-Forwarded-For": "8.8.8.8", "X-Forwarded-Uri": "/api/status/..;/admin"},
        )
        assert response.status_code == 401

        client.post(
            "/knock",
            headers={"X-Api-Key": "USER_KEY", "X-Forwarded-For": "8.8.8.8"},
        )

        response = client.get(
            "/verify",
            headers={"X-Forwarded-For": "8.8.8.8", "X-Forwarded-Uri": "/api/status/..;/admin"},
        )
        assert response.status_code == 200

    @pytest.mark.parametrize("path", ambiguous_request_paths)
    def test_verify_rejects_ambiguous_paths_for_non_whitelisted_ip(self, path):
        """/verify must not treat an ambiguous request path as excluded."""
        response = client.get(
            "/verify", headers={"X-Forwarded-For": "8.8.8.8", "X-Forwarded-Uri": path}
        )
        assert response.status_code == 401, f"Expected 401 for path: {path}"

    def test_single_decode_traversals_still_rejected(self):
        """Already-neutralized single-decode traversals stay rejected (no regression)."""
        still_blocked = [
            "/api/status/../secret",
            "/api/status/%2e%2e/secret",
        ]
        for path in still_blocked:
            response = client.get(
                "/verify", headers={"X-Forwarded-For": "8.8.8.8", "X-Forwarded-Uri": path}
            )
            assert response.status_code == 401, f"Expected 401 for path: {path}"

    def test_plain_excluded_path_still_allowed(self):
        """A benign subpath under an excluded prefix stays unauthenticated."""
        response = client.get(
            "/verify", headers={"X-Forwarded-For": "8.8.8.8", "X-Forwarded-Uri": "/api/status/foo"}
        )
        assert response.status_code == 200

    def test_legitimate_single_encoded_paths_not_flagged(self):
        """Ordinary percent-encoding decodes fully once and keeps its exclusion."""
        legitimate_paths = [
            "/api/status/hello%20world",
            "/api/status/h%C3%A4llo",
            "/api/status/report%2Epdf",
        ]
        for path in legitimate_paths:
            response = client.get(
                "/verify", headers={"X-Forwarded-For": "8.8.8.8", "X-Forwarded-Uri": path}
            )
            assert response.status_code == 200, f"Expected 200 for path: {path}"

    def test_query_strings_do_not_trigger_the_guard(self, secure_settings):
        """Query strings are stripped before the ambiguity check."""
        request_path = "/api/status/list?filter=a%3Bb&next=%2Fprivate"
        assert core.is_path_excluded(request_path, secure_settings) is True

    def test_config_prefixes_with_marker_characters_still_load(self):
        """Configured prefixes are pre-normalized and never fail because of markers."""
        validated_security = SecuritySettings.model_validate(
            {
                "excluded_paths": ["/files;a=b", "/down%25load"],
                "excluded_paths_by_host": {"files.example.com": ["/downloads%252e"]},
            }
        )

        exclusions = core.PathExclusions.from_config(validated_security)

        assert exclusions.global_paths == ("/files;a=b", "/down%load")
        assert exclusions.host_paths["files.example.com"] == ("/downloads%2e",)

    def test_full_config_with_marker_prefixes_still_validates(self, secure_settings):
        """Settings validation accepts configurations using such marker characters."""
        config_dict = {
            **secure_settings,
            "security": {
                **secure_settings["security"],
                "excluded_paths": ["/api/status", "/files;a=b"],
                "excluded_paths_by_host": {"files.example.com": ["/share%20me"]},
            },
        }

        security_settings = validate_settings(config_dict).security

        assert security_settings.excluded_paths == ["/api/status", "/files;a=b"]
        assert security_settings.excluded_paths_by_host == {"files.example.com": ["/share%20me"]}


class TestInformationDisclosurePrevention:
    """Test that information disclosure has been reduced."""

    def test_api_key_names_not_in_logs(self, caplog):
        """API key names should not be logged in plaintext."""
        caplog.set_level(logging.INFO, logger="uvicorn.error")
        response = client.post(
            "/knock", headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"}
        )
        assert response.status_code == 200

        # Check that sensitive information is not in logs
        log_messages = [record.message for record in caplog.records]
        sensitive_logged = any("admin" in msg.lower() for msg in log_messages)
        assert not sensitive_logged

    def test_generic_error_messages(self):
        """Error messages should be generic and not leak system details."""
        response = client.post(
            "/knock", headers={"X-Api-Key": "INVALID_KEY", "X-Forwarded-For": "1.2.3.4"}
        )
        assert response.status_code == 401

        error_data = response.json()
        assert "error" in error_data
        # Error message should not contain internal details
        assert "database" not in error_data["error"].lower()
        assert "file" not in error_data["error"].lower()
        assert "path" not in error_data["error"].lower()


class TestWhitelistSizeLimits:
    """Test that whitelist size limits prevent DoS."""

    def test_whitelist_size_limit_enforced(self):
        """Whitelist should be limited to prevent unlimited growth."""
        # Add entries up to the limit
        max_entries = 100  # From our test config

        # Add entries beyond the limit
        for i in range(max_entries + 10):
            forwarded_ip = f"10.1.{i // 250}.{(i % 250) + 1}"
            response = client.post(
                "/knock",
                headers={
                    "X-Api-Key": "ADMIN_KEY",
                    "X-Forwarded-For": forwarded_ip,
                    "x-knocker-test-direct-ip": f"127.0.0.{(i % 250) + 1}",
                },
                json={"ip_address": f"10.0.{i // 256}.{i % 256}", "ttl": 3600},
            )
            assert response.status_code == 200

        # Check that whitelist doesn't exceed the limit
        settings = app.dependency_overrides[get_settings]()
        whitelist = core.ensure_runtime_state(settings).whitelist.active_snapshot()
        assert len(whitelist) <= max_entries


class TestCORSPolicy:
    """Test that CORS policy has been tightened."""

    def test_cors_origin_restricted(self):
        """CORS should not use wildcard origin."""
        response = client.options("/knock")
        assert response.status_code == 204
        cors_origin = response.headers.get("Access-Control-Allow-Origin")
        assert cors_origin != "*"
        assert cors_origin == "https://trusted.example.com"


class TestCoreSecurityFunctions:
    """Test the core security functions directly."""

    def test_is_safe_cidr_range(self):
        """Test CIDR range safety validation."""
        # Safe ranges
        assert core.is_safe_cidr_range("192.168.1.0/24") == True
        assert core.is_safe_cidr_range("10.0.0.0/20") == True
        assert core.is_safe_cidr_range("127.0.0.1/32") == True
        assert core.is_safe_cidr_range("2001:db8::/120") == True

        # Unsafe ranges
        assert core.is_safe_cidr_range("0.0.0.0/0") == False
        assert core.is_safe_cidr_range("10.0.0.0/8") == False
        assert core.is_safe_cidr_range("::/0") == False
        assert (
            core.is_safe_cidr_range("2001:db8::/32") == False
        )  # Too broad IPv6 (less restrictive than /64)

        # /64 should now be allowed for home networks
        assert core.is_safe_cidr_range("2001:db8::/64") == True

        # Custom limits
        assert core.is_safe_cidr_range("192.168.0.0/16", max_host_count=1000) == False
        assert core.is_safe_cidr_range("192.168.1.0/24", max_host_count=1000) == True

    def test_is_trusted_proxy(self):
        """Test trusted proxy validation."""
        trusted_proxies = ["127.0.0.1", "172.29.238.0/24", "10.0.0.0/8"]

        # Trusted IPs
        assert core.is_trusted_proxy("127.0.0.1", trusted_proxies) == True
        assert core.is_trusted_proxy("172.29.238.100", trusted_proxies) == True
        assert core.is_trusted_proxy("10.1.1.1", trusted_proxies) == True

        # Untrusted IPs
        assert core.is_trusted_proxy("8.8.8.8", trusted_proxies) == False
        assert core.is_trusted_proxy("192.168.1.1", trusted_proxies) == False

        # Invalid inputs
        assert core.is_trusted_proxy("", trusted_proxies) == False
        assert core.is_trusted_proxy("invalid-ip", trusted_proxies) == False
        assert core.is_trusted_proxy("127.0.0.1", []) == False

    def test_normalize_path(self):
        """Test path normalization function."""
        test_cases = [
            ("/api/status", "/api/status"),
            ("/api/status/", "/api/status"),
            ("/api/status/../status", "/api/status"),
            ("/api/status/../../etc/passwd", "/etc/passwd"),
            ("/api/./status", "/api/status"),
            ("//api///status//", "/api/status"),
            ("/api/status/./health", "/api/status/health"),
            ("", "/"),
            ("api/status", "/api/status"),
        ]

        for input_path, expected in test_cases:
            result = core.normalize_path(input_path)
            assert result == expected, (
                f"normalize_path('{input_path}') = '{result}', expected '{expected}'"
            )
