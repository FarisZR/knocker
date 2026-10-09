"""
Tests for production hardening improvements.
Tests timing attack resistance, edge case handling, and input validation.
"""

import pytest
import asyncio
import inspect
import logging
import threading
from unittest.mock import Mock
from pathlib import Path
from fastapi.testclient import TestClient
from src.main import app, get_settings
from src import core
from src.main import _full_readiness_check, reset_firewalld_readiness_cache


def _minimal_valid_config_yaml() -> str:
    return """
server:
  trusted_proxies:
    - "127.0.0.1"
cors:
  allowed_origin: "https://example.com"
security:
  always_allowed_ips: []
  excluded_paths: []
  max_whitelist_entries: 100
whitelist:
  storage_path: "/tmp/knocker-test-whitelist.json"
  cleanup_interval_seconds: 60
api_keys:
  - name: "primary"
    key: "secret-1"
    max_ttl: 3600
    allow_remote_whitelist: true
documentation:
  enabled: false
""".strip()


def _write_config(tmp_path: Path, content: str) -> Path:
    config_file = tmp_path / "test_config.yaml"
    config_file.write_text(content)
    return config_file


@pytest.fixture
def test_settings():
    """Test settings with multiple API keys."""
    return {
        "server": {"trusted_proxies": ["127.0.0.1", "172.29.238.0/24"]},
        "api_keys": [
            {
                "key": "valid_key_12345",
                "max_ttl": 3600,
                "allow_remote_whitelist": True,
                "name": "test1",
            },
            {
                "key": "another_valid_key",
                "max_ttl": 600,
                "allow_remote_whitelist": False,
                "name": "test2",
            },
        ],
        "whitelist": {"storage_path": "./test_prod_whitelist.json"},
        "security": {
            "always_allowed_ips": ["192.168.1.100"],
            "excluded_paths": ["/health"],
            "max_whitelist_entries": 100,
        },
        "cors": {"allowed_origin": "https://example.com"},
    }


@pytest.fixture(autouse=True)
def override_settings(test_settings):
    """Override settings for all tests."""
    app.dependency_overrides[get_settings] = lambda: test_settings
    yield
    app.dependency_overrides = {}


@pytest.fixture(autouse=True)
def cleanup_whitelist(test_settings):
    """Clean up test whitelist files."""
    import os

    path = test_settings["whitelist"]["storage_path"]
    if os.path.exists(path):
        os.remove(path)
    yield
    if os.path.exists(path):
        os.remove(path)


class _FakeMonotonicClock:
    """Controllable stand-in for the time module used by the readiness cache."""

    def __init__(self, start: float = 1000.0):
        self.now = start

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture(autouse=True)
def isolate_firewalld_ready_cache():
    """Keep the cached readiness verdict isolated between tests."""
    reset_firewalld_readiness_cache()
    yield
    reset_firewalld_readiness_cache()


client = TestClient(app)


class TestTimingAttackResistance:
    """Test that API key validation is resistant to timing attacks."""

    def test_dockerfile_disables_uvicorn_proxy_header_rewrite(self):
        dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile"
        content = dockerfile.read_text(encoding="utf-8")

        assert "--no-proxy-headers" in content
        assert "--forwarded-allow-ips" not in content

    def test_constant_time_validation_scans_all_keys(self, test_settings, monkeypatch):
        """Validation compares every configured key without an early return."""
        compared_keys = []
        original_verify = core.APIKeyRecord.verify
        verify_source = inspect.getsource(original_verify)

        def verify(record, presented_key):
            compared_keys.append(record.key)
            return original_verify(record, presented_key)

        monkeypatch.setattr(core.APIKeyRecord, "verify", verify)
        configured_keys = [record["key"] for record in test_settings["api_keys"]]

        assert core.is_valid_api_key(configured_keys[0], test_settings) is True
        assert compared_keys == configured_keys

        compared_keys.clear()
        assert core.is_valid_api_key("invalid_key_12345", test_settings) is False
        assert compared_keys == configured_keys
        assert "hmac.compare_digest" in verify_source

    def test_empty_api_key_handled(self, test_settings):
        """Empty API key should be handled gracefully."""
        assert core.is_valid_api_key("", test_settings) == False
        assert core.is_valid_api_key(None, test_settings) == False

    def test_empty_api_keys_list_raises_configuration_error(self):
        """Empty API keys list should surface a configuration error."""
        settings = {"api_keys": []}
        with pytest.raises(ValueError, match="Configuration must contain at least one API key"):
            core.is_valid_api_key("any_key", settings)


class TestTTLEdgeCases:
    """Test TTL validation edge cases."""

    def test_zero_ttl_rejected(self):
        """TTL of 0 should be rejected."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={"ttl": 0},
        )
        assert response.status_code == 400
        assert "positive integer" in response.json()["error"].lower()

    def test_negative_ttl_rejected(self):
        """Negative TTL should be rejected."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={"ttl": -100},
        )
        assert response.status_code == 400
        assert "positive integer" in response.json()["error"].lower()

    def test_extremely_large_ttl_rejected(self):
        """Extremely large TTL (>10 years) should be rejected."""
        ten_years = 315360000
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={"ttl": ten_years + 1},
        )
        assert response.status_code == 400
        assert "too large" in response.json()["error"].lower()

    def test_max_valid_ttl_accepted(self):
        """Maximum valid TTL (10 years) should be accepted but capped by key limit."""
        ten_years = 315360000
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={"ttl": ten_years},
        )
        assert response.status_code == 200
        # Should be capped to key's max_ttl (3600)
        assert response.json()["expires_in_seconds"] == 3600

    def test_float_ttl_rejected(self):
        """Float TTL should be rejected."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={"ttl": 3.14},
        )
        assert response.status_code == 400

    def test_string_ttl_rejected(self):
        """String TTL should be rejected."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={"ttl": "3600"},
        )
        assert response.status_code == 400


class TestInputSizeValidation:
    """Test input size limits to prevent DoS."""

    def test_extremely_long_ip_rejected(self):
        """IP address longer than 100 chars should be rejected."""
        long_ip = "1.2.3.4" + "x" * 100
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={"ip_address": long_ip},
        )
        assert response.status_code == 400
        assert "too long" in response.json()["error"].lower()

    def test_non_string_ip_rejected(self):
        """Non-string IP should be rejected."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={"ip_address": 12345},
        )
        assert response.status_code == 400

    def test_valid_ipv6_length_accepted(self):
        """Valid IPv6 with CIDR should be accepted."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={"ip_address": "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"},
        )
        assert response.status_code == 200


class TestHealthCheckDependencies:
    """Test liveness and readiness endpoint behavior."""

    def test_health_check_with_valid_config(self):
        """Health check should pass with valid configuration."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_health_check_detects_missing_api_keys(self):
        """Health check should fail if no API keys are configured."""
        bad_settings = {
            "api_keys": [],
            "whitelist": {"storage_path": "./test_health_whitelist.json"},
        }
        app.dependency_overrides[get_settings] = lambda: bad_settings

        response = client.get("/health")
        assert response.status_code == 503
        assert "unhealthy" in response.json()["status"]

        app.dependency_overrides = {}

    def test_health_check_detects_storage_issues(self, test_settings, monkeypatch):
        """Readiness should detect inaccessible storage."""
        bad_settings = {**test_settings, "whitelist": {"storage_path": "./will_fail.json"}}
        app.dependency_overrides[get_settings] = lambda: bad_settings

        monkeypatch.setattr("src.main.os.access", lambda *_args, **_kwargs: False)
        resp = client.get("/ready")
        assert resp.status_code == 503
        app.dependency_overrides = {}

    def test_health_does_not_probe_firewalld(self, test_settings, monkeypatch):
        """Liveness must stay cheap even when firewalld is enabled."""
        test_settings["firewalld"] = {"enabled": True}
        app.dependency_overrides[get_settings] = lambda: test_settings

        def unexpected_probe():
            pytest.fail("liveness probe queried firewalld")

        monkeypatch.setattr("src.main.firewalld.get_firewalld_integration", unexpected_probe)

        response = client.get("/health")

        assert response.status_code == 200

    def test_readiness_verifies_firewalld(self, test_settings, monkeypatch):
        """Readiness must retain the full read-only firewalld verification."""
        test_settings["firewalld"] = {"enabled": True}
        app.dependency_overrides[get_settings] = lambda: test_settings
        integration = Mock()
        integration.is_enabled.return_value = True
        integration.verify_protection.return_value = False
        monkeypatch.setattr("src.main.firewalld.get_firewalld_integration", lambda: integration)

        response = client.get("/ready")

        assert response.status_code == 503
        integration.verify_protection.assert_called_once_with()

    def test_readiness_caches_successful_verification_within_ttl(self, test_settings, monkeypatch):
        """Repeated readiness polls inside the TTL must reuse one verification run."""
        test_settings["firewalld"] = {"enabled": True}
        app.dependency_overrides[get_settings] = lambda: test_settings
        clock = _FakeMonotonicClock()
        monkeypatch.setattr("src.main.time", clock)
        integration = Mock()
        integration.is_enabled.return_value = True
        integration.verify_protection.return_value = True
        monkeypatch.setattr("src.main.firewalld.get_firewalld_integration", lambda: integration)

        for _ in range(5):
            assert client.get("/ready").status_code == 200
            clock.advance(1.0)

        assert integration.verify_protection.call_count == 1

    def test_readiness_refreshes_firewalld_verdict_after_cache_ttl(
        self, test_settings, monkeypatch
    ):
        """A stale verdict must trigger a fresh verification chain."""
        test_settings["firewalld"] = {"enabled": True}
        app.dependency_overrides[get_settings] = lambda: test_settings
        clock = _FakeMonotonicClock()
        monkeypatch.setattr("src.main.time", clock)
        integration = Mock()
        integration.is_enabled.return_value = True
        integration.verify_protection.side_effect = [True, False]
        monkeypatch.setattr("src.main.firewalld.get_firewalld_integration", lambda: integration)

        assert client.get("/ready").status_code == 200

        # Just before the TTL the cached verdict is still served.
        clock.advance(9.0)
        assert client.get("/ready").status_code == 200
        assert integration.verify_protection.call_count == 1

        clock.advance(1.0)
        assert client.get("/ready").status_code == 503
        assert integration.verify_protection.call_count == 2

    def test_readiness_cache_is_keyed_to_integration_instance(self, test_settings, monkeypatch):
        """A reloaded firewalld integration must never inherit a cached verdict."""
        test_settings["firewalld"] = {"enabled": True}
        app.dependency_overrides[get_settings] = lambda: test_settings
        first_integration = Mock()
        first_integration.is_enabled.return_value = True
        first_integration.verify_protection.return_value = True
        second_integration = Mock()
        second_integration.is_enabled.return_value = True
        monkeypatch.setattr(
            "src.main.firewalld.get_firewalld_integration", lambda: first_integration
        )

        assert client.get("/ready").status_code == 200

        # Different instance inside the TTL window must not reuse the verdict.
        monkeypatch.setattr(
            "src.main.firewalld.get_firewalld_integration", lambda: second_integration
        )
        assert client.get("/ready").status_code == 200
        assert second_integration.verify_protection.call_count == 1
        assert first_integration.verify_protection.call_count == 1

    def test_concurrent_readiness_requests_share_one_verification(self, test_settings, monkeypatch):
        """Parallel readiness polls must collapse into a single firewall-cmd chain."""
        test_settings["firewalld"] = {"enabled": True}
        app.dependency_overrides[get_settings] = lambda: test_settings
        integration = Mock()
        integration.is_enabled.return_value = True
        calls: list[int] = []
        release = threading.Event()

        def verify():
            calls.append(1)
            release.wait(timeout=5)
            return True

        integration.verify_protection.side_effect = verify
        monkeypatch.setattr("src.main.firewalld.get_firewalld_integration", lambda: integration)

        async def poll_together():
            tasks = [asyncio.create_task(_full_readiness_check(test_settings)) for _ in range(8)]
            await asyncio.sleep(0.1)
            running_chains = len(calls)
            release.set()
            results = await asyncio.gather(*tasks)
            return results, running_chains

        responses, running_chains = asyncio.run(poll_together())

        assert all(response is None for response in responses)
        assert running_chains == 1
        assert len(calls) == 1

    def test_cancelled_readiness_request_keeps_shared_verification(
        self, test_settings, monkeypatch
    ):
        """Cancelling one poller must not start a second verification chain."""
        test_settings["firewalld"] = {"enabled": True}
        app.dependency_overrides[get_settings] = lambda: test_settings
        integration = Mock()
        integration.is_enabled.return_value = True
        started = threading.Event()
        release = threading.Event()

        def verify():
            started.set()
            release.wait(timeout=5)
            return True

        integration.verify_protection.side_effect = verify
        monkeypatch.setattr("src.main.firewalld.get_firewalld_integration", lambda: integration)

        async def cancel_then_retry():
            first = asyncio.create_task(_full_readiness_check(test_settings))
            assert await asyncio.to_thread(started.wait, 5)

            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first

            second = asyncio.create_task(_full_readiness_check(test_settings))
            release.set()
            return await second

        result = asyncio.run(cancel_then_retry())

        assert result is None
        assert integration.verify_protection.call_count == 1


class TestConfigurationValidation:
    """Test configuration loading validation."""

    def test_duplicate_api_keys_detected(self, tmp_path, caplog):
        """Duplicate API keys should be detected during config load."""
        import os
        from src import config

        # Save original env var
        original_path = os.environ.get("KNOCKER_CONFIG_PATH")

        try:
            config_file = _write_config(
                tmp_path,
                _minimal_valid_config_yaml().replace(
                    "allow_remote_whitelist: true",
                    'allow_remote_whitelist: true\n  - name: "duplicate"\n    key: "secret-1"\n    max_ttl: 600\n    allow_remote_whitelist: false',
                    1,
                ),
            )

            # Set environment variable
            os.environ["KNOCKER_CONFIG_PATH"] = str(config_file)

            # Should exit with error
            caplog.set_level(logging.CRITICAL)
            with pytest.raises(SystemExit) as exc_info:
                config.load_config()

            assert exc_info.value.code == 1
            assert "Duplicate API key material detected at index 1" in caplog.text
        finally:
            # Restore original env var
            if original_path:
                os.environ["KNOCKER_CONFIG_PATH"] = original_path
            elif "KNOCKER_CONFIG_PATH" in os.environ:
                del os.environ["KNOCKER_CONFIG_PATH"]

    def test_empty_api_keys_detected(self, tmp_path, caplog):
        """Empty API keys list should be detected."""
        import os
        from src import config

        original_path = os.environ.get("KNOCKER_CONFIG_PATH")

        try:
            config_content = _minimal_valid_config_yaml().replace(
                'api_keys:\n  - name: "primary"\n    key: "secret-1"\n    max_ttl: 3600\n    allow_remote_whitelist: true',
                "api_keys: []",
            )
            config_file = _write_config(tmp_path, config_content)

            os.environ["KNOCKER_CONFIG_PATH"] = str(config_file)

            caplog.set_level(logging.CRITICAL)
            with pytest.raises(SystemExit) as exc_info:
                config.load_config()

            assert exc_info.value.code == 1
            assert "Configuration must contain at least one API key" in caplog.text
        finally:
            if original_path:
                os.environ["KNOCKER_CONFIG_PATH"] = original_path
            elif "KNOCKER_CONFIG_PATH" in os.environ:
                del os.environ["KNOCKER_CONFIG_PATH"]

    def test_path_traversal_in_config_path_rejected(self, tmp_path, caplog):
        """Path traversal in KNOCKER_CONFIG_PATH should be rejected."""
        import os
        from src import config

        original_path = os.environ.get("KNOCKER_CONFIG_PATH")

        try:
            _write_config(tmp_path, _minimal_valid_config_yaml())

            # Try to use path traversal
            os.environ["KNOCKER_CONFIG_PATH"] = "../../../etc/passwd"

            caplog.set_level(logging.CRITICAL)
            with pytest.raises(SystemExit) as exc_info:
                config.load_config()

            assert exc_info.value.code == 1
            assert "Invalid configuration path: ../../../etc/passwd" in caplog.text
        finally:
            if original_path:
                os.environ["KNOCKER_CONFIG_PATH"] = original_path
            elif "KNOCKER_CONFIG_PATH" in os.environ:
                del os.environ["KNOCKER_CONFIG_PATH"]


class TestAPIKeyValidation:
    """Test comprehensive API key validation."""

    def test_missing_api_key_rejected(self):
        """Request without API key should be rejected."""
        response = client.post("/knock", headers={"X-Forwarded-For": "1.2.3.4"}, json={})
        assert response.status_code == 401

    def test_invalid_api_key_rejected(self):
        """Request with invalid API key should be rejected."""
        response = client.post(
            "/knock", headers={"X-Api-Key": "invalid_key", "X-Forwarded-For": "1.2.3.4"}, json={}
        )
        assert response.status_code == 401

    def test_valid_api_key_accepted(self):
        """Request with valid API key should be accepted."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={},
        )
        assert response.status_code == 200


class TestEdgeCaseHandling:
    """Test various edge cases in the application."""

    def test_concurrent_requests_handled(self):
        """Multiple concurrent requests should be handled safely."""
        import threading

        results = []

        def make_request():
            response = client.post(
                "/knock",
                headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
                json={},
            )
            results.append(response.status_code)

        threads = [threading.Thread(target=make_request) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All requests should succeed
        assert all(code == 200 for code in results)

    def test_malformed_json_rejected(self, test_settings, monkeypatch):
        """Malformed JSON should be rejected gracefully."""
        import os

        # Ensure KNOCKER_CONFIG_PATH is set to a valid path for this test
        # since previous tests may have changed it
        test_config_path = os.path.abspath("knocker.example.yaml")
        if os.path.exists(test_config_path):
            monkeypatch.setenv("KNOCKER_CONFIG_PATH", test_config_path)

        response = client.post(
            "/knock",
            headers={
                "X-Api-Key": "valid_key_12345",
                "X-Forwarded-For": "1.2.3.4",
                "Content-Type": "application/json",
            },
            content="{ invalid json }",
        )
        assert response.status_code == 422 or response.status_code == 400

    def test_empty_request_body_accepted(self):
        """Empty request body should be accepted (whitelist client IP)."""
        response = client.post(
            "/knock", headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"}
        )
        assert response.status_code == 200
        assert response.json()["whitelisted_entry"] == "1.2.3.4"
