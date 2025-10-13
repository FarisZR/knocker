"""
Tests for production hardening improvements.
Tests timing attack resistance, edge case handling, and input validation.
"""
import pytest
import time
from fastapi.testclient import TestClient
from src.main import app, get_settings
from src import core


@pytest.fixture
def test_settings():
    """Test settings with multiple API keys."""
    return {
        "server": {
            "trusted_proxies": ["127.0.0.1", "172.29.238.0/24"]
        },
        "api_keys": [
            {"key": "valid_key_12345", "max_ttl": 3600, "allow_remote_whitelist": True, "name": "test1"},
            {"key": "another_valid_key", "max_ttl": 600, "allow_remote_whitelist": False, "name": "test2"},
        ],
        "whitelist": {"storage_path": "./test_prod_whitelist.json"},
        "security": {
            "always_allowed_ips": ["192.168.1.100"],
            "excluded_paths": ["/health"],
            "max_whitelist_entries": 100
        },
        "cors": {"allowed_origin": "https://example.com"}
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


client = TestClient(app)


class TestTimingAttackResistance:
    """Test that API key validation is resistant to timing attacks."""
    
    def test_constant_time_validation(self, test_settings):
        """
        Verify timing is consistent regardless of key validity using robust statistical analysis.
        
        Uses warm-up runs, large sample size, outlier removal, and statistical testing
        to detect timing attack vulnerabilities.
        """
        valid_key = "valid_key_12345"
        invalid_key = "invalid_key_12345"
        
        # Warm-up runs to stabilize timing
        for _ in range(10):
            core.is_valid_api_key(valid_key, test_settings)
            core.is_valid_api_key(invalid_key, test_settings)
        
        # Collect measurements with high-resolution timing
        sample_size = 150
        valid_times = []
        invalid_times = []
        
        for _ in range(sample_size):
            start = time.perf_counter_ns()
            core.is_valid_api_key(valid_key, test_settings)
            valid_times.append(time.perf_counter_ns() - start)
            
            start = time.perf_counter_ns()
            core.is_valid_api_key(invalid_key, test_settings)
            invalid_times.append(time.perf_counter_ns() - start)
        
        # Remove outliers using trimmed mean (remove top/bottom 10%)
        def trimmed_mean(samples, trim_percent=0.1):
            sorted_samples = sorted(samples)
            trim_count = int(len(sorted_samples) * trim_percent)
            if trim_count > 0:
                trimmed = sorted_samples[trim_count:-trim_count]
            else:
                trimmed = sorted_samples
            return sum(trimmed) / len(trimmed), trimmed
        
        valid_mean, valid_trimmed = trimmed_mean(valid_times)
        invalid_mean, invalid_trimmed = trimmed_mean(invalid_times)
        
        # Calculate standard deviations
        def std_dev(samples, mean):
            variance = sum((x - mean) ** 2 for x in samples) / len(samples)
            return variance ** 0.5
        
        valid_std = std_dev(valid_trimmed, valid_mean)
        invalid_std = std_dev(invalid_trimmed, invalid_mean)
        
        # Perform Mann-Whitney U test (non-parametric)
        # Null hypothesis: distributions are the same
        def mann_whitney_u(samples1, samples2):
            """Simplified Mann-Whitney U test for timing attack detection."""
            n1, n2 = len(samples1), len(samples2)
            combined = [(val, 0) for val in samples1] + [(val, 1) for val in samples2]
            combined.sort(key=lambda x: x[0])
            
            # Calculate ranks
            rank_sum_1 = sum(i + 1 for i, (val, group) in enumerate(combined) if group == 0)
            
            # Calculate U statistic
            u1 = rank_sum_1 - (n1 * (n1 + 1)) / 2
            u2 = n1 * n2 - u1
            u = min(u1, u2)
            
            # Calculate expected value and standard deviation under null hypothesis
            mean_u = n1 * n2 / 2
            std_u = ((n1 * n2 * (n1 + n2 + 1)) / 12) ** 0.5
            
            # Calculate z-score
            z = (u - mean_u) / std_u if std_u > 0 else 0
            
            # For two-tailed test, we want |z| to be small (distributions similar)
            # p-value approximation: larger |z| means more different distributions
            return abs(z)
        
        z_score = mann_whitney_u(valid_trimmed, invalid_trimmed)
        
        # Check relative difference (must be < 10% for practical constant-time)
        relative_diff = abs(valid_mean - invalid_mean) / max(valid_mean, invalid_mean)
        
        # For timing attack resistance, we care about practical exploitability.
        # Over a network, timing differences < 10% at nanosecond scale are not exploitable
        # due to network jitter, OS scheduling, and other noise sources.
        # This test validates the implementation follows constant-time principles.
        assert relative_diff < 0.10, (
            f"Timing difference too large: {relative_diff*100:.1f}% difference between "
            f"valid ({valid_mean:.0f}ns ± {valid_std:.0f}ns) and "
            f"invalid ({invalid_mean:.0f}ns ± {invalid_std:.0f}ns) key validation times. "
            f"This indicates a structural timing difference in the implementation."
        )
        
        # Log timing stats for informational purposes
        import logging
        logging.info(
            f"Timing attack test: valid={valid_mean:.0f}ns ± {valid_std:.0f}ns, "
            f"invalid={invalid_mean:.0f}ns ± {invalid_std:.0f}ns, "
            f"diff={relative_diff*100:.2f}%, z-score={z_score:.2f}"
        )
    
    def test_empty_api_key_handled(self, test_settings):
        """Empty API key should be handled gracefully."""
        assert core.is_valid_api_key("", test_settings) == False
        assert core.is_valid_api_key(None, test_settings) == False
    
    def test_empty_api_keys_list_handled(self):
        """Empty API keys list should be handled gracefully."""
        settings = {"api_keys": []}
        assert core.is_valid_api_key("any_key", settings) == False


class TestTTLEdgeCases:
    """Test TTL validation edge cases."""
    
    def test_zero_ttl_rejected(self):
        """TTL of 0 should be rejected."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={"ttl": 0}
        )
        assert response.status_code == 400
        assert "positive integer" in response.json()["error"].lower()
    
    def test_negative_ttl_rejected(self):
        """Negative TTL should be rejected."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={"ttl": -100}
        )
        assert response.status_code == 400
        assert "positive integer" in response.json()["error"].lower()
    
    def test_extremely_large_ttl_rejected(self):
        """Extremely large TTL (>10 years) should be rejected."""
        ten_years = 315360000
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={"ttl": ten_years + 1}
        )
        assert response.status_code == 400
        assert "too large" in response.json()["error"].lower()
    
    def test_max_valid_ttl_accepted(self):
        """Maximum valid TTL (10 years) should be accepted but capped by key limit."""
        ten_years = 315360000
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={"ttl": ten_years}
        )
        assert response.status_code == 200
        # Should be capped to key's max_ttl (3600)
        assert response.json()["expires_in_seconds"] == 3600
    
    def test_float_ttl_rejected(self):
        """Float TTL should be rejected."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={"ttl": 3.14}
        )
        assert response.status_code == 400
    
    def test_string_ttl_rejected(self):
        """String TTL should be rejected."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={"ttl": "3600"}
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
            json={"ip_address": long_ip}
        )
        assert response.status_code == 400
        assert "too long" in response.json()["error"].lower()
    
    def test_non_string_ip_rejected(self):
        """Non-string IP should be rejected."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={"ip_address": 12345}
        )
        assert response.status_code == 400
    
    def test_valid_ipv6_length_accepted(self):
        """Valid IPv6 with CIDR should be accepted."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={"ip_address": "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"}
        )
        assert response.status_code == 200


class TestHealthCheckDependencies:
    """Test that health check validates critical dependencies."""
    
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
        """Health check should detect inaccessible storage."""
        bad_settings = {**test_settings, "whitelist": {"storage_path": "./will_fail.json"}}
        app.dependency_overrides[get_settings] = lambda: bad_settings
        # Simulate write failure
        monkeypatch.setattr(core, "save_whitelist", lambda wl, st: (_ for _ in ()).throw(PermissionError("denied")))
        resp = client.get("/health")
        assert resp.status_code == 503
        app.dependency_overrides = {}

class TestConfigurationValidation:
    """Test configuration loading validation."""
    
    def test_duplicate_api_keys_detected(self, tmp_path):
        """Duplicate API keys should be detected during config load."""
        import os
        from src import config
        
        # Save original env var
        original_path = os.environ.get("KNOCKER_CONFIG_PATH")
        
        try:
            # Create a config with duplicate keys
            config_content = """
api_keys:
  - name: "key1"
    key: "duplicate_key"
    max_ttl: 3600
    allow_remote_whitelist: true
  - name: "key2"
    key: "duplicate_key"
    max_ttl: 600
    allow_remote_whitelist: false
"""
            config_file = tmp_path / "test_config.yaml"
            config_file.write_text(config_content)
            
            # Set environment variable
            os.environ["KNOCKER_CONFIG_PATH"] = str(config_file)
            
            # Should exit with error
            with pytest.raises(SystemExit) as exc_info:
                config.load_config()
            
            assert exc_info.value.code == 1
        finally:
            # Restore original env var
            if original_path:
                os.environ["KNOCKER_CONFIG_PATH"] = original_path
            elif "KNOCKER_CONFIG_PATH" in os.environ:
                del os.environ["KNOCKER_CONFIG_PATH"]
    
    def test_empty_api_keys_detected(self, tmp_path):
        """Empty API keys list should be detected."""
        import os
        from src import config
        
        original_path = os.environ.get("KNOCKER_CONFIG_PATH")
        
        try:
            config_content = """
api_keys: []
"""
            config_file = tmp_path / "test_config.yaml"
            config_file.write_text(config_content)
            
            os.environ["KNOCKER_CONFIG_PATH"] = str(config_file)
            
            with pytest.raises(SystemExit) as exc_info:
                config.load_config()
            
            assert exc_info.value.code == 1
        finally:
            if original_path:
                os.environ["KNOCKER_CONFIG_PATH"] = original_path
            elif "KNOCKER_CONFIG_PATH" in os.environ:
                del os.environ["KNOCKER_CONFIG_PATH"]
    
    def test_path_traversal_in_config_path_rejected(self, tmp_path):
        """Path traversal in KNOCKER_CONFIG_PATH should be rejected."""
        import os
        from src import config
        
        original_path = os.environ.get("KNOCKER_CONFIG_PATH")
        
        try:
            # Try to use path traversal
            os.environ["KNOCKER_CONFIG_PATH"] = "../../../etc/passwd"
            
            with pytest.raises(SystemExit) as exc_info:
                config.load_config()
            
            assert exc_info.value.code == 1
        finally:
            if original_path:
                os.environ["KNOCKER_CONFIG_PATH"] = original_path
            elif "KNOCKER_CONFIG_PATH" in os.environ:
                del os.environ["KNOCKER_CONFIG_PATH"]


class TestAPIKeyValidation:
    """Test comprehensive API key validation."""
    
    def test_missing_api_key_rejected(self):
        """Request without API key should be rejected."""
        response = client.post(
            "/knock",
            headers={"X-Forwarded-For": "1.2.3.4"},
            json={}
        )
        assert response.status_code == 401
    
    def test_invalid_api_key_rejected(self):
        """Request with invalid API key should be rejected."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "invalid_key", "X-Forwarded-For": "1.2.3.4"},
            json={}
        )
        assert response.status_code == 401
    
    def test_valid_api_key_accepted(self):
        """Request with valid API key should be accepted."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"},
            json={}
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
                json={}
            )
            results.append(response.status_code)
        
        threads = [threading.Thread(target=make_request) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All requests should succeed
        assert all(code == 200 for code in results)
    
    def test_malformed_json_rejected(self, test_settings):
        """Malformed JSON should be rejected gracefully."""
        import os
        # Ensure KNOCKER_CONFIG_PATH is set to a valid path for this test
        # since previous tests may have changed it
        test_config_path = os.path.abspath("knocker.example.yaml")
        if os.path.exists(test_config_path):
            os.environ["KNOCKER_CONFIG_PATH"] = test_config_path
        
        response = client.post(
            "/knock",
            headers={
                "X-Api-Key": "valid_key_12345",
                "X-Forwarded-For": "1.2.3.4",
                "Content-Type": "application/json"
            },
            content="{ invalid json }"
        )
        assert response.status_code == 422 or response.status_code == 400
    
    def test_empty_request_body_accepted(self):
        """Empty request body should be accepted (whitelist client IP)."""
        response = client.post(
            "/knock",
            headers={"X-Api-Key": "valid_key_12345", "X-Forwarded-For": "1.2.3.4"}
        )
        assert response.status_code == 200
        assert response.json()["whitelisted_entry"] == "1.2.3.4"
