import pytest
from fastapi.testclient import TestClient
from src.main import app, get_settings

# --- Test Fixtures ---

@pytest.fixture
def mock_settings():
    """Provides a standard settings object for API tests."""
    return {
        "server": {
            "trusted_proxies": ["127.0.0.1"]
        },
        "api_keys": [
            {"key": "ADMIN_KEY", "max_ttl": 3600, "allow_remote_whitelist": True},
            {"key": "USER_KEY_1", "max_ttl": 600, "allow_remote_whitelist": False},
        ],
        "whitelist": {"storage_path": "./test_whitelist.json"},
        "security": {
            "always_allowed_ips": ["100.100.100.100", "2001:db8:cafe::/48"],
            "excluded_paths": ["/healthz", "/api/v1/public"]
        },
        "cors": {
            "allowed_origin": "*"
        }
    }

@pytest.fixture(autouse=True)
def override_settings(mock_settings):
    """
    This fixture runs for every test. It overrides the get_settings dependency
    with our mock_settings, ensuring tests are isolated and predictable.
    """
    app.dependency_overrides[get_settings] = lambda: mock_settings
    yield
    # Clean up the override after the test is done
    app.dependency_overrides = {}

@pytest.fixture(autouse=True)
def cleanup_whitelist(mock_settings):
    """Ensure the test whitelist is clean before and after each test."""
    import os
    path = mock_settings["whitelist"]["storage_path"]
    if os.path.exists(path):
        os.remove(path)
    yield
    if os.path.exists(path):
        os.remove(path)

client = TestClient(app)

# --- Test /knock Endpoint ---

def test_knock_success_source_ip_uses_default_ttl():
    """A valid key should be able to whitelist its own IP and use the default max_ttl."""
    response = client.post(
        "/knock",
        headers={"X-Api-Key": "USER_KEY_1", "X-Forwarded-For": "1.2.3.4"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["whitelisted_entry"] == "1.2.3.4"
    assert data["expires_in_seconds"] == 600

def test_knock_success_remote_ip_with_permission():
    """An admin key should be able to whitelist a remote IP."""
    response = client.post(
        "/knock",
        headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"},
        json={"ip_address": "2001:db8::/120"}
    )
    assert response.status_code == 200
    assert response.json()["whitelisted_entry"] == "2001:db8::/120"

def test_knock_fail_remote_ip_without_permission():
    """A standard user key should NOT be able to whitelist a remote IP."""
    response = client.post(
        "/knock",
        headers={"X-Api-Key": "USER_KEY_1", "X-Forwarded-For": "1.2.3.4"},
        json={"ip_address": "8.8.8.8"}
    )
    assert response.status_code == 403

def test_knock_fail_invalid_api_key():
    """A request with a bad API key should be rejected."""
    response = client.post("/knock", headers={"X-Api-Key": "INVALID_KEY", "X-Forwarded-For": "1.2.3.4"})
    assert response.status_code == 401

def test_knock_fail_invalid_ip_in_body():
    """A request with a malformed IP in the body should be rejected."""
    response = client.post(
        "/knock",
        headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"},
        json={"ip_address": "not-an-ip"}
    )
    assert response.status_code == 400

def test_knock_with_custom_valid_ttl():
    """A knock with a custom TTL lower than the max should be accepted."""
    response = client.post(
        "/knock",
        headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"},
        json={"ttl": 300}
    )
    assert response.status_code == 200
    assert response.json()["expires_in_seconds"] == 300

def test_knock_with_custom_ttl_exceeding_max():
    """A knock with a custom TTL higher than the max should be capped at the max."""
    response = client.post(
        "/knock",
        headers={"X-Api-Key": "USER_KEY_1", "X-Forwarded-For": "1.2.3.4"},
        json={"ttl": 9999}
    )
    assert response.status_code == 200
    assert response.json()["expires_in_seconds"] == 600 # Capped at the key's max_ttl

def test_knock_with_invalid_ttl_negative():
    """A knock with a negative TTL should be rejected."""
    response = client.post(
        "/knock",
        headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"},
        json={"ttl": -100}
    )
    assert response.status_code == 400

def test_knock_with_invalid_ttl_string():
    """A knock with a non-integer TTL should be rejected."""
    response = client.post(
        "/knock",
        headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"},
        json={"ttl": "three hundred"}
    )
    assert response.status_code == 400

def test_knock_options_cors():
    """OPTIONS request to /knock should return 204 with CORS headers."""
    response = client.options("/knock")
    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert response.headers["Access-Control-Allow-Methods"] == "POST, OPTIONS"
    assert response.headers["Access-Control-Allow-Headers"] == "X-Api-Key, Content-Type"

def test_knock_post_cors_header():
    """POST /knock should include Access-Control-Allow-Origin header."""
    response = client.post(
        "/knock",
        headers={"X-Api-Key": "USER_KEY_1", "X-Forwarded-For": "1.2.3.4"}
    )
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "*"

# --- Test /verify Endpoint ---

def test_verify_success_whitelisted_ip():
    """A whitelisted IP should pass the /verify endpoint."""
    # First, knock to whitelist the IP
    client.post("/knock", headers={"X-Api-Key": "USER_KEY_1", "X-Forwarded-For": "5.6.7.8"})
    
    # Then, verify it
    response = client.get("/verify", headers={"X-Forwarded-For": "5.6.7.8"})
    assert response.status_code == 200

def test_verify_fail_non_whitelisted_ip():
    """A non-whitelisted IP should fail the /verify endpoint."""
    response = client.get("/verify", headers={"X-Forwarded-For": "9.10.11.12"})
    assert response.status_code == 401

def test_verify_success_always_allowed_ip():
    """An IP in the always-allowed list should pass /verify without a knock."""
    response = client.get("/verify", headers={"X-Forwarded-For": "100.100.100.100"})
    assert response.status_code == 200

def test_verify_success_always_allowed_cidr():
    """An IP within an always-allowed CIDR should pass /verify."""
    response = client.get("/verify", headers={"X-Forwarded-For": "2001:db8:cafe:1234::1"})
    assert response.status_code == 200

def test_verify_success_excluded_path():
    """A request to an excluded path should pass /verify regardless of IP."""
    response = client.get("/verify", headers={"X-Forwarded-For": "9.9.9.9", "X-Forwarded-Uri": "/healthz"})
    assert response.status_code == 200

def test_verify_success_excluded_path_prefix():
    """A request to a path that starts with an excluded prefix should pass."""
    response = client.get("/verify", headers={"X-Forwarded-For": "9.9.9.9", "X-Forwarded-Uri": "/api/v1/public/status"})
    assert response.status_code == 200