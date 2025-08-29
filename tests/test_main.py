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
            {"key": "ADMIN_KEY", "ttl": 3600, "allow_remote_whitelist": True},
            {"key": "USER_KEY_1", "ttl": 600, "allow_remote_whitelist": False},
        ],
        "whitelist": {"storage_path": "./test_whitelist.json"}
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

def test_knock_success_source_ip():
    """A valid key should be able to whitelist its own IP."""
    response = client.post(
        "/knock",
        headers={"X-Api-Key": "USER_KEY_1", "X-Forwarded-For": "1.2.3.4"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["whitelisted_entry"] == "1.2.3.4"
    assert "expires_at" in data

def test_knock_success_remote_ip_with_permission():
    """An admin key should be able to whitelist a remote IP."""
    response = client.post(
        "/knock",
        headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"},
        json={"ip_address": "2001:db8::/64"}
    )
    assert response.status_code == 200
    assert response.json()["whitelisted_entry"] == "2001:db8::/64"

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