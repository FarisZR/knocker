"""
Tests for OpenAPI documentation generation and functionality.
"""
import asyncio
import copy
import json
import os
import tempfile
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from main import app, get_settings, generate_and_persist_openapi


def configure_app_with_settings(settings: dict):
    """Apply settings to the FastAPI app and regenerate documentation."""
    settings_copy = copy.deepcopy(settings)
    app.dependency_overrides[get_settings] = lambda: settings_copy
    asyncio.run(generate_and_persist_openapi(app, copy.deepcopy(settings_copy)))
    return settings_copy


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
        },
        "documentation": {
            "enabled": True,
            "openapi_output_path": "test_openapi.json"
        }
    }


@pytest.fixture(autouse=True)
def override_settings(mock_settings):
    """Override settings for all tests."""
    settings_copy = configure_app_with_settings(mock_settings)
    yield
    app.dependency_overrides = {}
    cleanup_settings = {
        "documentation": {
            "enabled": False,
            "openapi_output_path": settings_copy.get("documentation", {}).get("openapi_output_path", "openapi.json")
        }
    }
    asyncio.run(generate_and_persist_openapi(app, copy.deepcopy(cleanup_settings)))


@pytest.fixture(autouse=True)
def cleanup_test_files():
    """Clean up test files."""
    import os
    files_to_clean = ["./test_whitelist.json", "openapi.json", "test_openapi.json"]
    for file in files_to_clean:
        if os.path.exists(file):
            os.remove(file)
    yield
    for file in files_to_clean:
        if os.path.exists(file):
            os.remove(file)


@pytest.fixture
def client():
    """Create a test client for each test."""
    return TestClient(app)


def test_openapi_json_endpoint(client):
    """Test that the OpenAPI JSON endpoint is accessible."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    
    schema = response.json()
    assert schema["openapi"] == "3.1.0"
    assert schema["info"]["title"] == "Knocker API"
    assert schema["info"]["version"] == "1.0.0"
    assert len(schema["paths"]) >= 3  # At least /knock, /health, /verify


def test_swagger_ui_endpoint(client):
    """Test that Swagger UI is accessible."""
    response = client.get("/docs")
    assert response.status_code == 200
    assert "swagger" in response.text.lower()


def test_redoc_endpoint(client):
    """Test that ReDoc is accessible."""
    response = client.get("/redoc")
    assert response.status_code == 200
    assert "redoc" in response.text.lower()


def test_openapi_schema_structure(client):
    """Test that the OpenAPI schema has proper structure."""
    response = client.get("/openapi.json")
    schema = response.json()
    
    # Check basic structure
    assert "paths" in schema
    assert "components" in schema
    assert "info" in schema
    
    # Check endpoint paths
    paths = schema["paths"]
    assert "/knock" in paths
    assert "/health" in paths
    assert "/verify" in paths
    
    # Check that POST /knock has proper structure
    knock_post = paths["/knock"]["post"]
    assert "tags" in knock_post
    assert "Authentication" in knock_post["tags"]
    assert "summary" in knock_post
    assert "description" in knock_post
    assert "responses" in knock_post
    
    # Check response schemas
    responses = knock_post["responses"]
    assert "200" in responses
    assert "400" in responses
    assert "401" in responses
    assert "403" in responses
    assert "500" in responses


def test_pydantic_models_in_schema(client):
    """Test that Pydantic models are properly included in schema."""
    response = client.get("/openapi.json")
    schema = response.json()
    
    components = schema.get("components", {})
    schemas = components.get("schemas", {})
    
    # Check that our custom models are present
    assert "KnockRequest" in schemas
    assert "KnockResponse" in schemas
    assert "HealthResponse" in schemas
    assert "ErrorResponse" in schemas
    
    # Check KnockRequest structure
    knock_request = schemas["KnockRequest"]
    assert "properties" in knock_request
    properties = knock_request["properties"]
    assert "ip_address" in properties
    assert "ttl" in properties
    
    # Check KnockResponse structure
    knock_response = schemas["KnockResponse"]
    assert "properties" in knock_response
    properties = knock_response["properties"]
    assert "whitelisted_entry" in properties
    assert "expires_at" in properties
    assert "expires_in_seconds" in properties


def test_endpoint_tags_and_descriptions(client):
    """Test that endpoints have proper tags and descriptions."""
    response = client.get("/openapi.json")
    schema = response.json()
    
    paths = schema["paths"]
    
    # Test /knock POST endpoint
    knock_post = paths["/knock"]["post"]
    assert knock_post["tags"] == ["Authentication"]
    assert "Whitelist IP Address" in knock_post["summary"]
    assert "API key" in knock_post["description"]
    
    # Test /health endpoint
    health_get = paths["/health"]["get"]
    assert health_get["tags"] == ["System"]
    assert "Health Check" in health_get["summary"]
    
    # Test /verify endpoint
    verify_get = paths["/verify"]["get"]
    assert verify_get["tags"] == ["Authentication"]
    assert "Verify IP Authorization" in verify_get["summary"]


def test_api_tags_configuration(client):
    """Test that OpenAPI tags are properly configured."""
    response = client.get("/openapi.json")
    schema = response.json()
    
    tags = schema.get("tags", [])
    tag_names = [tag["name"] for tag in tags]
    
    assert "Authentication" in tag_names
    assert "System" in tag_names
    
    # Check tag descriptions
    auth_tag = next(tag for tag in tags if tag["name"] == "Authentication")
    assert "whitelisting" in auth_tag["description"].lower()
    
    system_tag = next(tag for tag in tags if tag["name"] == "System")  
    assert "health" in system_tag["description"].lower()


def test_backward_compatibility_with_dict_input(client):
    """Test that endpoints still accept dict input for backward compatibility."""
    # Test with dictionary input (old format)
    response = client.post(
        "/knock",
        headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"},
        json={"ip_address": "192.168.1.100", "ttl": 3600}
    )
    assert response.status_code == 200
    
    data = response.json()
    assert "whitelisted_entry" in data
    assert "expires_at" in data
    assert "expires_in_seconds" in data


def test_validation_error_conversion(client):
    """Test that Pydantic validation errors are converted to 400 status codes."""
    # Test invalid TTL (should be converted from 422 to 400)
    response = client.post(
        "/knock",
        headers={"X-Api-Key": "ADMIN_KEY", "X-Forwarded-For": "1.2.3.4"},
        json={"ttl": -100}
    )
    assert response.status_code == 400
    
    data = response.json()
    assert "error" in data
    assert "TTL" in data["error"]


def test_documentation_endpoints_available_when_enabled(client):
    """Test that documentation endpoints are available when documentation is enabled."""
    # The default mock_settings has documentation.enabled = True
    
    # Test that documentation endpoints work
    docs_response = client.get("/docs")
    redoc_response = client.get("/redoc") 
    openapi_response = client.get("/openapi.json")
    
    # All should work when documentation is enabled
    assert docs_response.status_code == 200
    assert redoc_response.status_code == 200
    assert openapi_response.status_code == 200
    
    # Verify content types are appropriate
    assert "text/html" in docs_response.headers.get("content-type", "")
    assert "text/html" in redoc_response.headers.get("content-type", "")
    assert "application/json" in openapi_response.headers.get("content-type", "")


def test_app_configuration_honors_documentation_settings(tmp_path):
    """Test that the app correctly applies documentation settings."""
    schema_path = tmp_path / "config_openapi.json"
    
    enabled_settings = {
        "documentation": {"enabled": True, "openapi_output_path": str(schema_path)}
    }
    asyncio.run(generate_and_persist_openapi(app, enabled_settings))
    
    assert app.docs_url == "/docs"
    assert app.redoc_url == "/redoc"
    assert app.openapi_url == "/openapi.json"
    assert schema_path.exists()
    
    disabled_settings = {
        "documentation": {"enabled": False, "openapi_output_path": str(schema_path)}
    }
    asyncio.run(generate_and_persist_openapi(app, disabled_settings))
    
    assert app.docs_url is None
    assert app.redoc_url is None
    assert app.openapi_url is None


def test_documentation_disabled_removes_endpoints_and_schema(tmp_path, mock_settings):
    """Documentation disabled removes routes and deletes persisted schema."""
    schema_path = tmp_path / "disabled_openapi.json"
    schema_path.write_text("{}")
    
    disabled_settings = copy.deepcopy(mock_settings)
    disabled_settings["documentation"]["enabled"] = False
    disabled_settings["documentation"]["openapi_output_path"] = str(schema_path)
    
    configure_app_with_settings(disabled_settings)
    local_client = TestClient(app)
    
    assert local_client.get("/docs").status_code == 404
    assert local_client.get("/redoc").status_code == 404
    assert local_client.get("/openapi.json").status_code == 404
    assert not schema_path.exists()


def test_documentation_defaults_to_disabled_when_missing(mock_settings):
    """Missing documentation config defaults to disabled behaviour."""
    default_schema_path = Path("openapi.json")
    default_schema_path.write_text("{}")
    
    missing_settings = copy.deepcopy(mock_settings)
    missing_settings.pop("documentation", None)
    
    configure_app_with_settings(missing_settings)
    local_client = TestClient(app)
    
    assert local_client.get("/docs").status_code == 404
    assert local_client.get("/redoc").status_code == 404
    assert local_client.get("/openapi.json").status_code == 404
    assert not default_schema_path.exists()


def test_documentation_can_be_reenabled_after_disable(tmp_path, mock_settings):
    """Disabling, then re-enabling documentation restores routes and schema."""
    schema_path = tmp_path / "reenabled_openapi.json"
    
    disabled_settings = copy.deepcopy(mock_settings)
    disabled_settings["documentation"]["enabled"] = False
    disabled_settings["documentation"]["openapi_output_path"] = str(schema_path)
    configure_app_with_settings(disabled_settings)
    disabled_client = TestClient(app)
    
    assert disabled_client.get("/docs").status_code == 404
    assert not schema_path.exists()
    
    enabled_settings = copy.deepcopy(mock_settings)
    enabled_settings["documentation"]["openapi_output_path"] = str(schema_path)
    configure_app_with_settings(enabled_settings)
    enabled_client = TestClient(app)
    
    assert enabled_client.get("/docs").status_code == 200
    assert enabled_client.get("/redoc").status_code == 200
    assert enabled_client.get("/openapi.json").status_code == 200
    assert schema_path.exists()

    # Disable again to verify removal after re-enable cycle
    configure_app_with_settings(disabled_settings)
    re_disabled_client = TestClient(app)

    assert re_disabled_client.get("/docs").status_code == 404
    assert not schema_path.exists()