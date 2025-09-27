"""
Tests for OpenAPI documentation generation and functionality.
"""
import json
import os
import tempfile
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from main import app, get_settings


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
            "openapi_output_path": "openapi.json"
        }
    }


@pytest.fixture(autouse=True)
def override_settings(mock_settings):
    """Override settings for all tests."""
    app.dependency_overrides[get_settings] = lambda: mock_settings
    yield
    app.dependency_overrides = {}


@pytest.fixture(autouse=True)
def cleanup_test_files():
    """Clean up test files."""
    import os
    files_to_clean = ["./test_whitelist.json", "openapi.json"]
    for file in files_to_clean:
        if os.path.exists(file):
            os.remove(file)
    yield
    for file in files_to_clean:
        if os.path.exists(file):
            os.remove(file)


client = TestClient(app)


def test_openapi_json_endpoint():
    """Test that the OpenAPI JSON endpoint is accessible."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    
    schema = response.json()
    assert schema["openapi"] == "3.1.0"
    assert schema["info"]["title"] == "Knocker API"
    assert schema["info"]["version"] == "1.0.0"
    assert len(schema["paths"]) >= 3  # At least /knock, /health, /verify


def test_swagger_ui_endpoint():
    """Test that Swagger UI is accessible."""
    response = client.get("/docs")
    assert response.status_code == 200
    assert "swagger" in response.text.lower()


def test_redoc_endpoint():
    """Test that ReDoc is accessible."""
    response = client.get("/redoc")
    assert response.status_code == 200
    assert "redoc" in response.text.lower()


def test_openapi_schema_structure():
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


def test_pydantic_models_in_schema():
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


def test_endpoint_tags_and_descriptions():
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


def test_api_tags_configuration():
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


def test_backward_compatibility_with_dict_input():
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


def test_validation_error_conversion():
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