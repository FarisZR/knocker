# Interactive API Documentation

The Knocker service automatically generates interactive API documentation using OpenAPI 3.1 specification. This documentation provides a complete reference for all API endpoints with the ability to test them directly from the browser.

## Accessing the Documentation

Once the service is running, you can access the interactive documentation at:

- **Swagger UI**: `http://your-server:8000/docs`
- **ReDoc**: `http://your-server:8000/redoc`
- **OpenAPI JSON Schema**: `http://your-server:8000/openapi.json`

## Features

### Swagger UI (`/docs`)
- Interactive interface for testing API endpoints
- Built-in request/response examples
- Schema validation and error messages
- Support for API key authentication testing

### ReDoc (`/redoc`) 
- Clean, responsive documentation layout
- Detailed schema documentation
- Code samples in multiple formats
- Three-panel layout for easy navigation

### OpenAPI Schema (`/openapi.json`)
- Complete API specification in JSON format
- Compatible with OpenAPI 3.1 standard
- Can be imported into API development tools
- Automatically generated on service startup

## Configuration

The documentation system can be configured in your `knocker.yaml` file:

```yaml
documentation:
  enabled: true  # Set to false to disable OpenAPI generation
  openapi_output_path: "openapi.json"  # Where to save the generated schema
```

### Disabling Documentation

To disable the interactive documentation (e.g., in production environments):

```yaml
documentation:
  enabled: false
```

This will:
- Disable automatic OpenAPI schema generation
- Remove the `/docs` and `/redoc` endpoints
- Skip writing the OpenAPI file to disk

## Schema Persistence

The service automatically generates and persists the OpenAPI schema to disk on startup. This provides:

- **Offline Access**: Schema available even when service is down
- **CI/CD Integration**: Schema file can be used in automated testing
- **Documentation Archiving**: Track API changes over time
- **Tool Integration**: Import schema into API design tools

The generated file (`openapi.json` by default) is automatically ignored by git to prevent committing generated content.

## API Authentication in Documentation

When testing endpoints that require API keys (like `/knock`):

1. Click the "Authorize" button in Swagger UI
2. Enter your API key in the `X-Api-Key` field
3. Test protected endpoints with proper authentication

Example API keys are defined in `knocker.example.yaml`:
- `CHANGE_ME_SUPER_SECRET_ADMIN_KEY` (admin access)
- `CHANGE_ME_SECRET_PHONE_KEY` (personal access)
- `CHANGE_ME_TEMPORARY_GUEST_KEY` (guest access)

**Security Note**: Change these default keys in production!

## API Endpoints Overview

### Authentication Endpoints
- `POST /knock` - Add IP addresses to whitelist
- `GET /verify` - Verify if IP is authorized
- `OPTIONS /knock` - CORS preflight support

### System Endpoints  
- `GET /health` - Health check and service status

## Request/Response Schemas

All endpoints now include properly typed request and response schemas:

- **Validation**: Automatic input validation with detailed error messages
- **Documentation**: Clear parameter descriptions and examples
- **Type Safety**: Structured data models for reliable API integration

### Example Schemas

**KnockRequest**:
```json
{
  "ip_address": "192.168.1.100",  // Optional, defaults to client IP
  "ttl": 3600                     // Optional, capped by API key limits
}
```

**KnockResponse**:
```json
{
  "whitelisted_entry": "192.168.1.100",
  "expires_at": 1640995200,
  "expires_in_seconds": 3600
}
```

## Integration Examples

### Using with curl
```bash
# Test the knock endpoint
curl -X POST "http://localhost:8000/knock" \
  -H "X-Api-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.100", "ttl": 3600}'
```

### Using with Python requests
```python
import requests

response = requests.post(
    "http://localhost:8000/knock",
    headers={"X-Api-Key": "your-api-key"},
    json={"ip_address": "192.168.1.100", "ttl": 3600}
)
data = response.json()
print(f"Whitelisted until: {data['expires_at']}")
```

## Development

When running in development mode (using `dev/docker-compose.yml`), the documentation is accessible through the Caddy reverse proxy, providing the same experience as production deployment.

The generated OpenAPI schema reflects the exact API configuration including:
- Configured CORS origins
- Available API keys and their permissions  
- All security settings and validation rules
- Complete request/response examples