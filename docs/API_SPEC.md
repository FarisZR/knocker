# Caddy Knocker API Specification

This document provides a formal specification for the Caddy Knocker API.

## Endpoints

### 1. Knock

This endpoint is used to authenticate and whitelist an IP address or CIDR network.

*   **URL**: `/knock`
*   **Method**: `POST`, `OPTIONS`
*   **Headers**:
    *   `X-Api-Key` (string, **required** for POST): The secret API key for authentication.
    *   `X-Forwarded-For` (string, **required** for POST): The client's real IP address. This is expected to be set by a trusted proxy like Caddy.
*   **Request Body** (optional, JSON):
    ```json
    {
      "ip_address": "string",
      "ttl": "integer"
    }
    ```
    *   `ip_address` (string): The IPv4/IPv6 address or CIDR network to whitelist. If provided, the API key must have `allow_remote_whitelist: true` permission.
    *   `ttl` (integer, optional): The desired time-to-live for the whitelist entry in seconds. If not provided, the key's default `max_ttl` will be used. If the provided TTL exceeds the key's `max_ttl`, the `max_ttl` will be used instead.

#### Responses

*   **`200 OK`** (Success)
    *   Returned when the knock is successful.
    *   **Headers**:
        *   `Access-Control-Allow-Origin`: The configured allowed origin (or "*" for any).
    *   **Body**:
        ```json
        {
          "whitelisted_entry": "string",
          "expires_at": "integer",
          "expires_in_seconds": "integer"
        }
        ```
        *   `whitelisted_entry`: The IP or CIDR that was added to the whitelist.
        *   `expires_at`: The Unix timestamp when the whitelist entry will expire.
        *   `expires_in_seconds`: The actual TTL (Time To Live) of the whitelist entry in seconds. This may be the value requested by the client or the capped maximum TTL allowed by the API key.

*   **`204 No Content`** (OPTIONS)
    *   Returned for CORS preflight OPTIONS requests.
    *   **Headers**:
        *   `Access-Control-Allow-Origin`: The configured allowed origin (or "*" for any).
        *   `Access-Control-Allow-Methods`: "POST, OPTIONS"
        *   `Access-Control-Allow-Headers`: "X-Api-Key, Content-Type"

*   **`400 Bad Request`**
    *   Returned if the client IP cannot be determined or if the `ip_address` in the request body is malformed.
    *   **Body**: `{"error": "string"}`

*   **`401 Unauthorized`**
    *   Returned if the `X-Api-Key` is missing or invalid.
    *   **Body**: `{"error": "string"}`

*   **`403 Forbidden`**
    *   Returned if an API key without `allow_remote_whitelist` permission attempts to whitelist a specific `ip_address`.
    *   **Body**: `{"error": "string"}`

---

### 2. Verify

This endpoint is used by Caddy's `forward_auth` directive to verify if a client's IP is currently whitelisted.

*   **URL**: `/verify`
*   **Method**: `GET`
*   **Headers**:
    *   `X-Forwarded-For` (string, **required**): The client's real IP address, set by the proxy.

#### Responses

*   **`200 OK`** (Success)
    *   Returned if the client's IP is found in an active (non-expired) whitelist entry, is in the `always_allowed_ips` list, or if the request path is in the `excluded_paths` list. The response has an empty body.

*   **`401 Unauthorized`**
    *   Returned if the client's IP is not authorized. The response has an empty body.
    *   **Note**: When using Caddy's `forward_auth` directive, this response bypasses Caddy's `handle_errors` directive. Custom error handling for unauthorized access must be implemented either in this service or through alternative Caddy configurations.

---

### 3. Health Check

This endpoint is used to verify the operational status of the Knocker service.

*   **URL**: `/health`
*   **Method**: `GET`

#### Responses

*   **`200 OK`** (Success)
    *   Returned if the service is running correctly.
    *   **Body**:
        ```json
        {
          "status": "ok"
        }
        ```

## Configuration (`knocker.yaml`)

- **`server`** (object, required): Server settings.
    - **`host`** (string, required): The host to bind to.
    - **`port`** (integer, required): The port to listen on.
    - **`trusted_proxies`** (array of strings, required): A list of trusted proxy IPs/CIDRs.
- **`whitelist`** (object, required): Whitelist settings.
    - **`storage_path`** (string, required): Path to the whitelist JSON file.
- **`api_keys`** (array of objects, required): A list of API key configurations.
    - **`name`** (string, required): A friendly name for the key.
    - **`key`** (string, required): The secret API key.
    - **`max_ttl`** (integer, required): The maximum time-to-live for whitelisted IPs in seconds.
    - **`allow_remote_whitelist`** (boolean, required): If `true`, the key can whitelist any IP/CIDR. If `false`, it can only whitelist the source IP of the request.
- **`security`** (object, optional): Security-related settings.
    - **`always_allowed_ips`** (array of strings, optional): A list of IPs or CIDR ranges that are always permitted by the `/verify` endpoint, bypassing the dynamic whitelist.
    - **`excluded_paths`** (array of strings, optional): A list of URL paths (e.g., `/api/health`) that are exempt from any IP-based authentication at the `/verify` endpoint.
- **`cors`** (object, optional): CORS settings for the `/knock` endpoint.
    - **`allowed_origin`** (string, optional): The allowed origin for CORS requests. Defaults to "*" (any origin). Set to your web app's origin (e.g., "https://your-web-app.com") for security.