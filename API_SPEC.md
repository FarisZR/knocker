# Caddy Knocker API Specification

This document provides a formal specification for the Caddy Knocker API.

## Endpoints

### 1. Knock

This endpoint is used to authenticate and whitelist an IP address or CIDR network.

*   **URL**: `/knock`
*   **Method**: `POST`
*   **Headers**:
    *   `X-Api-Key` (string, **required**): The secret API key for authentication.
    *   `X-Forwarded-For` (string, **required**): The client's real IP address. This is expected to be set by a trusted proxy like Caddy.
*   **Request Body** (optional, JSON):
    *   To whitelist a specific IP or CIDR, the key must have `allow_remote_whitelist: true` permission.
    ```json
    {
      "ip_address": "string"
    }
    ```
    *   `ip_address` (string): The IPv4/IPv6 address or CIDR network to whitelist.

#### Responses

*   **`200 OK`** (Success)
    *   Returned when the knock is successful.
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
        *   `expires_in_seconds`: The TTL (Time To Live) of the whitelist entry in seconds.

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

### 2. Check

This endpoint is used by Caddy's `forward_auth` directive to verify if a client's IP is currently whitelisted.

*   **URL**: `/check`
*   **Method**: `GET`
*   **Headers**:
    *   `X-Forwarded-For` (string, **required**): The client's real IP address, set by the proxy.

#### Responses

*   **`200 OK`** (Success)
    *   Returned if the client's IP is found in an active (non-expired) whitelist entry. The response has an empty body.

*   **`401 Unauthorized`**
    *   Returned if the client's IP is not found in the whitelist or if its entry has expired. The response has an empty body.