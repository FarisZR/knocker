# Caddy Knocker

Caddy Knocker is a secure, configurable, and self-hosted service that provides a "knock-knock" single-packet authorization (SPA) gateway for your Caddy v2 reverse proxy. It allows you to keep your services completely private, opening them up on-demand only for authorized IP addresses.

This is ideal for homelab environments where you want to expose services to the internet without a persistent VPN connection, while minimizing your public-facing attack surface.

 <!-- Placeholder for diagram -->

## Features

*   **API Key Authentication**: Secure your knock endpoint with multiple, configurable API keys.
*   **Configurable TTL**: Each API key can have its own Time-To-Live (TTL), defining how long a whitelisted IP remains active.
*   **Remote Whitelisting**: Grant specific admin keys permission to whitelist any IP or CIDR range, not just their own.
*   **IPv6 First-Class Citizen**: Full support for IPv6 and IPv4 in whitelisting, trusted proxies, and Docker networking.
*   **Secure by Default**: Built-in protection against IP spoofing via a trusted proxy mechanism.
*   **Test-Driven Development**: A comprehensive test suite ensures code correctness and reliability.

## Deployment

This project is designed to be deployed as a set of Docker containers using the provided `docker-compose.yml` file.

For a formal API specification and a summary of the architectural choices, please see:

*   [**API Specification**](./API_SPEC.md)
*   [**Design Decisions**](./DESIGN_DECISIONS.md)

### 1. Prerequisites
    *   Docker and Docker Compose installed.
    *   A public-facing server to run the containers.

2.  **Configuration**:
    *   Rename `knocker.example.yaml` to `knocker.yaml`.
    *   **Crucially, change the default API keys** in `knocker.yaml` to your own secure, random strings.
    *   Review the `trusted_proxies` list in `knocker.yaml`. The defaults are suitable for most Docker setups, but you should verify they match your Docker network's subnets if you have a custom configuration.
    *   Create a `Caddyfile` in the `knocker` directory. See the "Caddy Integration" section below for examples.

3.  **Run the Service**:
    ```bash
    docker-compose up -d
    ```
    This will build the `knocker` image and start both the `knocker` and `caddy` services.

## Configuration (`knocker.yaml`)

The service is configured entirely through the `knocker.yaml` file.

*   **`server`**:
    *   `host` & `port`: The address the internal server listens on. Should generally be left as is.
    *   `trusted_proxies`: A list of IPs or CIDR ranges. The service will only trust the `X-Forwarded-For` header from these addresses. **This is a critical security setting.**

*   **`whitelist`**:
    *   `storage_path`: The location inside the container where the `whitelist.json` file is stored. This is mounted to a Docker volume for persistence.

*   **`api_keys`**:
    *   A list of key objects.
    *   `name`: A friendly name for the key.
    *   `key`: The secret API key string.
    *   `ttl`: The duration in seconds that an IP will be whitelisted for.
    *   `allow_remote_whitelist`: A boolean (`true` or `false`). If `true`, this key can be used to whitelist any IP/CIDR passed in the request body. If `false`, it can only whitelist the IP of the device making the request.

## Caddy Integration

To protect your services, you will use Caddy's `forward_auth` directive.

1.  **Define a Reusable Snippet**: It's best practice to define a snippet in your `Caddyfile` for the auth check.

2.  **Protect Your Services**: Import the snippet for any service you want to protect.

**Example `Caddyfile`**:

```caddyfile
# Caddyfile

# Define a reusable snippet for the knock-knock check.
# It points to the knocker service using Docker's internal DNS.
(knocker_auth) {
  forward_auth knocker:8000 {
    uri /check
    copy_headers X-Forwarded-For
  }
}

# The public endpoint for performing the knock.
# Make sure this domain points to your Caddy server's IP.
knock.your-domain.com {
  reverse_proxy knocker:8000
}

# An example protected service.
jellyfin.your-domain.com {
  import knocker_auth  # Apply the forward_auth check
  reverse_proxy jellyfin_service_name:8096
}
```

### Handling Authorization Failures

You can control what happens when a user is not whitelisted using Caddy's `handle_errors` directive.

*   **Option 1: Default (Return HTTP 401)**
    *   No extra configuration needed. Caddy will return a blank `401 Unauthorized` page.

*   **Option 2: Serve a Custom Error Page**
    ```caddyfile
    jellyfin.your-domain.com {
      import knocker_auth
      reverse_proxy jellyfin_service_name:8096

      handle_errors {
        if {http.error.status_code} == 401 {
          rewrite * /unauthorized.html
          file_server {
            root /path/to/your/error/pages
          }
        }
      }
    }
    ```

*   **Option 3: Redirect to an Info Page**
    ```caddyfile
    jellyfin.your-domain.com {
      import knocker_auth
      reverse_proxy jellyfin_service_name:8096

      handle_errors {
        if {http.error.status_code} == 401 {
          respond "You are not authorized. Please see the guide." 302 {
            header Location https://your-guide-url.com
          }
        }
      }
    }
    ```

## API Usage

### `/knock` (POST)

This endpoint validates an API key and whitelists an IP.

*   **Headers**:
    *   `X-Api-Key`: Your secret API key.

*   **Body (Optional)**:
    *   To whitelist a remote IP/CIDR (requires `allow_remote_whitelist: true`):
        ```json
        {"ip_address": "YOUR_TARGET_IP_OR_CIDR"}
        ```

*   **Example (Whitelisting your own IP)**:
    ```bash
    curl -i -H "X-Api-Key: YOUR_SECRET_KEY" https://knock.your-domain.com/knock
    ```

*   **Success Response (`200 OK`)**:
    ```json
    {
      "whitelisted_entry": "1.2.3.4",
      "expires_at": 1672534800,
      "expires_in_seconds": 3600
    }
    ```

### `/check` (GET)

This endpoint is used by Caddy's `forward_auth` to check if the client's IP is whitelisted. It returns `200 OK` on success and `401 Unauthorized` on failure.

## Running Tests

The project includes a full test suite. To run the tests locally:

1.  **Install Dependencies**:
    ```bash
    pip install -r src/requirements.txt
    ```

2.  **Run Pytest**:
    ```bash
    python3 -m pytest