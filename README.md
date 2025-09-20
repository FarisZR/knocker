# Knocker

Knocker is a secure, configurable, and self-hosted service that provides a "knock-knock" single-packet authorization (SPA) gateway for your Caddy v2 reverse proxy. It allows you to keep your services completely private, opening them up on-demand only for authorized IP addresses.

This is ideal for homelab environments where you want to expose services to the internet without a persistent VPN connection, while minimizing your public-facing attack surface.

 <!-- Placeholder for diagram -->

## Features

*   **API Key Authentication**: Secure your knock endpoint with multiple, configurable API keys.
*   **Configurable TTL**: Each API key can have its own Time-To-Live (TTL), defining how long a whitelisted IP remains active.
*   **Remote Whitelisting**: Grant specific admin keys permission to whitelist any IP or CIDR range, not just their own.
*   **Static IP/CIDR Whitelisting**: Always allow certain IP addresses or ranges to bypass the dynamic whitelist.
*   **Path-Based Exclusion**: Exclude specific URL paths (like health checks or public APIs) from authentication entirely.
*   **IPv6 First-Class Citizen**: Full support for IPv6 and IPv4 in whitelisting, trusted proxies, and Docker networking.
*   **Secure by Default**: Built-in protection against IP spoofing via a trusted proxy mechanism.
*   **Test-Driven Development**: A comprehensive test suite ensures code correctness and reliability.
*   **Firewalld Integration**: Advanced firewall control with timed rules that automatically expire based on TTL. Creates dynamic firewall rules using firewalld rich rules for enhanced security. (Optional, requires root container access)

## CI/CD

This project uses GitHub Actions for continuous integration and deployment.

*   **CI (`ci.yml`)**: On every pull request to `main`, this workflow runs the full Python test suite and then performs a live integration test with Docker Compose to ensure the Caddy and Knocker services work together correctly.
*   **Docker Publish (`docker-publish.yml`)**: On every push to `main`, this workflow builds and publishes a multi-arch Docker image to the GitHub Container Registry (ghcr.io).

## Deployment

This project is designed to be deployed as a set of Docker containers using the provided `docker-compose.yml` file. It uses the pre-built image from the GitHub Container Registry.

For a formal API specification and a summary of the architectural choices, please see:

*   [**API Specification**](./docs/API_SPEC.md)
*   [**Design Decisions**](./docs/DESIGN_DECISIONS.md)  
*   [**Firewalld Integration**](./docs/FIREWALLD_INTEGRATION.md) - Advanced firewall control with timed rules

### 1. Prerequisites
    *   Docker and Docker Compose installed.
    *   A public-facing server to run the containers.
    *   (Optional) Firewalld installed and running on the host for advanced firewall integration.

2.  **Configuration**:
    *   Rename `knocker.example.yaml` to `knocker.yaml`.
    *   **Crucially, change the default API keys** in `knocker.yaml` to your own secure, random strings.
    *   Review the `trusted_proxies` list in `knocker.yaml`. The defaults are suitable for most Docker setups, but you should verify they match your Docker network's subnets if you have a custom configuration.
    *   (Optional) Configure firewalld integration by setting `firewalld.enabled: true` and adjusting the related settings. **Note**: This requires the container to run as root.
    *   Create a `Caddyfile` in the `knocker` directory. See the "Caddy Integration" section below for examples.

3.  **Update `docker-compose.yml`**:
    *   Open the `docker-compose.yml` file.
    *   Change the `image` line for the `knocker` service to point to your own GitHub repository:
        ```yaml
        image: ghcr.io/YOUR_GITHUB_USERNAME/YOUR_REPOSITORY_NAME:latest
        ```

4.  **Run the Service**:
    ```bash
    docker compose up -d
    ```
    This will pull the pre-built `knocker` image and start both the `knocker` and `caddy` services.

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

*   **`security`**:
    *   `always_allowed_ips`: A list of IPv4 or IPv6 addresses or CIDR ranges that will always be allowed to pass the `/verify` endpoint, regardless of whether they are in the dynamic whitelist. This is useful for permanently allowing access to trusted IPs, such as the IP of a reverse proxy or an admin workstation.
      ```yaml
      security:
        always_allowed_ips:
          - "1.2.3.4"
          - "192.168.1.0/24"
          - "2001:db8::/32"
      ```
    *   `excluded_paths`: A list of URL paths that will bypass the IP whitelist check entirely. Any request whose path starts with one of these values will be allowed. This is useful for exposing health check endpoints or public API routes.
      ```yaml
      security:
        excluded_paths:
          - "/api/v1/status"
          - "/metrics"
      ```

*   **`firewalld`** (Optional):
    *   `enabled`: Set to `true` to enable firewalld integration for advanced firewall control
    *   `zone_name`: Name of the firewalld zone to create (default: "knocker")
    *   `zone_priority`: Zone priority, higher numbers have more priority (default: 100)
    *   `monitored_ports`: List of ports to protect with firewall rules
    *   `monitored_ips`: IP ranges the firewalld zone will apply to
    *   **Note**: Requires container to run as root with system dbus access. See [Firewalld Integration](docs/FIREWALLD_INTEGRATION.md) for detailed setup.

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
    uri /verify
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
### Userland-proxy related issues

If you are enabling knocking for IPs behind tailscale or other IPs, you may face issues due to how userland-proxy works, you may get different request IP from the actual ip address.

Disabling Userland-proxy should fix it, but make sure to test your setup.
You may also use host networking.

### Authorization Failures

When a user is not whitelisted, Caddy's `forward_auth` directive will return a `401 Unauthorized` response with an empty body. 

**Important Note**: Caddy's `handle_errors` directive does **not** work with `forward_auth` responses. The error response comes directly from the authentication service (knocker), not from Caddy itself, so `handle_errors` cannot intercept or modify these responses.

If you need custom error pages for unauthorized access, you have a few alternatives:

*   **Modify the knocker service**: Update the `/verify` endpoint to return custom HTML content in 401 responses (requires code changes).
*   **Use a different approach**: Instead of `forward_auth`, you could implement authorization at the application level.
*   **Accept the default**: Use the standard 401 response for unauthorized access.

**Example of the standard behavior**:
```caddyfile
jellyfin.your-domain.com {
  import knocker_auth  # This will return empty 401 responses for unauthorized users
  reverse_proxy jellyfin_service_name:8096
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

### `/verify` (GET)

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