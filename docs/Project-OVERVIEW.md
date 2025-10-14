# Knocker

Knocker is a secure, configurable, and self-hosted service that provides a "knock-knock" single-packet authorization (SPA) gateway for your Homelab, it can be used as authentication for your reverse proxy like Caddy, or even on the firewall level using the FirewallD integration. It allows you to keep your services completely private, opening them up on-demand only for authorized IP addresses.

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
*   **Optional Interactive API Docs**: Generate Swagger UI, ReDoc, and OpenAPI JSON on demand when documentation is explicitly enabled.
*   **Firewalld Integration**: Advanced firewall control with timed rules that automatically expire based on TTL. Creates dynamic firewall rules using firewalld rich rules for enhanced security. (Optional, requires root container access)

## CI/CD

This project uses GitHub Actions for continuous integration and deployment.

*   **CI (`tests.yml`)**: On every pull request to `main`, this workflow runs the full Python test suite and then performs a live integration test with Docker Compose to ensure the Caddy and Knocker services work together correctly.
*   **Docker Publish (`docker-publish.yml`)**: Builds and publishes multi-arch Docker images to GitHub Container Registry (ghcr.io)
    - On push to `main` → `ghcr.io/fariszr/knocker:main` (rolling development)
    - On version tags (v1.2.3) → Multiple tags including `:latest`, `:v1.2.3`, `:1.2.3`, `:1.2`, `:1` (stable releases)
*   **Release Workflow (`release.yml`)**: On version tags, automatically creates GitHub releases with changelogs and installation instructions

## Deployment

This project is designed to be deployed as a set of Docker containers using the provided `docker-compose.yml` file. It uses the pre-built docker images with support for AMD64, Arm64 and risc-v.
### 1. Prerequisites
    *   Docker and Docker Compose installed.
    *   A public-facing server to run the containers.
    *   (Optional) Firewalld installed and running on the host for advanced firewall integration.

2.  **Configuration**:
    *   Rename `knocker.example.yaml` to `knocker.yaml`.
    *   **Crucially, change the default API keys** in `knocker.yaml` to your own secure, random strings.
    *   Review the `trusted_proxies` list in `knocker.yaml`, they should match the subnet of the reverse proxys network (`docker network inspect xxx`)
    *   (Optional) Enable interactive documentation by setting `documentation.enabled: true` (it is disabled by default).
    *   (Optional) Configure firewalld integration by setting `firewalld.enabled: true` and adjusting the related settings. **Note**: This requires the container to run as root.
    *   Create a `Caddyfile` in the `knocker` directory. See the "Caddy Integration" section below for examples.

3.  **Run the Service**:
    ```bash
    docker compose up -d
    ```
    This will pull the pre-built `knocker` image and start both the `knocker` and `caddy` services.

## Configuration (`knocker.yaml`)

The service is configured entirely through the `knocker.yaml` file, an example config with all the option is in [knocker.example.yaml](./knocker.example.yaml)

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

## FirewallD Integration

Knocker provides advanced firewall integration through firewalld, creating dynamic, time-based firewall rules that automatically expire based on the TTL specified in knock requests. This feature operates at the network level, allowing you to use knocker for non-http services like ssh or game servers.

### Why FirewallD?

FirewallD was chosen for the ability to separates the cli interface from the daemon. This allows Knocker to control firewalld from within a Docker container by mounting the system's D-Bus socket, and also FirewallD is the only firewall that integrates correctly with docker, meaning docker doesn't just ignore it's rules like UFW.
https://docs.docker.com/engine/network/packet-filtering-firewalls/#integration-with-firewalld

### How It Works

1. **Creates a dedicated firewalld zone** with high priority
2. **Adds DROP/REJECT rules** for monitored ports to block unauthorized access
3. **Dynamically adds ALLOW rules** for whitelisted IPs that override the blocking rules
4. **Automatically expires rules** based on TTL using firewalld's timeout mechanism
5. **Recovers rules on startup** by comparing whitelist.json with active firewalld rules

### Enabling FirewallD Integration

1. **Prerequisites**:
   - FirewallD installed and running on the host system
   - Docker container must run as root for D-Bus access

2. **Configuration** in `knocker.yaml`:
   ```yaml
   firewalld:
     enabled: true
     zone_name: "knocker"
     zone_priority: -100  # Higher priority (negative = higher)
     monitored_ports:
       - port: 80
         protocol: tcp
       - port: 443
         protocol: tcp
       - port: 22
         protocol: tcp
     monitored_ips:
       - "0.0.0.0/0"    # All IPv4 (requires /0 suffix)
       - "::/0"          # All IPv6 (requires /0 suffix)
   ```

3. **Docker Configuration**:
   ```yaml
   services:
     knocker:
       user: "0:0"  # Run as root
       cap_add:
         - NET_ADMIN
       volumes:
         - /var/run/dbus/system_bus_socket:/var/run/dbus/system_bus_socket:ro
   ```

### Testing and Troubleshooting

Monitor active rules:
```bash
# Check knocker zone
firewall-cmd --zone=knocker --list-all

# View rich rules
firewall-cmd --zone=knocker --list-rich-rules

# Monitor rule changes
journalctl -u firewalld -f
```

For detailed configuration, architecture, and troubleshooting information, see the complete [FirewallD Integration Guide](./docs/FIREWALLD_INTEGRATION.md).

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

## Tests
The project includes a full test suite

### Unit tests
To run the tests locally:

1.  **Install Dependencies**:
    ```bash
    pip install -r src/requirements.txt
    ```

2.  **Run Pytest**:
    ```bash
    python3 -m pytest

### Integration Tests
There's a dev environment under [dev](./dev/), with bash scripts for integrations tests with caddy and a separate one with firewalld.
The CI runs the caddy tests, but firewalld needs a privileged runner, which is why it needs to be run locally and isn't a part of the CI.

## Docs

Interactive documentation endpoints (`/docs`, `/redoc`, `/openapi.json`) are disabled by default. To expose them, set the following in `knocker.yaml`:

```yaml
documentation:
  enabled: true
  openapi_output_path: "openapi.json"
```

When documentation is disabled (default), Knocker removes these endpoints and deletes any previously generated schema file to prevent stale artifacts.

For a formal API specification and a summary of the architectural choices, please see the [documentation](./docs/).
