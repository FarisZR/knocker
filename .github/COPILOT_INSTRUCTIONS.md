# GitHub Copilot Instructions for Knocker

This file provides guidance to GitHub Copilot when working with code in this repository.

## Project Overview

Knocker is a dynamic IP whitelisting service that integrates with reverse proxies (like Caddy) to provide port-knocking functionality. It can optionally integrate with firewalld for advanced firewall rule management.

## Critical Project-Specific Information

### Configuration and Setup

- **Configuration is Mandatory**: The application will not start without the `KNOCKER_CONFIG_PATH` environment variable pointing to a valid `knocker.yaml` file. See `knocker.example.yaml` for the required structure.
- **Configuration Loading**: All configuration is loaded from a single YAML file via the `get_settings()` function in `src/main.py`. This function is cached with `@lru_cache`, so the config file is only read once.

### Security Considerations

- **IP Spoofing Risk**: The service's security depends on the `trusted_proxies` list in `knocker.yaml`. If this is misconfigured, clients can easily spoof their IP address via the `X-Forwarded-For` header.
- **Reverse Proxy is Essential**: The application is not designed to be exposed directly to the internet. It relies on a reverse proxy (like Caddy) to handle TLS and to provide the `X-Forwarded-For` header, which is critical for the IP whitelisting logic.
- **Security Dependency**: The `get_client_ip` function in `src/main.py` relies on the `X-Forwarded-For` header. This is only secure if the `trusted_proxies` in `knocker.yaml` is correctly configured.

### Data Storage

- **Whitelist Persistence**: The IP whitelist is stored in a simple JSON file (`/data/whitelist.json` inside the container), not a database. The path is configured in `knocker.yaml`.
- **No Database**: The project intentionally uses a simple JSON file for the whitelist to keep the architecture simple and to avoid introducing a database dependency. Any proposal to add a database would be a major architectural change.
- **Stateless Application Design**: The knocker service is designed to be stateless at the process level: it maintains no in-memory state between requests. All state is persisted externally in the `whitelist.json` file via a Docker volume. Do not introduce in-memory state that would break this pattern.
- **State Management**: The application's state (the IP whitelist) is managed in a single JSON file. All functions in `src/core.py` that modify the whitelist (`add_ip_to_whitelist`, `cleanup_expired_ips`) handle file I/O (load and save).

### API Key Permissions

- **API Key Permissions**: API keys have two important properties: `allow_remote_whitelist` (boolean) and `max_ttl` (integer). A key with `allow_remote_whitelist: false` can only whitelist its own source IP. `max_ttl` defines the maximum duration in seconds an IP can be whitelisted for with that key.

## Code Organization

### Core Logic

- **Core logic is in `src/core.py`**: While `src/main.py` defines the API endpoints, all the business logic for IP validation, whitelist management, and API key permissions is located in `src/core.py`. Do not implement this logic elsewhere.

### Configuration Reference

- **`knocker.example.yaml` is the primary reference**: The `knocker.example.yaml` file is the most reliable source of truth for configuration options. The `API_SPEC.md` and `README.md` provide a high-level overview, but the YAML file contains all the details.

## Testing Requirements

### Unit Tests

- **Testing Requires `PYTHONPATH`**: Unit tests must be run with `PYTHONPATH=src python3 -m pytest`. Without this, imports will fail.
- **Run All Tests After Changes**: After making any code changes, you must run both the local unit tests (`PYTHONPATH=src python3 -m pytest`) and the full Docker-based integration tests.

### Integration Tests

- **Development Environment**: The only reliable way to run the full stack for development is with `docker compose -f dev/docker-compose.yml up`. This includes the Caddy reverse proxy, which is essential for testing the full request flow.
- **`dev/docker-compose.yml` for development**: The `docker-compose.yml` in the root is for production deployment. The `dev/docker-compose.yml` is specifically for the development environment and includes the Caddy reverse proxy for full end-to-end testing.
- **CI workflow shows integration tests**: The `.github/workflows/ci.yml` file contains the `curl` commands that serve as the project's integration tests. This is the best place to understand the expected request/response flow.
- **Integration tests are authoritative**: Integration tests (dev/firewalld_integration_test.sh and dev/docker-compose.yml) exercise real interactions with the system (firewalld, Caddy). Use them as the final verification step for changes that touch networking, firewall rules, or startup/restore logic.

## Firewalld Integration

- **Firewalld integration caveat**: When integrating with firewalld, command-line tools (firewall-cmd) may return "success" with a warning (e.g., ALREADY_ENABLED) while not updating timeouts. Any code that adds rich-rules must detect these warnings, remove the existing rule and re-add it with the intended timeout to ensure TTL semantics are enforced.
- **Command output handling**: When invoking external tools (e.g., firewall-cmd), parse both stdout and stderr for success-with-warning markers like "ALREADY_ENABLED" or "already in". Treat those as collisions that require explicit replacement (remove then add) rather than trusting the success code alone.

## Coding Standards

### Logging

- **Logging sensitive information**: Avoid logging API key names or other sensitive identifiers at INFO level. Use DEBUG logging for such details (e.g., API key name) so production logs do not leak identifying information. Unit tests assert this behavior; if changing logging, ensure tests remain consistent.

## Documentation

- **Interactive API Documentation Available**: The service provides dynamic OpenAPI 3.1 documentation accessible at `/docs` (Swagger UI), `/redoc` (ReDoc), and `/openapi.json` (raw schema). Documentation can be disabled in production via `knocker.yaml` by setting `documentation.enabled: false`. See `docs/INTERACTIVE_DOCUMENTATION.md` for complete usage guide.
- **Update Documentation**: On any changes, you must update the documentation under the docs/ directory.

## Workflow

- **Create Git Commits**: All work should be committed to Git.
- **Run All Tests After Changes**: After making any code changes, you must run both the local unit tests (`PYTHONPATH=src python3 -m pytest`) and the full Docker-based integration tests (`docker compose -f dev/docker-compose.yml up -d --build` followed by the scripts under dev).

## Repository Information

- **GitHub Repository**: FarisZR/knocker
