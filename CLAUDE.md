# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Knocker is a self-hosted single-packet authorization (SPA) gateway for homelabs. It provides HTTP-based authentication for reverse proxies (like Caddy) and optional firewall-level access control via FirewallD integration. Built with FastAPI, it maintains a dynamic IP whitelist with time-based expiration.

## Development Commands

### Testing

```bash
# Run unit tests (must set PYTHONPATH)
PYTHONPATH=src python3 -m pytest

# Run specific test file
PYTHONPATH=src python3 -m pytest tests/test_core.py

# Run with verbose output
PYTHONPATH=src python3 -m pytest -v

# Run integration tests (requires Docker)
cd dev && ./local_integration_tests.sh

# Run firewalld integration tests (requires root/privileged container)
cd dev && ./firewalld_integration_test.sh
```

### Development Environment

```bash
# Start dev environment with Docker Compose
docker compose -f dev/docker-compose.yml up --build

# View logs
docker compose -f dev/docker-compose.yml logs -f

# Stop dev environment
docker compose -f dev/docker-compose.yml down

# Install dependencies locally
pip install -r src/requirements.txt
```

### Running Locally (without Docker)

```bash
# Set config path and run with uvicorn
export KNOCKER_CONFIG_PATH=knocker.yaml
cd src && uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Building Docker Image

```bash
# Build image
docker build -t knocker:local .

# Run container
docker run -p 8000:8000 \
  -v $(pwd)/knocker.yaml:/app/knocker.yaml:ro \
  -e KNOCKER_CONFIG_PATH=/app/knocker.yaml \
  -v knocker-data:/data \
  knocker:local
```

## Architecture

### Core Components

- **[main.py](src/main.py)**: FastAPI application setup, lifespan management, and endpoint definitions. Handles `/knock` (POST), `/verify` (GET), and `/health` (GET).
- **[core.py](src/core.py)**: Business logic for whitelist management, IP validation, API key authentication, and TTL enforcement. Uses thread-safe and inter-process file locking.
- **[firewalld.py](src/firewalld.py)**: Optional FirewallD integration that creates dynamic firewall rules with automatic expiration via D-Bus communication.
- **[config.py](src/config.py)**: YAML configuration loading and validation.
- **[models.py](src/models.py)**: Pydantic models for request/response schemas.

### Data Flow

1. **Knock Request**: Client sends POST to `/knock` with `X-Api-Key` header
   - [main.py](src/main.py) validates API key via [core.py](src/core.py)
   - Determines client IP (from `X-Forwarded-For` if from trusted proxy, else socket IP)
   - Adds IP/CIDR to whitelist with TTL expiration timestamp
   - If FirewallD enabled, adds corresponding firewall rule
   - Returns whitelisted entry and expiration details

2. **Verify Request**: Reverse proxy sends GET to `/verify` with `X-Forwarded-For`
   - [core.py](src/core.py) checks if IP is in `always_allowed_ips`, matches `excluded_paths`, or exists in dynamic whitelist
   - Returns 200 OK if authorized, 401 Unauthorized if not
   - No body in either response

3. **Whitelist Persistence**: JSON file at `/data/whitelist.json` (configurable)
   - Thread-safe reads/writes with `threading.RLock`
   - Inter-process locking via `fcntl.flock` on `.lock` file
   - Startup cleanup removes expired entries
   - FirewallD rules restored from whitelist on startup

### FirewallD Integration Architecture

When enabled, Knocker creates a high-priority firewalld zone that:
- Blocks all traffic to monitored ports by default (DROP or REJECT)
- Dynamically adds ACCEPT rules for whitelisted IPs
- Uses firewalld's timeout mechanism for automatic rule expiration
- Communicates via D-Bus (requires root container and `/var/run/dbus/system_bus_socket` mount)
- Recovers rules on startup by comparing whitelist.json with active rules

See [docs/FIREWALLD_INTEGRATION.md](docs/FIREWALLD_INTEGRATION.md) for detailed architecture.

## Configuration

### Critical Settings

- **`trusted_proxies`**: Must match reverse proxy network. If misconfigured, clients can spoof IPs via `X-Forwarded-For`. Always verify with `docker network inspect`.
- **`always_allowed_ips`**: Should include reverse proxy network to prevent lockout. These IPs bypass whitelist checks.
- **`excluded_paths`**: Paths that bypass authentication. Always includes `/knock` by default.
- **`api_keys[].allow_remote_whitelist`**: Only `true` allows whitelisting arbitrary IPs. Keys with `false` can only whitelist their source IP.
- **`api_keys[].max_ttl`**: Maximum TTL in seconds per key. Actual TTL is capped at this value.

### FirewallD Configuration

- **`monitored_ips`**: MUST include CIDR notation (e.g., `192.168.1.100/32` not `192.168.1.100`)
- Using `0.0.0.0/0` or `::/0` blocks ALL traffic by default (use cautiously)
- Container requires `user: "0:0"`, `cap_add: [NET_ADMIN]`, and D-Bus socket mount
- **IMPORTANT**: FirewallD will NOT work with Docker published ports. See [issue #17](https://github.com/FarisZR/knocker/issues/17) for details.

## Testing Requirements

### Unit Tests

- **MUST** set `PYTHONPATH=src` or imports will fail
- Tests use fixtures in `conftest.py` (if present) and mock external dependencies
- Security tests validate IP spoofing prevention, CIDR range limits, and API key permissions

### Integration Tests

The [dev/local_integration_tests.sh](dev/local_integration_tests.sh) script:
- Starts full stack (Caddy + Knocker) via Docker Compose
- Tests knock workflow, verify endpoint, TTL expiration, remote whitelisting
- Validates trusted proxy behavior and API key permissions
- Must pass before committing changes

The [dev/firewalld_integration_test.sh](dev/firewalld_integration_test.sh):
- Tests FirewallD zone creation, rule management, and TTL expiration
- Requires privileged container (cannot run in CI)
- Run locally when modifying FirewallD code

## Important Implementation Details

### IP Address Handling

- IPv6 fully supported alongside IPv4
- CIDR ranges allowed for whitelisting (with safety limits: /16 for IPv4, /64 for IPv6)
- [core.py](src/core.py) normalizes IPs for comparison: IPv4-mapped IPv6 addresses are handled correctly
- Trusted proxy check validates source before trusting `X-Forwarded-For`

### Security Considerations

- Constant-time API key comparison using `hmac.compare_digest` prevents timing attacks
- Whitelist has configurable max entries (default 10000) to prevent resource exhaustion
- File locking prevents race conditions in multi-instance deployments
- Documentation endpoints disabled by default (enable via `documentation.enabled: true`)

### Uvicorn Configuration

The application runs with `--forwarded-allow-ips="*"` because:
- Only reverse proxy (Caddy) can reach the container on Docker network
- Knocker validates trusted proxies internally via `trusted_proxies` list
- This allows proper X-Forwarded-For header processing

### Whitelist File Format

```json
{
  "192.168.1.100": 1640995200,
  "10.0.0.0/24": 1640998800
}
```

Keys are IPs/CIDRs, values are Unix timestamps for expiration.

## Workflow

After making changes:
1. Run unit tests: `PYTHONPATH=src python3 -m pytest`
2. Build and test with Docker: `cd dev && docker compose up --build -d`
3. Run integration tests: `cd dev && ./local_integration_tests.sh`
4. If modifying FirewallD code, run: `cd dev && ./firewalld_integration_test.sh`
5. Update relevant documentation in [docs/](docs/)
6. Commit with descriptive message

## Known Issues

- Caddy's `handle_errors` directive does NOT work with `forward_auth` responses. 401 responses come directly from Knocker, not Caddy.
- Docker userland-proxy can cause IP address mismatches with Tailscale or similar overlays. Disable userland-proxy or use host networking.
- FirewallD integration requires version 2.0+ (Debian 13, Ubuntu 24.04+) for zone priority feature.

## Related Documentation

- [API_SPEC.md](docs/API_SPEC.md): Formal API specification
- [DESIGN_DECISIONS.md](docs/DESIGN_DECISIONS.md): Architectural rationale
- [SECURITY.md](docs/SECURITY.md): Security model and threat analysis
- [FIREWALLD_INTEGRATION.md](docs/FIREWALLD_INTEGRATION.md): Complete FirewallD guide
- [AGENTS.md](AGENTS.md): Additional agent-specific guidance (may contain duplicate info)
