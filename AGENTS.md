# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Critical Project-Specific Information (Non-Obvious)

- **Configuration is Mandatory**: The application will not start without the `KNOCKER_CONFIG_PATH` environment variable pointing to a valid `knocker.yaml` file. See [`knocker.example.yaml`](knocker.example.yaml:1) for the required structure.
- **IP Spoofing Risk**: The service's security depends on the `trusted_proxies` list in `knocker.yaml`. If this is misconfigured, clients can easily spoof their IP address via the `X-Forwarded-For` header.
- **Testing Requires `PYTHONPATH`**: Unit tests must be run with `PYTHONPATH=src python3 -m pytest`. Without this, imports will fail.
- **Whitelist Persistence**: The IP whitelist is stored in a simple JSON file (`/data/whitelist.json` inside the container), not a database. The path is configured in `knocker.yaml`.
- **API Key Permissions**: API keys have two important properties: `allow_remote_whitelist` (boolean) and `max_ttl` (integer). A key with `allow_remote_whitelist: false` can only whitelist its own source IP. `max_ttl` defines the maximum duration in seconds an IP can be whitelisted for with that key.
- **Development/Test Stacks**: Use `dev/docker-compose.yml` for the firewalld/local stack and `dev/docker-compose.ci.yml` for the CI/unprivileged stack. Both are test stacks and expose Caddy on host ports `18080` and `18443`.

## Workflow

- **Run All Tests After Changes**: After making any code changes, you must run both the local unit tests (`PYTHONPATH=src python3 -m pytest`) and the Docker-based integration tests using the standard `dev/` compose files plus the scripts under `dev/`.
- **Create Git Commits**: All work should be committed to Git.

- github repo: FarisZR/knocker

- **Update Documentation**: on any changes, you must update the documentation under the docs/ directory.
