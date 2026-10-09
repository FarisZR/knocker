# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Critical Project-Specific Information (Non-Obvious)

- **Configuration is Mandatory**: The application will not start without the `KNOCKER_CONFIG_PATH` environment variable pointing to a valid `knocker.yaml` file. See [`knocker.example.yaml`](knocker.example.yaml:1) for the required structure.
- **IP Spoofing Risk**: The service's security depends on the `trusted_proxies` list in `knocker.yaml`. If this is misconfigured, clients can easily spoof their IP address via the `X-Forwarded-For` header.
- **Astral Toolchain**: This project uses `uv` for environment and dependency management, `ruff` for linting and formatting, and `ty` for type checking.
- **Whitelist Persistence**: The IP whitelist is stored in a simple JSON file (`/data/whitelist.json` inside the container), not a database. The path is configured in `knocker.yaml`.
- **API Key Permissions**: API keys have two important properties: `allow_remote_whitelist` (boolean) and `max_ttl` (integer). A key with `allow_remote_whitelist: false` can only whitelist its own source IP. `max_ttl` defines the maximum duration in seconds an IP can be whitelisted for with that key.
- **Development/Test Stacks**: Every PR requires Python checks, Caddy (`dev/docker-compose.ci.yml`), isolated FirewallD (`dev/docker-compose.firewalld-ci.yml`), and the original Linux host FirewallD suite (`dev/docker-compose.yml` and `dev/firewalld_integration_test.sh`). The isolated stacks never mount host D-Bus or publish host ports. Run `bash dev/test.sh linux` on a dedicated host with FirewallD 2.0+ for the full CI-equivalent suite, or `bash dev/test.sh` for the portable isolated subset.

## Workflow

- **Run All Tests After Changes**: After making any code changes, you must run the local checks (`uv run pytest`, `uv run --group lint ruff check .`, `uv run --group lint ruff format --check .`, and `uv run --group type ty check`) and the Docker-based integration tests using the standard `dev/` compose files plus the scripts under `dev/`.
- **Create Git Commits**: All work should be committed to Git.

- github repo: FarisZR/knocker

- **Update Documentation**: on any changes, you must update the documentation under the docs/ directory.
