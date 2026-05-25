# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Critical Project-Specific Information (Non-Obvious)

- **Configuration is Mandatory**: The application will not start without the `KNOCKER_CONFIG_PATH` environment variable pointing to a valid `knocker.yaml` file. See [`knocker.example.yaml`](knocker.example.yaml:1) for the required structure.
- **IP Spoofing Risk**: The service's security depends on the `trusted_proxies` list in `knocker.yaml`. If this is misconfigured, clients can easily spoof their IP address via the `X-Forwarded-For` header.
- **Astral Toolchain**: Dependencies, test commands, linting, formatting, and type checking are managed through uv, Ruff, and Ty. Run local checks with `uv run pytest`, `uv run ruff check`, `uv run ruff format --check`, and `uv run ty check`.
- **Whitelist Persistence**: The IP whitelist is stored in a simple JSON file (`/data/whitelist.json` inside the container), not a database. The path is configured in `knocker.yaml`.
- **API Key Permissions**: API keys have two important properties: `allow_remote_whitelist` (boolean) and `max_ttl` (integer). A key with `allow_remote_whitelist: false` can only whitelist its own source IP. `max_ttl` defines the maximum duration in seconds an IP can be whitelisted for with that key.
- **Development Environment**: The only reliable way to run the full stack for development is with `docker compose -f dev/docker-compose.yml up`. This includes the Caddy reverse proxy, which is essential for testing the full request flow.

## Workflow

- **Run All Tests After Changes**: After making any code changes, you must run the local uv/Ruff/Ty checks (`uv run pytest`, `uv run ruff check`, `uv run ruff format --check`, `uv run ty check`) and the full Docker-based integration tests (`docker compose -f dev/docker-compose.yml up -d --build` followed by the scripts under dev.
- **Create Git Commits**: All work should be committed to Git.

- github repo: FarisZR/knocker

- **Update Documentation**: on any changes, you must update the documentation under the docs/ directory.
