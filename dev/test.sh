#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
uv sync --locked --all-groups
uv run pytest
uv run --group lint ruff check .
uv run --group lint ruff format --check .
uv run --group type ty check
bash dev/integration_tests.sh all
