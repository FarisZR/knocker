#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mode="${1:-isolated}"
case "$mode" in
    isolated|linux) ;;
    *) echo "Usage: $0 [isolated|linux]" >&2; exit 2 ;;
esac
uv sync --locked --all-groups
uv run pytest
uv run --group lint ruff check .
uv run --group lint ruff format --check .
uv run --group type ty check
bash dev/integration_tests.sh all
if [ "$mode" = linux ]; then
    bash dev/firewalld_integration_test.sh
fi
