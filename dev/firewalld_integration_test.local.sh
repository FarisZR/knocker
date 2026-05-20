#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

python3 - <<'PY' | bash
from pathlib import Path

content = Path("firewalld_integration_test.sh").read_text(encoding="utf-8")
content = content.replace('BASE_URL="http://localhost"', 'BASE_URL="http://localhost:18080"')
content = content.replace('docker-compose.yml', 'docker-compose.firewalld.localtest.yml')
print(content, end="")
PY
