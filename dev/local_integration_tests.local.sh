#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

perl -0pe '
  s|BASE_URL="http://localhost"|BASE_URL="http://localhost:18080"|g;
  s|COMPOSE_FILE="docker-compose\.yml"|COMPOSE_FILE="docker-compose.localtest.yml"|g;
  s|if \[ "\$COMPOSE_FILE" != "docker-compose\.ci\.yml" \]; then\n        run_firewalld_tests\n    else\n        info "Firewalld integration tests skipped \(running in CI mode\)"\n    fi|info "Firewalld integration tests skipped (running local alt-port mode)"|s;
' local_integration_tests.sh | bash
