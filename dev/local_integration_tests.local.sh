#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

temp_script="$(mktemp "$SCRIPT_DIR/local_integration_tests.local.XXXXXX.sh")"
cleanup() {
  rm -f "$temp_script"
}
trap cleanup EXIT

perl -0pe '
  BEGIN {
    our $matched_base_url = 0;
    our $matched_compose_file = 0;
    our $matched_firewalld_block = 0;
  }
  $matched_base_url += s|BASE_URL="http://localhost"|BASE_URL="http://localhost:18080"|g;
  $matched_compose_file += s|COMPOSE_FILE="docker-compose\.yml"|COMPOSE_FILE="docker-compose.localtest.yml"|g;
  $matched_firewalld_block += s|if \[ "\$COMPOSE_FILE" != "docker-compose\.ci\.yml" \]; then\n        run_firewalld_tests\n    else\n        info "Firewalld integration tests skipped \(running in CI mode\)"\n    fi|info "Firewalld integration tests skipped (running local alt-port mode)"|s;
  END {
    my @missing;
    push @missing, q{BASE_URL="http://localhost"} unless $matched_base_url;
    push @missing, q{COMPOSE_FILE="docker-compose\.yml"} unless $matched_compose_file;
    push @missing, q{firewalld tests block} unless $matched_firewalld_block;
    if (@missing) {
      die "local_integration_tests.local.sh substitutions failed for: " . join(", ", @missing) . "\n";
    }
  }
' local_integration_tests.sh > "$temp_script"

bash "$temp_script"
