#!/usr/bin/env bash
set -euo pipefail
exec bash "$(dirname "$0")/integration_tests.sh" firewalld
