#!/usr/bin/env bash
# Self-contained local/CI runner. Every run owns and removes its own resources.
set -euo pipefail
cd "$(dirname "$0")"

mode="${1:-all}"
case "$mode" in
    all)
        bash ./integration_tests.sh caddy
        bash ./integration_tests.sh firewalld
        exit
        ;;
    caddy) compose_file=docker-compose.ci.yml ;;
    firewalld) compose_file=docker-compose.firewalld-ci.yml ;;
    *) echo "Usage: $0 [all|caddy|firewalld]" >&2; exit 2 ;;
esac

# Override any caller's project name so cleanup cannot remove a development stack.
export COMPOSE_PROJECT_NAME="knocker-test-${mode}-$$-${RANDOM}"
compose=(docker compose --project-name "$COMPOSE_PROJECT_NAME" -f "$compose_file")

cleanup() {
    result=$?
    trap - EXIT
    if [ "$result" -ne 0 ]; then
        "${compose[@]}" logs --no-color || true
        if [ "$mode" = firewalld ]; then
            "${compose[@]}" exec -T knocker firewall-cmd --list-all-zones || true
        fi
    fi
    if ! "${compose[@]}" down --volumes --remove-orphans; then
        [ "$result" -ne 0 ] || result=1
    fi
    if [ -z "${KNOCKER_TEST_IMAGE:-}" ] && docker image inspect "${COMPOSE_PROJECT_NAME}-knocker" >/dev/null 2>&1; then
        if ! docker image rm "${COMPOSE_PROJECT_NAME}-knocker"; then
            [ "$result" -ne 0 ] || result=1
        fi
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -z "${KNOCKER_TEST_IMAGE:-}" ]; then
    "${compose[@]}" build knocker
fi
"${compose[@]}" up -d --no-build --wait --wait-timeout 90
if [ "$mode" = caddy ]; then
    "${compose[@]}" run --rm --no-deps tests
else
    # The controller runs on the host; packet probes run in separate containers.
    python3 ./firewalld/e2e.py
fi
