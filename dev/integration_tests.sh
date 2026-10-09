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
    firewalld) compose_file=docker-compose.yml ;;
    *) echo "Usage: $0 [all|caddy|firewalld]" >&2; exit 2 ;;
esac

# Override any caller's project name so cleanup cannot remove a development stack.
export COMPOSE_PROJECT_NAME="knocker-test-${mode}-$$-${RANDOM}"
compose=(docker compose --project-name "$COMPOSE_PROJECT_NAME" -f "$compose_file")
ca_file=""

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
    if docker image inspect "${COMPOSE_PROJECT_NAME}-knocker" >/dev/null 2>&1; then
        if ! docker image rm "${COMPOSE_PROJECT_NAME}-knocker"; then
            [ "$result" -ne 0 ] || result=1
        fi
    fi
    if [ -n "$ca_file" ]; then
        rm -f -- "$ca_file"
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Bake restricts file reads outside its working directory. Stage the CA bundle
# under dev/ (excluded from Git and the build context), without granting access
# to arbitrary host files. Compose sends it only as a BuildKit secret.
ca_source="${CODEX_PROXY_CERT:-/etc/ssl/certs/ca-certificates.crt}"
ca_file="$(mktemp "$PWD/.integration-ca.XXXXXX")"
cp -- "$ca_source" "$ca_file"
export CODEX_PROXY_CERT="$ca_file"

"${compose[@]}" build knocker
"${compose[@]}" up -d --wait --wait-timeout 180
if [ "$mode" = caddy ]; then
    "${compose[@]}" run --rm --no-deps tests
else
    # The controller runs on the host; packet probes run in separate containers.
    python3 ./firewalld/e2e.py
fi
