#!/usr/bin/env bash
# Additional deployment check: Knocker talks to the HOST FirewallD over D-Bus.
# CI's required packet tests use integration_tests.sh firewalld instead.
set -euo pipefail
cd "$(dirname "$0")"

for tool in docker firewall-cmd systemctl curl uv; do
    command -v "$tool" >/dev/null || { echo "Host tests require $tool" >&2; exit 1; }
done
systemctl is-active --quiet firewalld || { echo 'Host FirewallD must be running' >&2; exit 1; }
if [ "$(id -u)" -eq 0 ]; then
    host_firewall=(firewall-cmd)
else
    host_firewall=(sudo -n firewall-cmd)
fi
"${host_firewall[@]}" --state

export COMPOSE_PROJECT_NAME="knocker-host-test-$$-$RANDOM"
compose=(docker compose --project-name "$COMPOSE_PROJECT_NAME" -f docker-compose.yml)
zone="knocker-$RANDOM"
zone_owned=false
test_ipv4="192.0.2.$((RANDOM % 200 + 2))"
test_ipv6="2001:db8::$(printf '%x' "$((RANDOM + 1))")"
ports=(tcp:80 tcp:443 tcp:22 udp:9001)
admin_key=dev-only-admin-9c2f4a6d0d4b8f17e6a1c5b9d3f7a2e8
workdir="$(mktemp -d "$PWD/.host-firewalld.XXXXXX")"
export KNOCKER_HOST_TEST_CONFIG="$workdir/knocker.yaml"
response_file="$workdir/response.json"

cleanup() {
    result=$?
    trap - EXIT
    if [ "$result" -ne 0 ]; then "${compose[@]}" logs --no-color || true; fi
    # Stop requests before removing our zone. Never stop/restart host FirewallD
    # or remove a pre-existing zone, even if cleanup fails.
    "${compose[@]}" down --volumes --remove-orphans || result=1
    if "$zone_owned"; then
        if zones=$("${host_firewall[@]}" --permanent --get-zones); then
            if printf '%s\n' "$zones" | tr ' ' '\n' | grep -qx "$zone"; then
                "${host_firewall[@]}" --permanent "--delete-zone=$zone" || result=1
                "${host_firewall[@]}" --reload || result=1
            fi
        else
            echo "Could not inspect host FirewallD; verify cleanup of $zone" >&2
            result=1
        fi
    fi
    if [ -z "${KNOCKER_TEST_IMAGE:-}" ] && docker image inspect "${COMPOSE_PROJECT_NAME}-knocker" >/dev/null 2>&1; then
        docker image rm "${COMPOSE_PROJECT_NAME}-knocker" || result=1
    fi
    rm -f -- "$KNOCKER_HOST_TEST_CONFIG" "$response_file" "$workdir/before.json" "$workdir/after.json"
    rmdir "$workdir" || result=1
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Refuse to adopt a zone that another process already owns.
if "${host_firewall[@]}" --permanent --get-zones | tr ' ' '\n' | grep -qx "$zone"; then
    echo "Test zone already exists: $zone" >&2
    exit 1
fi
zone_owned=true
uv run python - "$KNOCKER_HOST_TEST_CONFIG" "$zone" "$test_ipv4" "$test_ipv6" <<'PY'
from pathlib import Path
import sys
import yaml

path, zone, ipv4, ipv6 = sys.argv[1:]
config = yaml.safe_load(Path('knocker.firewalld.yaml').read_text())
config['firewalld']['zone_name'] = zone
config['firewalld']['monitored_ips'] = [ipv4 + '/32', ipv6 + '/128']
Path(path).write_text(yaml.safe_dump(config))
PY

firewall() {
    "${compose[@]}" exec -T knocker firewall-cmd "--zone=$zone" "$@"
}
ready_status() {
    "${compose[@]}" exec -T knocker curl --noproxy '*' --silent --show-error \
        --max-time 15 --output /dev/null --write-out '%{http_code}' http://127.0.0.1:8000/ready
}
wait_ready() {
    deadline=$((SECONDS + 60))
    until [ "$(ready_status 2>/dev/null || true)" = 200 ]; do
        [ "$SECONDS" -lt "$deadline" ] || { echo 'Knocker did not become ready' >&2; return 1; }
        sleep 1
    done
}
knock() {
    expected="$1"; ip="$2"; ttl="$3"; key="${4:-$admin_key}"
    status=$(curl --noproxy '*' --silent --show-error --max-time 15 \
        --output "$response_file" --write-out '%{http_code}' \
        -H "X-Api-Key: $key" -H 'X-Forwarded-For: 192.0.2.254' \
        -H 'Content-Type: application/json' \
        -d "{\"ip_address\":\"$ip\",\"ttl\":$ttl}" http://127.0.0.1:18080/knock)
    [ "$status" = "$expected" ] || { cat "$response_file" >&2; return 1; }
    if [ "$expected" = 200 ]; then
        uv run python - "$response_file" "$ip" "$ttl" <<'PY'
import json, sys
from pathlib import Path
body = json.loads(Path(sys.argv[1]).read_text())
assert body['whitelisted_entry'] == sys.argv[2], body
assert body['expires_in_seconds'] == int(sys.argv[3]), body
PY
    fi
}
rule() {
    ip="$1"; pair="$2"
    family=ipv4; [[ "$ip" != *:* ]] || family=ipv6
    printf 'rule family="%s" source address="%s" port protocol="%s" port="%s" accept priority="1000"' \
        "$family" "$ip" "${pair%:*}" "${pair#*:}"
}
assert_rules() {
    expected="$1"; ip="$2"
    for pair in "${ports[@]}"; do
        actual=$(firewall "--query-rich-rule=$(rule "$ip" "$pair")" || true)
        [ "$actual" = "$expected" ] || { echo "Missing expected $expected rule: $ip $pair" >&2; return 1; }
    done
}
wait_expiry() {
    ip="$1"; deadline=$((SECONDS + 20))
    while firewall --list-rich-rules | grep -Fq "source address=\"$ip\""; do
        [ "$SECONDS" -lt "$deadline" ] || { echo "Rules did not expire: $ip" >&2; return 1; }
        sleep 1
    done
    assert_rules no "$ip"
}

if [ -z "${KNOCKER_TEST_IMAGE:-}" ]; then "${compose[@]}" build knocker; fi
"${compose[@]}" up -d --no-build
wait_ready
[ "$("${compose[@]}" exec -T knocker firewall-cmd --state)" = running ]
[ "$(firewall --permanent --get-priority)" = -100 ]
[ "$(firewall --permanent --get-target)" = default ]
for source in "$test_ipv4/32" "$test_ipv6/128"; do
    [ "$(firewall "--query-source=$source")" = yes ]
done
for family in ipv4 ipv6; do
    for pair in "${ports[@]}"; do
        default_rule="rule family=\"$family\" port port=\"${pair#*:}\" protocol=\"${pair%:*}\" drop priority=\"9999\""
        [ "$(firewall "--query-rich-rule=$default_rule")" = yes ]
    done
done
echo 'PASS: host D-Bus, zone priority/target/sources, every default TCP/UDP rule'

for ip in "$test_ipv4" "$test_ipv6"; do
    knock 200 "$ip" 8
    assert_rules yes "$ip"
    wait_expiry "$ip"
done
echo 'PASS: exact IPv4/IPv6 timed rules and real expiry'

knock 200 "$test_ipv4" 120
knock 200 "$test_ipv4" 6
assert_rules yes "$test_ipv4"
wait_expiry "$test_ipv4"
echo 'PASS: shorter TTL replaces the original long grant'

for ip in "$test_ipv4" "$test_ipv6"; do
    knock 200 "$ip" 120
    assert_rules yes "$ip"
    for pair in "${ports[@]}"; do firewall "--remove-rich-rule=$(rule "$ip" "$pair")"; done
    assert_rules no "$ip"
done
"${compose[@]}" exec -T knocker cat /data/whitelist.json > "$workdir/before.json"
"${host_firewall[@]}" --reload
"${compose[@]}" restart knocker
wait_ready
for ip in "$test_ipv4" "$test_ipv6"; do assert_rules yes "$ip"; done
"${compose[@]}" exec -T knocker cat /data/whitelist.json > "$workdir/after.json"
cmp "$workdir/before.json" "$workdir/after.json"
echo 'PASS: all eight timed rules recover without extending persisted expiry'

knock 401 "$test_ipv4" 60 invalid
knock 403 "$test_ipv4" 60 dev-only-phone-4b7e1a9d2c6f8e3a5d0b7c1f9a4e6d2b
"${compose[@]}" exec -T knocker cat /data/whitelist.json > "$workdir/after.json"
cmp "$workdir/before.json" "$workdir/after.json"
echo 'PASS: rejected API keys and remote permission failures do not mutate persistence'

default_rule='rule family="ipv4" port port="80" protocol="tcp" drop priority="9999"'
firewall "--remove-rich-rule=$default_rule"
[ "$(ready_status)" = 503 ]
"${compose[@]}" exec -T knocker curl --noproxy '*' --fail --silent http://127.0.0.1:8000/health >/dev/null
firewall "--add-rich-rule=$default_rule"
[ "$(ready_status)" = 200 ]
echo 'PASS: readiness detects lost protection; liveness remains available'
