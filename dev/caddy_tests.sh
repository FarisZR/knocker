#!/usr/bin/env bash
# Runs inside a disposable client on the Caddy test network.
set -euo pipefail
base_url="${BASE_URL:?BASE_URL is required}"
admin_key=dev-only-admin-9c2f4a6d0d4b8f17e6a1c5b9d3f7a2e8
personal_key=dev-only-phone-4b7e1a9d2c6f8e3a5d0b7c1f9a4e6d2b
guest_key=dev-only-guest-8e1d4c7a2b9f5d3e6c0a4b8f1d7e2c9a
response_file="$(mktemp)"
trap 'rm -f "$response_file"' EXIT

request() {
    expected="$1"
    path="$2"
    shift 2
    status=$(curl --noproxy '*' --silent --show-error --max-time 20 \
        --output "$response_file" --write-out '%{http_code}' "$@" "$base_url$path")
    if [ "$status" != "$expected" ]; then
        echo "$path: expected HTTP $expected, got $status" >&2
        cat "$response_file" >&2
        exit 1
    fi
}

field() {
    python -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1" < "$response_file"
}

request 401 /private -H 'X-Forwarded-For: 1.1.1.1'
echo 'PASS: unauthorized private access'
request 200 /public -H 'X-Forwarded-For: 1.1.1.1'
echo 'PASS: excluded public path'
request 200 /knock -X POST -H "X-Api-Key: $admin_key" -H 'X-Forwarded-For: 1.1.1.1'
[ "$(field whitelisted_entry)" = 1.1.1.1 ]
echo 'PASS: knock preserves client address through Caddy'
request 200 /private -H 'X-Forwarded-For: 1.1.1.1'
echo 'PASS: authorized private access'
request 200 /knock -X POST -H "X-Api-Key: $admin_key" -H 'X-Forwarded-For: 1.1.1.1' \
    -H 'Content-Type: application/json' -d '{"ip_address":"8.8.8.8"}'
[ "$(field whitelisted_entry)" = 8.8.8.8 ]
request 200 /private -H 'X-Forwarded-For: 8.8.8.8'
echo 'PASS: remote whitelist grants access'
request 403 /knock -X POST -H "X-Api-Key: $personal_key" -H 'X-Forwarded-For: 1.1.1.1' \
    -H 'Content-Type: application/json' -d '{"ip_address":"9.9.9.9"}'
echo 'PASS: personal key cannot whitelist a remote address'
request 401 /knock -X POST -H 'X-Api-Key: invalid' -H 'X-Forwarded-For: 1.1.1.1'
echo 'PASS: invalid API key'
request 200 /knock -X POST -H "X-Api-Key: $admin_key" -H 'X-Forwarded-For: 1.1.1.1' \
    -H 'Content-Type: application/json' -d '{"ttl":120}'
[ "$(field expires_in_seconds)" = 120 ]
echo 'PASS: requested TTL'
request 200 /knock -X POST -H "X-Api-Key: $guest_key" -H 'X-Forwarded-For: 1.1.1.1' \
    -H 'Content-Type: application/json' -d '{"ttl":9999}'
[ "$(field expires_in_seconds)" = 600 ]
echo 'PASS: TTL capped by key permission'
request 400 /knock -X POST -H "X-Api-Key: $admin_key" -H 'X-Forwarded-For: 1.1.1.1' \
    -H 'Content-Type: application/json' -d '{"ttl":-5}'
echo 'PASS: invalid TTL'
