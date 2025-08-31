#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Helper Functions ---
info() {
    echo "[INFO] $1"
}

success() {
    echo "✅ $1"
}

fail() {
    echo "❌ $1"
    exit 1
}

# --- Configuration ---
BASE_URL="http://localhost"
PROTECTED_URL="$BASE_URL/private"
KNOCK_URL="$BASE_URL/knock"

# IPs
REGULAR_IP="1.1.1.1"
ALWAYS_ALLOWED_IP="172.29.238.10" # From the docker-compose network
REMOTE_WHITELIST_IP="8.8.8.8"

# API Keys (from knocker.example.yaml)
VALID_ADMIN_KEY="CHANGE_ME_SUPER_SECRET_ADMIN_KEY"
INVALID_KEY="INVALID_KEY"
NO_REMOTE_KEY="CHANGE_ME_SECRET_PHONE_KEY"

# Global variable to store the whitelisted IP from a successful knock
WHITELISTED_IP=""

# --- Test Runner ---
run_test() {
    info "Running test: $1"
    eval "$2"
    info "Finished test: $1"
    echo # Newline for readability
}

# --- Test Cases ---

test_unauthorized_access() {
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: $REGULAR_IP" $PROTECTED_URL)
    if [ "$http_code" -eq 401 ]; then
        success "Unauthorized access correctly returned 401"
    else
        fail "Unauthorized access returned $http_code instead of 401"
    fi
}

test_successful_knock() {
    response=$(curl -s -X POST -H "X-Api-Key: $VALID_ADMIN_KEY" -H "X-Forwarded-For: $REGULAR_IP" $KNOCK_URL)
    if echo "$response" | grep -q "whitelisted_entry"; then
        # Extract the whitelisted IP from the response
        WHITELISTED_IP=$(echo "$response" | sed -n 's/.*"whitelisted_entry":"\([^"]*\)".*/\1/p')
        if [ -z "$WHITELISTED_IP" ]; then
            fail "Could not extract whitelisted IP from knock response: $response"
        fi
        success "Successful knock for $WHITELISTED_IP"
    else
        fail "Knock failed for $REGULAR_IP. Response: $response"
    fi
}

test_authorized_access_after_knock() {
    if [ -z "$WHITELISTED_IP" ]; then
        fail "WHITELISTED_IP variable is not set. Cannot run authorized access test."
    fi
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: $WHITELISTED_IP" $PROTECTED_URL)
    if [ "$http_code" -eq 200 ]; then
        success "Authorized access after knock for $WHITELISTED_IP returned 200"
    else
        fail "Authorized access after knock for $WHITELISTED_IP returned $http_code instead of 200"
    fi
}

test_always_allowed_ip_access() {
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: $ALWAYS_ALLOWED_IP" $PROTECTED_URL)
    if [ "$http_code" -eq 200 ]; then
        success "Always-allowed IP ($ALWAYS_ALLOWED_IP) accessed protected route directly"
    else
        fail "Always-allowed IP ($ALWAYS_ALLOWED_IP) failed to access protected route. Got $http_code"
    fi
}

test_knock_for_always_allowed_ip_valid_key() {
    response=$(curl -s -X POST -H "X-Api-Key: $VALID_ADMIN_KEY" -H "X-Forwarded-For: $ALWAYS_ALLOWED_IP" $KNOCK_URL)
    if echo "$response" | grep -q "whitelisted_entry"; then
        success "Knock for always-allowed IP with valid key was successful (as expected)"
    else
        fail "Knock for always-allowed IP with valid key failed. Response: $response"
    fi
}

test_knock_for_always_allowed_ip_invalid_key() {
    response=$(curl -s -X POST -H "X-Api-Key: $INVALID_KEY" -H "X-Forwarded-For: $ALWAYS_ALLOWED_IP" $KNOCK_URL)
    if echo "$response" | grep -q "Invalid or missing API key"; then
        success "Knock for always-allowed IP with invalid key correctly failed"
    else
        fail "Knock for always-allowed IP with invalid key did not fail as expected. Response: $response"
    fi
}

test_remote_whitelist_success() {
    response=$(curl -s -X POST -H "X-Api-Key: $VALID_ADMIN_KEY" -H "Content-Type: application/json" -d "{\"ip_address\": \"$REMOTE_WHITELIST_IP\"}" $KNOCK_URL)
    if echo "$response" | grep -q "whitelisted_entry.*$REMOTE_WHITELIST_IP"; then
        success "Remote whitelist for $REMOTE_WHITELIST_IP with admin key successful"
    else
        fail "Remote whitelist for $REMOTE_WHITELIST_IP with admin key failed. Response: $response"
    fi
}

test_remote_whitelist_permission_denied() {
    response=$(curl -s -X POST -H "X-Api-Key: $NO_REMOTE_KEY" -H "Content-Type: application/json" -d "{\"ip_address\": \"$REMOTE_WHITELIST_IP\"}" $KNOCK_URL)
    if echo "$response" | grep -q "API key lacks remote whitelist permission"; then
        success "Remote whitelist with no-permission key correctly failed"
    else
        fail "Remote whitelist with no-permission key did not fail as expected. Response: $response"
    fi
}

# --- Main Execution ---
main() {
    info "Starting integration tests..."

    info "Waiting for services to be healthy..."
    retry_count=0
    max_retries=30
    retry_interval=2

    until $(curl --output /dev/null --silent --fail "$BASE_URL/health"); do
        if [ ${retry_count} -ge ${max_retries} ]; then
            fail "Services did not become healthy in time."
        fi
        printf '.'
        retry_count=$((retry_count+1))
        sleep ${retry_interval}
    done
    echo # Newline after dots
    success "Services are healthy!"

    run_test "Unauthorized Access" "test_unauthorized_access"
    run_test "Successful Knock" "test_successful_knock"
    run_test "Authorized Access After Knock" "test_authorized_access_after_knock"
    run_test "Always-Allowed IP Direct Access" "test_always_allowed_ip_access"
    run_test "Knock for Always-Allowed IP (Valid Key)" "test_knock_for_always_allowed_ip_valid_key"
    run_test "Knock for Always-Allowed IP (Invalid Key)" "test_knock_for_always_allowed_ip_invalid_key"
    run_test "Remote Whitelist (Success)" "test_remote_whitelist_success"
    run_test "Remote Whitelist (Permission Denied)" "test_remote_whitelist_permission_denied"
    run_test "Knock with Invalid Key" "test_knock_with_invalid_key"

    info "All integration tests passed!"
}

test_knock_with_invalid_key() {
    response=$(curl -s -X POST -H "X-Api-Key: $INVALID_KEY" -H "X-Forwarded-For: $REGULAR_IP" $KNOCK_URL)
    if echo "$response" | grep -q "Invalid or missing API key"; then
        success "Knock with invalid key correctly failed"
    else
        fail "Knock with invalid key did not fail as expected. Response: $response"
    fi
}

main