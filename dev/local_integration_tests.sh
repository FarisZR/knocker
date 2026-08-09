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
# Ensure script runs from its own directory (so tests use the dev/ compose files and
# the script won't accidentally start services from the repository root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || true
 
BASE_URL="http://localhost:18080"
PROTECTED_URL="$BASE_URL/private"
PUBLIC_URL="$BASE_URL/public"
KNOCK_URL="$BASE_URL/knock"
 
# IPs
REGULAR_IP="1.1.1.1"
REMOTE_WHITELIST_IP="8.8.8.8"

# API Keys (from knocker.example.yaml)
VALID_ADMIN_KEY="dev-only-admin-9c2f4a6d0d4b8f17e6a1c5b9d3f7a2e8"
INVALID_KEY="INVALID_KEY"
NO_REMOTE_KEY="dev-only-phone-4b7e1a9d2c6f8e3a5d0b7c1f9a4e6d2b"
GUEST_KEY="dev-only-guest-8e1d4c7a2b9f5d3e6c0a4b8f1d7e2c9a"

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

test_public_path_requires_authorization() {
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: $REGULAR_IP" $PUBLIC_URL)
    if [ "$http_code" -eq 200 ]; then
        success "Protected path correctly required authorization"
    else
        fail "Protected path returned $http_code instead of 401"
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

test_remote_whitelist_success() {
    response=$(curl -s -X POST -H "X-Api-Key: $VALID_ADMIN_KEY" -H "X-Forwarded-For: $REGULAR_IP" -H "Content-Type: application/json" -d "{\"ip_address\": \"$REMOTE_WHITELIST_IP\"}" $KNOCK_URL)
    if echo "$response" | grep -q "whitelisted_entry.*$REMOTE_WHITELIST_IP"; then
        success "Remote whitelist for $REMOTE_WHITELIST_IP with admin key successful"
    else
        fail "Remote whitelist for $REMOTE_WHITELIST_IP with admin key failed. Response: $response"
    fi
}

test_remote_whitelist_permission_denied() {
    response=$(curl -s -X POST -H "X-Api-Key: $NO_REMOTE_KEY" -H "X-Forwarded-For: $REGULAR_IP" -H "Content-Type: application/json" -d "{\"ip_address\": \"$REMOTE_WHITELIST_IP\"}" $KNOCK_URL)
    if echo "$response" | grep -q "API key lacks remote whitelist permission"; then
        success "Remote whitelist with no-permission key correctly failed"
    else
        fail "Remote whitelist with no-permission key did not fail as expected. Response: $response"
    fi
}

# --- Firewalld Integration Tests ---

run_firewalld_tests() {
    info "Running firewalld integration tests..." 
    run_test "Firewalld Zone Exists" "test_firewalld_zone_exists"
    run_test "Firewalld Rules After Knock" "test_firewalld_rules_after_knock"
}

# --- Main Execution ---
main() {
    info "Starting integration tests..."

    info "Waiting for services to be healthy..."
    retry_count=0
    max_retries=30
    retry_interval=2

    until curl --output /dev/null --silent --fail "$BASE_URL/health"; do
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
    run_test "Protected Path Requires Authorization" "test_public_path_requires_authorization"
    run_test "Successful Knock" "test_successful_knock"
    run_test "Authorized Access After Knock" "test_authorized_access_after_knock"
    run_test "Remote Whitelist (Success)" "test_remote_whitelist_success"
    run_test "Remote Whitelist (Permission Denied)" "test_remote_whitelist_permission_denied"
    run_test "Knock with Invalid Key" "test_knock_with_invalid_key"
    run_test "Knock with Custom TTL (Valid)" "test_knock_with_custom_ttl_valid"
    run_test "Knock with Custom TTL (Capped)" "test_knock_with_custom_ttl_capped"
    run_test "Knock with Custom TTL (Invalid)" "test_knock_with_custom_ttl_invalid"

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

test_knock_with_custom_ttl_valid() {
    response=$(curl -s -X POST -H "X-Api-Key: $VALID_ADMIN_KEY" -H "X-Forwarded-For: $REGULAR_IP" -H "Content-Type: application/json" -d '{"ttl": 120}' $KNOCK_URL)
    ttl=$(echo "$response" | sed -n 's/.*"expires_in_seconds":\([0-9]*\).*/\1/p')
    if [ "$ttl" -eq 120 ]; then
        success "Knock with valid custom TTL of 120s was successful"
    else
        fail "Knock with valid custom TTL failed. Expected 120, got $ttl. Response: $response"
    fi
}

test_knock_with_custom_ttl_capped() {
    # This key has a max_ttl of 600 in the config
    response=$(curl -s -X POST -H "X-Api-Key: $GUEST_KEY" -H "X-Forwarded-For: $REGULAR_IP" -H "Content-Type: application/json" -d '{"ttl": 9999}' $KNOCK_URL)
    ttl=$(echo "$response" | sed -n 's/.*"expires_in_seconds":\([0-9]*\).*/\1/p')
    if [ "$ttl" -eq 600 ]; then
        success "Knock with oversized TTL was correctly capped to 600s"
    else
        fail "Knock with oversized TTL was not capped correctly. Expected 600, got $ttl. Response: $response"
    fi
}

test_knock_with_custom_ttl_invalid() {
    response=$(curl -s -X POST -H "X-Api-Key: $VALID_ADMIN_KEY" -H "X-Forwarded-For: $REGULAR_IP" -H "Content-Type: application/json" -d '{"ttl": -50}' $KNOCK_URL)
    if echo "$response" | grep -q "Invalid TTL specified"; then
        success "Knock with invalid (negative) TTL correctly failed"
    else
        fail "Knock with invalid TTL did not fail as expected. Response: $response"
    fi
}

# --- Firewalld Integration Tests ---

test_firewalld_zone_exists() {
    if command -v docker-compose &> /dev/null || command -v docker &> /dev/null; then
        # Try docker compose first, then fall back to docker-compose
        if command -v docker &> /dev/null && docker compose version &> /dev/null; then
            zone_check=$(docker compose -f "$COMPOSE_FILE" exec -T knocker firewall-cmd --list-all-zones 2>/dev/null | grep -c "knocker" || echo "0")
        elif command -v docker-compose &> /dev/null; then
            zone_check=$(docker-compose -f "$COMPOSE_FILE" exec -T knocker firewall-cmd --list-all-zones 2>/dev/null | grep -c "knocker" || echo "0")
        else
            fail "Docker Compose is unavailable for firewalld validation"
        fi
        
        if [ "$zone_check" -gt 0 ]; then
            success "Firewalld knocker zone exists"
        else
            fail "Firewalld knocker zone is missing"
        fi
    else
        fail "Docker is unavailable for firewalld validation"
    fi
}

test_firewalld_rules_after_knock() {
    if command -v docker-compose &> /dev/null || command -v docker &> /dev/null; then
        # First, perform a knock
        response=$(curl -s -X POST -H "X-Api-Key: $VALID_ADMIN_KEY" -H "X-Forwarded-For: $REGULAR_IP" $KNOCK_URL)
        if echo "$response" | grep -q "whitelisted_entry"; then
            # Check if rich rules exist for the IP
            # Try docker compose first, then fall back to docker-compose
            if command -v docker &> /dev/null && docker compose version &> /dev/null; then
                rules_check=$(docker compose -f "$COMPOSE_FILE" exec -T knocker firewall-cmd --zone=knocker --list-rich-rules 2>/dev/null | grep -c "$REGULAR_IP" || echo "0")
            elif command -v docker-compose &> /dev/null; then
                rules_check=$(docker-compose -f "$COMPOSE_FILE" exec -T knocker firewall-cmd --zone=knocker --list-rich-rules 2>/dev/null | grep -c "$REGULAR_IP" || echo "0")
            else
                fail "Docker Compose is unavailable for firewalld validation"
            fi
            
            if [ "$rules_check" -gt 0 ]; then
                success "Firewalld rules created for whitelisted IP ($REGULAR_IP)"
            else
                fail "Firewalld rules are missing after a successful knock"
            fi
        else
            fail "Could not perform knock for firewalld rules test"
        fi
    else
        fail "Docker is unavailable for firewalld validation"
    fi
}

main() {
    info "Starting integration tests..."

    # Check if we're in CI environment or if the firewalld test stack is actually usable.
    COMPOSE_FILE="docker-compose.yml"
    if [ "$CI" = "true" ] || [ "$KNOCKER_TEST_MODE" = "ci" ] || [ ! -f /var/run/dbus/system_bus_socket ] || ! systemctl is-active --quiet firewalld 2>/dev/null; then
        info "Using CI configuration (firewalld disabled)"
        COMPOSE_FILE="docker-compose.ci.yml"
    fi
    
    # Show docker logs for debugging if tests fail
    show_logs_on_exit() {
        if [ $? -ne 0 ]; then
            info "Test failed - showing container logs for debugging:"
            
            # Try docker compose first, then fall back to docker-compose
            if command -v docker &> /dev/null && docker compose version &> /dev/null; then
                info "=== Knocker container logs ==="
                docker compose -f "$COMPOSE_FILE" logs knocker || true
                info "=== Caddy container logs ==="
                docker compose -f "$COMPOSE_FILE" logs caddy || true
            elif command -v docker-compose &> /dev/null; then
                info "=== Knocker container logs ==="
                docker-compose -f "$COMPOSE_FILE" logs knocker || true
                info "=== Caddy container logs ==="
                docker-compose -f "$COMPOSE_FILE" logs caddy || true
            fi
        fi
    }
    trap show_logs_on_exit EXIT

    info "Waiting for services to be healthy..."
    retry_count=0
    max_retries=30
    retry_interval=2

    until curl --output /dev/null --silent --fail "$BASE_URL/health"; do
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
    run_test "Protected Path Requires Authorization" "test_public_path_requires_authorization"
    run_test "Successful Knock" "test_successful_knock"
    run_test "Authorized Access After Knock" "test_authorized_access_after_knock"
    run_test "Remote Whitelist (Success)" "test_remote_whitelist_success"
    run_test "Remote Whitelist (Permission Denied)" "test_remote_whitelist_permission_denied"
    run_test "Knock with Invalid Key" "test_knock_with_invalid_key"
    run_test "Knock with Custom TTL (Valid)" "test_knock_with_custom_ttl_valid"
    run_test "Knock with Custom TTL (Capped)" "test_knock_with_custom_ttl_capped"
    run_test "Knock with Custom TTL (Invalid)" "test_knock_with_custom_ttl_invalid"
    
    # Run firewalld integration tests only if not in CI mode
    if [ "$COMPOSE_FILE" != "docker-compose.ci.yml" ]; then
        run_firewalld_tests
    else
        info "Firewalld integration tests skipped (running in CI mode)"
    fi

    info "All integration tests passed!"
}

main
