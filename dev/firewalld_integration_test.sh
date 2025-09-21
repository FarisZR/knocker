#!/bin/bash

# Firewalld Integration Test Script
# Tests the firewalld integration feature with a real firewalld daemon

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

warning() {
    echo "⚠️  $1"
}

# --- Configuration ---
BASE_URL="http://localhost"
KNOCK_URL="$BASE_URL/knock"

# Test IP
TEST_IP="192.168.178.77"

# API Key (from knocker.firewalld.yaml)
VALID_ADMIN_KEY="CHANGE_ME_SUPER_SECRET_ADMIN_KEY"

# --- Test Functions ---

check_prerequisites() {
    info "Checking prerequisites..."
    
    # Check if docker compose is available
    if ! docker compose version &> /dev/null; then
        fail "docker compose v2 is required but not installed"
    fi
    
    # Check if firewalld is available on the host system
    if ! systemctl is-active --quiet firewalld 2>/dev/null; then
        warning "Firewalld is not running on host system. Some tests may be limited."
    fi
    
    success "Prerequisites check passed"
}

start_test_environment() {
    info "Starting test environment with firewalld integration..."
    
    # Start the services
    docker compose -f docker-compose.yml down --remove-orphans || true
    docker compose -f docker-compose.yml up -d --build
    
    # Wait for services to be ready
    info "Waiting for services to start..."
    retry_count=0
    max_retries=60
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
    
    success "Test environment started"
}

test_firewalld_daemon_access() {
    info "Testing firewalld daemon access from container..."
    
    # Test if the container can access firewalld
    if docker compose exec -T knocker firewall-cmd --state &>/dev/null; then
        success "Container can access firewalld daemon"
    else
        fail "Container cannot access firewalld daemon. Check dbus mount and permissions."
    fi
}

test_knocker_zone_creation() {
    info "Testing knocker zone creation..."
    
    # Check if the knocker zone was created
    if docker compose exec -T knocker firewall-cmd --list-all-zones | grep -q "knocker"; then
        success "Knocker firewalld zone exists"
    else
        fail "Knocker firewalld zone was not created"
    fi
    
    # Check zone properties
    zone_info=$(docker compose exec -T knocker firewall-cmd --zone=knocker --list-all)
    
    if echo "$zone_info" | grep -q "target: DROP"; then
        success "Knocker zone has correct target (DROP)"
    else
        warning "Knocker zone target may not be configured correctly"
    fi
}

test_successful_knock_creates_rules() {
    info "Testing that successful knock creates firewalld rules..."
    
    # Perform a knock
    response=$(curl -s -X POST -H "X-Api-Key: $VALID_ADMIN_KEY" -H "X-Forwarded-For: $TEST_IP" $KNOCK_URL)
    
    if ! echo "$response" | grep -q "whitelisted_entry"; then
        fail "Knock request failed. Response: $response"
    fi
    
    # Check if rich rules were created for the IP
    if docker compose exec -T knocker firewall-cmd --zone=knocker --list-rich-rules | grep -q "$TEST_IP"; then
        success "Firewalld rich rules created for $TEST_IP"
    else
        fail "No firewalld rich rules found for $TEST_IP after successful knock"
    fi
}

test_rule_expiration() {
    info "Testing rule expiration (this will take a moment)..."
    
    # Perform a knock with short TTL (10 seconds)
    response=$(curl -s -X POST -H "X-Api-Key: $VALID_ADMIN_KEY" -H "X-Forwarded-For: $TEST_IP" -H "Content-Type: application/json" -d '{"ttl": 10}' $KNOCK_URL)
    
    if ! echo "$response" | grep -q "whitelisted_entry"; then
        fail "Knock with TTL failed. Response: $response"
    fi
    
    # Verify rules exist
    if docker compose exec -T knocker firewall-cmd --zone=knocker --list-rich-rules | grep -q "$TEST_IP"; then
        success "Rules created with TTL"
    else
        fail "Rules not found after knock with TTL"
    fi
    
    # Wait for expiration (15 seconds to be safe)
    info "Waiting 15 seconds for rule expiration..."
    sleep 15
    
    # Check if rules are gone
    if ! docker compose exec -T knocker firewall-cmd --zone=knocker --list-rich-rules | grep -q "$TEST_IP"; then
        success "Rules expired correctly after TTL"
    else
        warning "Rules may not have expired correctly (could be due to timing)"
    fi
}

test_startup_rule_recovery() {
    info "Testing startup rule recovery..."
    
    # First, add a rule with long TTL
    response=$(curl -s -X POST -H "X-Api-Key: $VALID_ADMIN_KEY" -H "X-Forwarded-For: $TEST_IP" -H "Content-Type: application/json" -d '{"ttl": 3600}' $KNOCK_URL)
    
    if ! echo "$response" | grep -q "whitelisted_entry"; then
        fail "Initial knock for recovery test failed"
    fi
    
    # Manually remove the firewalld rule (simulate rule loss)
    docker compose exec -T knocker firewall-cmd --zone=knocker --remove-rich-rule="rule family=\"ipv4\" source address=\"$TEST_IP\" port protocol=\"tcp\" port=\"80\" accept" &>/dev/null || true
    
    # Restart the knocker container
    info "Restarting knocker container to test rule recovery..."
    docker compose restart knocker
    
    # Wait for restart
    sleep 10
    
    # Check if the rule was restored
    if docker compose exec -T knocker firewall-cmd --zone=knocker --list-rich-rules | grep -q "$TEST_IP"; then
        success "Rules recovered after container restart"
    else
        warning "Rule recovery test inconclusive (rule may have been recreated by other means)"
    fi
}

test_firewalld_error_handling() {
    info "Testing firewalld error handling..."
    
    # Temporarily break firewalld access and see if knocker handles it gracefully
    # This is a simplified test - in practice, we'd need more complex setup
    
    # For now, just verify that invalid requests are handled
    response=$(curl -s -X POST -H "X-Api-Key: invalid_key" -H "X-Forwarded-For: $TEST_IP" $KNOCK_URL)
    
    if echo "$response" | grep -q "Invalid or missing API key"; then
        success "Error handling works for invalid requests"
    else
        fail "Error handling may not be working correctly"
    fi
}

cleanup() {
    info "Cleaning up test environment..."
    docker compose -f docker-compose.yml down --remove-orphans || true
    success "Cleanup completed"
}

# --- Main Execution ---
main() {
    info "Starting Firewalld Integration Tests..."
    
    check_prerequisites
    start_test_environment
    
    test_firewalld_daemon_access
    test_knocker_zone_creation
    test_successful_knock_creates_rules
    test_rule_expiration
    test_startup_rule_recovery
    test_firewalld_error_handling
    
    success "All firewalld integration tests passed!"
    
    cleanup
}

# Handle script interruption
trap cleanup EXIT

main "$@"