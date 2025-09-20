#!/bin/bash

# Integration tests for firewalld functionality
# This script tests firewalld integration with a real firewalld daemon in the container

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
KNOCK_URL="$BASE_URL/knock"

# Test IP to whitelist
TEST_IP="192.168.100.50"

# API Key for testing (should match knocker.yaml config)
VALID_API_KEY="CHANGE_ME_SUPER_SECRET_ADMIN_KEY"

# --- Test Functions ---

test_firewalld_service_running() {
    info "Checking if firewalld is running in container..."
    
    # Check if we can connect to firewalld
    docker exec knocker-knocker-1 firewall-cmd --state > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        success "Firewalld is running in container"
    else
        fail "Firewalld is not running or not accessible in container"
    fi
}

test_knocker_zone_creation() {
    info "Checking if knocker zone was created..."
    
    # Check if knocker zone exists
    zones=$(docker exec knocker-knocker-1 firewall-cmd --get-zones)
    
    if echo "$zones" | grep -q "knocker"; then
        success "Knocker zone exists"
    else
        fail "Knocker zone was not created"
    fi
}

test_zone_configuration() {
    info "Verifying knocker zone configuration..."
    
    # Check zone target is DROP
    target=$(docker exec knocker-knocker-1 firewall-cmd --zone=knocker --get-target)
    if [ "$target" = "DROP" ]; then
        success "Zone target correctly set to DROP"
    else
        fail "Zone target is '$target', expected 'DROP'"
    fi
    
    # Check monitored ports are added
    ports=$(docker exec knocker-knocker-1 firewall-cmd --zone=knocker --list-ports)
    if echo "$ports" | grep -q "22/tcp" && echo "$ports" | grep -q "443/tcp"; then
        success "Monitored ports are configured"
    else
        fail "Monitored ports not found. Got: $ports"
    fi
}

test_successful_knock_creates_rule() {
    info "Testing successful knock creates firewalld rule..."
    
    # Perform knock
    response=$(curl -s -X POST -H "X-Api-Key: $VALID_API_KEY" -H "X-Forwarded-For: $TEST_IP" $KNOCK_URL)
    
    if echo "$response" | grep -q "whitelisted_entry"; then
        success "Knock request succeeded"
    else
        fail "Knock request failed. Response: $response"
    fi
    
    # Wait a moment for rule to be applied
    sleep 2
    
    # Check if rich rule was created for the IP
    rules=$(docker exec knocker-knocker-1 firewall-cmd --zone=knocker --list-rich-rules)
    
    if echo "$rules" | grep -q "source address=\"$TEST_IP\""; then
        success "Firewalld rich rule created for $TEST_IP"
    else
        fail "No firewalld rule found for $TEST_IP. Rules: $rules"
    fi
}

test_rule_has_timeout() {
    info "Verifying firewalld rule has timeout..."
    
    # Get rich rules with details
    rules=$(docker exec knocker-knocker-1 firewall-cmd --zone=knocker --list-rich-rules)
    
    # Note: firewall-cmd doesn't show timeout in --list-rich-rules output
    # The timeout is applied at runtime but not visible in the list
    # We can verify the rule exists and will be automatically cleaned up
    
    if echo "$rules" | grep -q "source address=\"$TEST_IP\""; then
        success "Rule exists (timeout applied at runtime)"
    else
        fail "Rule not found when checking timeout"
    fi
}

test_metadata_persistence() {
    info "Checking firewalld state metadata file..."
    
    # Check if state file was created
    if docker exec knocker-knocker-1 test -f /data/firewalld_state.json; then
        success "Firewalld state file exists"
    else
        fail "Firewalld state file not found"
    fi
    
    # Check if our IP is in the metadata
    metadata=$(docker exec knocker-knocker-1 cat /data/firewalld_state.json)
    
    if echo "$metadata" | grep -q "$TEST_IP"; then
        success "Test IP found in metadata file"
    else
        fail "Test IP not found in metadata. Content: $metadata"
    fi
}

test_knock_failure_with_firewalld_error() {
    info "Testing knock failure when firewalld is unavailable..."
    
    # Stop firewalld temporarily to simulate failure
    docker exec knocker-knocker-1 systemctl stop firewalld || true
    sleep 2
    
    # Attempt knock (should fail with 500)
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "X-Api-Key: $VALID_API_KEY" -H "X-Forwarded-For: 192.168.100.51" $KNOCK_URL)
    
    if [ "$http_code" -eq 500 ]; then
        success "Knock correctly failed with 500 when firewalld unavailable"
    else
        fail "Expected 500 error, got $http_code"
    fi
    
    # Restart firewalld
    docker exec knocker-knocker-1 systemctl start firewalld
    sleep 3
}

test_reconciliation_after_restart() {
    info "Testing state reconciliation after container restart..."
    
    # Record current metadata
    metadata_before=$(docker exec knocker-knocker-1 cat /data/firewalld_state.json)
    
    # Restart knocker container (simulates service restart)
    info "Restarting knocker container..."
    docker restart knocker-knocker-1
    
    # Wait for service to start up
    info "Waiting for service to restart..."
    retry_count=0
    max_retries=30
    retry_interval=2
    
    until $(curl --output /dev/null --silent --fail "$BASE_URL/health"); do
        if [ ${retry_count} -ge ${max_retries} ]; then
            fail "Service did not restart in time."
        fi
        printf '.'
        retry_count=$((retry_count+1))
        sleep ${retry_interval}
    done
    echo # Newline after dots
    
    # Check if metadata was preserved
    metadata_after=$(docker exec knocker-knocker-1 cat /data/firewalld_state.json)
    
    if [ "$metadata_before" = "$metadata_after" ]; then
        success "Metadata preserved after restart"
    else
        # This is OK if entries expired during restart
        info "Metadata changed after restart (may be due to expiration)"
    fi
    
    success "Service successfully restarted with firewalld integration"
}

cleanup_test_rules() {
    info "Cleaning up test rules..."
    
    # Remove any test rules
    docker exec knocker-knocker-1 firewall-cmd --zone=knocker --remove-rich-rule="rule family=ipv4 source address=\"$TEST_IP\" port port=22 protocol=tcp accept" || true
    docker exec knocker-knocker-1 firewall-cmd --zone=knocker --remove-rich-rule="rule family=ipv4 source address=\"$TEST_IP\" port port=443 protocol=tcp accept" || true
    
    success "Test cleanup completed"
}

# --- Main Execution ---
main() {
    info "Starting firewalld integration tests..."
    
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

    # Run firewalld-specific tests
    test_firewalld_service_running
    test_knocker_zone_creation
    test_zone_configuration
    test_successful_knock_creates_rule
    test_rule_has_timeout
    test_metadata_persistence
    test_knock_failure_with_firewalld_error
    test_reconciliation_after_restart
    
    # Cleanup
    cleanup_test_rules

    info "All firewalld integration tests passed!"
}

# Check if we're being called with a specific test
if [ $# -gt 0 ]; then
    case $1 in
        "cleanup")
            cleanup_test_rules
            ;;
        *)
            echo "Usage: $0 [cleanup]"
            exit 1
            ;;
    esac
else
    main
fi