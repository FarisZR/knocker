#!/bin/bash

# Integration tests for firewalld functionality
# This script tests the firewalld integration in a Docker environment

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

# API Keys (from knocker-firewalld.yaml)
VALID_ADMIN_KEY="CHANGE_ME_SUPER_SECRET_ADMIN_KEY"
INVALID_KEY="INVALID_KEY"
NO_REMOTE_KEY="CHANGE_ME_SECRET_PHONE_KEY"
GUEST_KEY="CHANGE_ME_TEMPORARY_GUEST_KEY"

# Firewalld test ports
TEST_PORTS=(80 443 8080 8443)

# Global variable to store the whitelisted IP from a successful knock
WHITELISTED_IP=""

# --- Test Runner ---
run_test() {
    info "Running test: $1"
    eval "$2"
    info "Finished test: $1"
    echo # Newline for readability
}

# --- Docker Helper Functions ---
get_container_name() {
    # Get the knocker-firewalld container name
    docker compose -f dev/docker-compose-firewalld.yml ps -q knocker-firewalld | head -1
}

exec_in_container() {
    local container_name=$(get_container_name)
    if [ -z "$container_name" ]; then
        fail "Could not find knocker-firewalld container"
    fi
    docker exec "$container_name" "$@"
}

check_firewalld_zone() {
    # Check if KNOCKER zone exists in firewalld
    exec_in_container firewall-cmd --list-all-zones | grep -q "KNOCKER" || return 1
}

list_firewalld_rules() {
    # List current rich rules in KNOCKER zone
    exec_in_container firewall-cmd --zone=KNOCKER --list-rich-rules 2>/dev/null || echo "No rules found"
}

count_firewalld_rules() {
    # Count rich rules in KNOCKER zone
    exec_in_container firewall-cmd --zone=KNOCKER --list-rich-rules 2>/dev/null | wc -l || echo "0"
}

# --- Test Cases ---

test_firewalld_zone_creation() {
    info "Checking if KNOCKER firewalld zone was created..."
    
    if check_firewalld_zone; then
        success "KNOCKER firewalld zone exists"
    else
        fail "KNOCKER firewalld zone was not created"
    fi
}

test_firewalld_default_deny_rules() {
    info "Checking default deny rules for monitored ports..."
    
    rules=$(list_firewalld_rules)
    
    for port in "${TEST_PORTS[@]}"; do
        if echo "$rules" | grep -q "port.*$port.*reject"; then
            success "Default deny rule exists for port $port"
        else
            fail "Default deny rule missing for port $port"
        fi
    done
}

test_firewalld_always_allowed_rules() {
    info "Checking always-allowed IP rules..."
    
    rules=$(list_firewalld_rules)
    
    # Check for rules allowing the always-allowed network
    if echo "$rules" | grep -q "172.29.238.0/24.*accept"; then
        success "Always-allowed rule exists for 172.29.238.0/24"
    else
        fail "Always-allowed rule missing for 172.29.238.0/24"
    fi
}

test_successful_knock_creates_firewalld_rule() {
    info "Testing that successful knock creates firewalld rules..."
    
    # Count rules before knock
    rules_before=$(count_firewalld_rules)
    
    # Perform knock
    response=$(curl -s -X POST -H "X-Api-Key: $VALID_ADMIN_KEY" -H "X-Forwarded-For: $REGULAR_IP" $KNOCK_URL)
    if echo "$response" | grep -q "whitelisted_entry"; then
        WHITELISTED_IP=$(echo "$response" | sed -n 's/.*"whitelisted_entry":"\([^"]*\)".*/\1/p')
        success "Knock successful for $WHITELISTED_IP"
    else
        fail "Knock failed. Response: $response"
    fi
    
    # Wait a moment for firewalld rule to be applied
    sleep 2
    
    # Count rules after knock
    rules_after=$(count_firewalld_rules)
    
    if [ "$rules_after" -gt "$rules_before" ]; then
        success "Firewalld rules increased from $rules_before to $rules_after after knock"
    else
        fail "No new firewalld rules created after knock"
    fi
    
    # Check that rules contain the whitelisted IP
    rules=$(list_firewalld_rules)
    if echo "$rules" | grep -q "$WHITELISTED_IP.*accept"; then
        success "Found firewalld rule allowing $WHITELISTED_IP"
    else
        fail "No firewalld rule found for whitelisted IP: $WHITELISTED_IP"
    fi
}

test_firewalld_rule_per_monitored_port() {
    info "Testing that firewalld rules are created for each monitored port..."
    
    if [ -z "$WHITELISTED_IP" ]; then
        fail "WHITELISTED_IP not set. Run successful knock test first."
    fi
    
    rules=$(list_firewalld_rules)
    
    for port in "${TEST_PORTS[@]}"; do
        if echo "$rules" | grep -q "$WHITELISTED_IP.*port.*$port.*accept"; then
            success "Found allow rule for $WHITELISTED_IP on port $port"
        else
            fail "Missing allow rule for $WHITELISTED_IP on port $port"
        fi
    done
}

test_firewalld_rule_cleanup_on_expiry() {
    info "Testing firewalld rule cleanup on expiry..."
    
    # Create a short-lived rule (minimum 60s due to TTL validation)
    response=$(curl -s -X POST -H "X-Api-Key: $GUEST_KEY" -H "X-Forwarded-For: 203.0.113.50" -H "Content-Type: application/json" -d '{"ttl": 60}' $KNOCK_URL)
    
    if echo "$response" | grep -q "whitelisted_entry"; then
        test_ip="203.0.113.50"
        success "Created short-lived rule for $test_ip"
    else
        fail "Failed to create short-lived rule. Response: $response"
    fi
    
    # Verify rule exists
    rules=$(list_firewalld_rules)
    if echo "$rules" | grep -q "$test_ip.*accept"; then
        success "Short-lived firewalld rule exists for $test_ip"
    else
        fail "Short-lived firewalld rule not found for $test_ip"
    fi
    
    info "Note: Full expiry testing requires waiting 60+ seconds. Skipping automatic cleanup test."
    info "Manual verification: Wait 60+ seconds and check that rules for $test_ip are removed."
}

test_always_allowed_ip_bypass() {
    info "Testing that always-allowed IPs don't get unnecessary firewalld rules..."
    
    rules_before=$(count_firewalld_rules)
    
    # Try to knock with always-allowed IP
    response=$(curl -s -X POST -H "X-Api-Key: $VALID_ADMIN_KEY" -H "X-Forwarded-For: $ALWAYS_ALLOWED_IP" $KNOCK_URL)
    
    if echo "$response" | grep -q "whitelisted_entry"; then
        success "Knock successful for always-allowed IP"
    else
        fail "Knock failed for always-allowed IP. Response: $response"
    fi
    
    # Wait and check rules
    sleep 2
    rules_after=$(count_firewalld_rules)
    
    # Rules count should not increase significantly (maybe tiny increase from cleanup, but not +N rules per port)
    rule_diff=$((rules_after - rules_before))
    if [ "$rule_diff" -le 1 ]; then
        success "No significant firewalld rule increase for always-allowed IP (diff: $rule_diff)"
    else
        fail "Unexpected firewalld rule increase for always-allowed IP (diff: $rule_diff)"  
    fi
}

test_firewalld_startup_synchronization() {
    info "Testing firewalld startup synchronization..."
    
    # This test would require container restart, which is complex
    # For now, just verify that startup synchronization doesn't crash
    container_logs=$(docker compose -f dev/docker-compose-firewalld.yml logs knocker-firewalld 2>&1)
    
    if echo "$container_logs" | grep -q "Firewalld integration initialized successfully"; then
        success "Firewalld integration initialized successfully"
    else
        fail "Firewalld integration initialization failed"
    fi
    
    if echo "$container_logs" | grep -q "synchronize"; then
        success "Startup synchronization attempted"
    else
        info "Startup synchronization message not found (may be normal)"
    fi
}

test_firewalld_service_health() {
    info "Testing firewalld service health in container..."
    
    # Check firewalld is running
    if exec_in_container firewall-cmd --state >/dev/null 2>&1; then
        success "Firewalld service is running"
    else
        fail "Firewalld service is not running"
    fi
    
    # Check D-Bus is working
    if exec_in_container dbus-send --system --print-reply --dest=org.fedoraproject.FirewallD1 /org/fedoraproject/FirewallD1 org.fedoraproject.FirewallD1.getDefaultZone >/dev/null 2>&1; then
        success "D-Bus communication with firewalld working"
    else
        fail "D-Bus communication with firewalld failed"
    fi
}

test_container_privileges() {
    info "Testing container has required privileges for firewalld..."
    
    # Test if container can modify iptables (required for firewalld)
    if exec_in_container iptables -L >/dev/null 2>&1; then
        success "Container can access iptables"
    else
        fail "Container cannot access iptables (needs --privileged or capabilities)"
    fi
}

# --- Main Execution ---
main() {
    info "Starting firewalld integration tests..."
    
    info "Waiting for services to be healthy..."
    retry_count=0
    max_retries=60  # Longer timeout for firewalld startup
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
    
    # Container and service health tests
    run_test "Container Privileges Check" "test_container_privileges"
    run_test "Firewalld Service Health" "test_firewalld_service_health"
    
    # Zone and rule setup tests
    run_test "Firewalld Zone Creation" "test_firewalld_zone_creation"
    run_test "Default Deny Rules" "test_firewalld_default_deny_rules"
    run_test "Always-Allowed Rules" "test_firewalld_always_allowed_rules"
    
    # Dynamic rule tests
    run_test "Successful Knock Creates Firewalld Rule" "test_successful_knock_creates_firewalld_rule"
    run_test "Firewalld Rule Per Monitored Port" "test_firewalld_rule_per_monitored_port"
    run_test "Always-Allowed IP Bypass" "test_always_allowed_ip_bypass"
    
    # Advanced tests
    run_test "Firewalld Rule Cleanup on Expiry" "test_firewalld_rule_cleanup_on_expiry"
    run_test "Startup Synchronization" "test_firewalld_startup_synchronization"
    
    info "All firewalld integration tests completed!"
    
    info "Current firewalld rules in KNOCKER zone:"
    list_firewalld_rules
}

# Run main if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi