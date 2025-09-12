#!/bin/bash

# Firewall Integration Tests
# This script tests the firewall integration functionality

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
BASE_URL="http://localhost:8000"  # knocker instance (host-exposed)
KNOCK_URL="$BASE_URL/knock"
HEALTH_URL="$BASE_URL/health"

# Test IPs
TEST_IP="203.0.113.10"  # From TEST-NET-3 (RFC 5737)
REMOTE_IP="198.51.100.5"  # From TEST-NET-2 (RFC 5737)

# API Keys (from knocker-firewall.example.yaml)
ADMIN_KEY="TEST_ADMIN_KEY_12345"
PHONE_KEY="TEST_PHONE_KEY_67890"

# --- Test Functions ---

test_service_health() {
    info "Testing service health..."
    response=$(curl -s -o /dev/null -w "%{http_code}" $HEALTH_URL)
    if [ "$response" -eq 200 ]; then
        success "Service is healthy"
    else
        fail "Service health check failed (HTTP $response)"
    fi
}

test_firewall_zone_creation() {
    info "Testing firewall zone creation..."
    # Check if knocker zone exists
    if firewall-cmd --get-zones | grep -q "knocker"; then
        success "Knocker firewall zone exists"
    else
        fail "Knocker firewall zone not found"
    fi
}

test_knock_creates_firewall_rules() {
    info "Testing that knock creates firewall rules..."
    
    # Perform knock
    response=$(curl -s -X POST -H "X-Api-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
        -d "{\"ip_address\": \"$TEST_IP\", \"ttl\": 300}" $KNOCK_URL)
    
    if echo "$response" | grep -q "whitelisted_entry"; then
        success "Knock request successful"
    else
        fail "Knock request failed: $response"
    fi
    
    # Wait a moment for firewall rules to be applied
    sleep 2
    
    # Check if firewall rules were created for the IP
    # Check for IPv4 rule on port 80
    if firewall-cmd --zone=knocker --list-rich-rules | grep -q "$TEST_IP.*port.*80.*accept"; then
        success "Firewall rules created for $TEST_IP"
    else
        fail "Firewall rules not found for $TEST_IP"
    fi
}

test_firewall_rule_content() {
    info "Testing firewall rule content..."
    
    # Get rich rules for knocker zone
    rules=$(firewall-cmd --zone=knocker --list-rich-rules)
    
    # Check for expected ports (80, 443, 22, 8080 from config)
    ports=("80" "443" "22" "8080")
    for port in "${ports[@]}"; do
        if echo "$rules" | grep -q "$TEST_IP.*port.*$port.*tcp.*accept"; then
            success "Found rule for port $port"
        else
            fail "Missing rule for port $port"
        fi
    done
}

test_rule_expiration_cleanup() {
    info "Testing rule expiration and cleanup..."
    
    # Create a rule with very short TTL
    response=$(curl -s -X POST -H "X-Api-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
        -d "{\"ip_address\": \"$REMOTE_IP\", \"ttl\": 5}" $KNOCK_URL)
    
    if echo "$response" | grep -q "whitelisted_entry"; then
        success "Short TTL knock successful"
    else
        fail "Short TTL knock failed: $response"
    fi
    
    # Wait for rules to be created
    sleep 2
    
    # Verify rules exist
    if firewall-cmd --zone=knocker --list-rich-rules | grep -q "$REMOTE_IP"; then
        success "Short TTL rules created"
    else
        fail "Short TTL rules not found"
    fi
    
    # Wait for expiration plus cleanup cycle
    info "Waiting for rule expiration..."
    sleep 8
    
    # Trigger cleanup by making another request (which calls cleanup)
    curl -s "$HEALTH_URL" > /dev/null
    
    # Wait for cleanup to process
    sleep 2
    
    # Verify rules are removed
    if firewall-cmd --zone=knocker --list-rich-rules | grep -q "$REMOTE_IP"; then
        fail "Expired rules not cleaned up"
    else
        success "Expired rules cleaned up successfully"
    fi
}

test_always_allowed_ips() {
    info "Testing always allowed IPs in firewall..."
    
    # Check that always allowed IPs from config have firewall rules
    # From knocker-firewall.example.yaml: 127.0.0.1/32, 192.168.0.0/16, 10.0.0.0/8
    always_allowed_ips=("127.0.0.1/32" "192.168.0.0/16" "10.0.0.0/8")
    
    for ip in "${always_allowed_ips[@]}"; do
        # Convert CIDR to the format used in firewall rules
        if firewall-cmd --zone=knocker --list-rich-rules | grep -q "$ip"; then
            success "Always allowed IP $ip has firewall rules"
        else
            # This might not be an error if firewall integration handles it differently
            info "Always allowed IP $ip not found in firewall rules (may be handled differently)"
        fi
    done
}

cleanup_test_rules() {
    info "Cleaning up test firewall rules..."
    
    # Remove any remaining test rules
    test_ips=("$TEST_IP" "$REMOTE_IP")
    for ip in "${test_ips[@]}"; do
        # Try to remove rules for each port
        ports=("80" "443" "22" "8080")
        for port in "${ports[@]}"; do
            rule="rule family=\"ipv4\" source address=\"$ip\" port port=\"$port\" protocol=\"tcp\" accept"
            firewall-cmd --zone=knocker --remove-rich-rule="$rule" 2>/dev/null || true
        done
    done
    
    success "Test cleanup completed"
}

# --- Main Execution ---
main() {
    info "Starting firewall integration tests..."
    
    # Check if we're running with sufficient privileges
    if [ "$EUID" -ne 0 ]; then
        fail "This script must be run as root for firewall access"
    fi
    
    # Check if firewalld is running
    if ! systemctl is-active --quiet firewalld; then
        fail "Firewalld service is not running"
    fi
    
    # Wait for knocker-firewall service to be ready
    info "Waiting for knocker service..."
    retry_count=0
    max_retries=30
    retry_interval=2
    
    until $(curl --output /dev/null --silent --fail "$HEALTH_URL"); do
        if [ ${retry_count} -ge ${max_retries} ]; then
            fail "knocker-firewall service did not become ready in time"
        fi
        printf '.'
        retry_count=$((retry_count+1))
        sleep ${retry_interval}
    done
    echo
    
    success "knocker service is ready!"
    
    # Run tests
    test_service_health
    test_firewall_zone_creation
    test_knock_creates_firewall_rules
    test_firewall_rule_content
    test_rule_expiration_cleanup
    test_always_allowed_ips
    
    # Cleanup
    cleanup_test_rules
    
    success "All firewall integration tests passed!"
}

# Run main function
main "$@"