# Firewalld Integration

Knocker provides advanced firewall integration through firewalld, allowing for dynamic, time-based firewall rule management. This feature creates timed rules that automatically expire based on the TTL specified in knock requests.

## Overview

The firewalld integration works by:

1. **Creating a dedicated firewalld zone** with configurable priority (default: high priority)
2. **Adding specific DROP rules** for monitored ports with low priority (9999)
3. **Adding ALLOW rules dynamically** for whitelisted IPs with high priority (1000) that override DROP rules
4. **Recovering missing rules on startup** by comparing whitelist.json with active firewalld rules
5. **Providing comprehensive error handling** with detailed logging and HTTP 500 responses on failures

This approach ensures that only monitored ports are affected by the firewall rules, while unmonitored ports remain unaffected.

## Configuration

Add the following section to your `knocker.yaml` configuration file:

```yaml
firewalld:
  enabled: true  # Set to true to enable firewalld integration
  zone_name: "knocker"  # Name of the firewalld zone to create
  zone_priority: -100  # Zone priority (negative numbers = higher priority)
  monitored_ports:
    # Ports that will be protected by knocker firewall rules
    # Only whitelisted IPs will be able to access these ports
    - port: 80
      protocol: tcp
    - port: 443
      protocol: tcp
    - port: 22
      protocol: tcp
  monitored_ips:
    # IP ranges that the firewalld zone will apply to
    # MUST include network mask (e.g., /32 for single IPv4 host, /128 for single IPv6 host)
    # Use 0.0.0.0/0 for all IPv4, ::/0 for all IPv6
    - "0.0.0.0/0"
    - "::/0"
```

### Configuration Options

- **`enabled`**: Boolean flag to enable/disable firewalld integration
- **`zone_name`**: Name of the firewalld zone to create (default: "knocker")
- **`zone_priority`**: Priority of the zone (negative numbers = higher priority, default: -100)
- **`default_action`**: Action for blocked traffic - "drop" (silent discard) or "reject" (connection refused with response) (default: "drop")
- **`monitored_ports`**: List of port/protocol combinations to protect
- **`monitored_ips`**: List of IP ranges the zone will apply to (**must include network mask**)

### ⚠️ Important: Network Mask Requirements

All IP addresses in `monitored_ips` **must include proper CIDR notation**:

- **IPv4**: Use `/32` for single hosts (e.g., `192.168.1.100/32`) or appropriate subnet mask
- **IPv6**: Use `/128` for single hosts (e.g., `2001:db8::1/128`) or appropriate prefix length

**Examples:**
```yaml
monitored_ips:
  - "192.168.1.100/32"    # Single IPv4 host
  - "192.168.1.0/24"      # IPv4 subnet
  - "2001:db8::1/128"     # Single IPv6 host
  - "2001:db8::/32"       # IPv6 prefix
  - "0.0.0.0/0"           # All IPv4 addresses
  - "::/0"                # All IPv6 addresses
```

The application will validate these requirements at startup and refuse to start with invalid CIDR notation.

## Docker Configuration

When firewalld integration is enabled, the knocker container **must run as root** to access the system dbus.

### Required Docker Configuration

1. **Run as root user**:
   ```yaml
   services:
     knocker:
       user: "0:0"  # Run as root
   ```

2. **Mount system dbus**:
   ```yaml
   services:
     knocker:
       volumes:
         - /var/run/dbus/system_bus_socket:/var/run/dbus/system_bus_socket:ro
   ```

3. **Add network capabilities**:
   ```yaml
   services:
     knocker:
       cap_add:
         - NET_ADMIN
   ```

### Complete Docker Compose Example

```yaml
version: '3.8'

services:
  knocker:
    image: your-knocker-image
    user: "0:0"  # Required for firewalld access
    cap_add:
      - NET_ADMIN
    volumes:
      - ./knocker.yaml:/app/knocker.yaml:ro
      - knocker_data:/data
      - /var/run/dbus/system_bus_socket:/var/run/dbus/system_bus_socket:ro
    environment:
      - KNOCKER_CONFIG_PATH=/app/knocker.yaml
    networks:
      - app_network

volumes:
  knocker_data:

networks:
  app_network:
```

## How It Works

### Zone Creation

On startup, knocker creates a firewalld zone with the following properties:

- **Name**: Configurable (default: "knocker")
- **Priority**: Configurable (default: -100, negative numbers = higher priority)
- **Target**: Default (not DROP) - only specific ports are affected
- **Sources**: Configured IP ranges from `monitored_ips`

### Port-Specific Rules Configuration

For each monitored port, knocker creates blocking rules with low priority (9999) for both IPv4 and IPv6:

**DROP Rules (Silent Discard)**:
```
rule family="ipv4" port protocol="tcp" port="80" drop priority="9999"
rule family="ipv6" port protocol="tcp" port="80" drop priority="9999"
```

**REJECT Rules (Connection Refused with Response)**:
```
rule family="ipv4" port protocol="tcp" port="80" reject priority="9999"
rule family="ipv6" port protocol="tcp" port="80" reject priority="9999"
```

The action is configurable via the `default_action` setting:
- **`drop`** (default): Silently discards packets - attackers don't know if service exists
- **`reject`**: Actively refuses connection - faster for legitimate clients but reveals service existence

This ensures only monitored ports are blocked, leaving other ports unaffected.

### Dynamic ALLOW Rule Creation

When a successful knock request is made:

1. **Firewalld ALLOW rules are added first** using rich rules with high priority (1000) and timeout
2. **Only after firewalld success** is `whitelist.json` updated
3. **On firewalld failure**, the request returns HTTP 500 and `whitelist.json` is not modified

Example rich rule created for whitelisting:
```
rule family="ipv4" source address="192.168.1.100" port protocol="tcp" port="80" accept priority="1000"
```

The high priority (1000) ensures these ALLOW rules override the low priority blocking rules (9999).

### Rule Priority System

Firewalld uses priority numbers where **lower numbers = higher priority**:

- **Priority 1000**: Whitelist ALLOW rules (high priority)
- **Priority 9999**: Default blocking rules (low priority) - either DROP or REJECT based on `default_action`

This ensures whitelisted IPs can access monitored ports while blocked IPs cannot.

### Rule Expiration

Rules automatically expire based on:
 
- **TTL from knock request** (if specified and within API key limits)
- **API key max_ttl** (if no TTL specified or TTL exceeds limit)
- **Firewalld timeout mechanism** handles automatic rule removal

### TTL replacement on existing rules (collision handling)

When adding a rich rule, firewalld may return a success-with-warning indicating the rule is already present (for example: "Warning: ALREADY_ENABLED: 'rule ...' already in 'knocker'"). Because firewalld's CLI reports success even when it does not update an existing rule's timeout, Knocker explicitly detects these warning messages (e.g. "ALREADY_ENABLED" or "already in") and will remove the existing rich rule and re-add it with the requested timeout. This ensures that a new, shorter TTL can replace a previously created longer TTL. Note that this behavior generates transient log warnings and may briefly remove the rule before re-adding it.

### Startup Recovery

On container startup, knocker:

1. **Loads existing whitelist** from `whitelist.json`
2. **Queries active firewalld rules** in the knocker zone
3. **Compares and identifies missing rules** for non-expired whitelist entries
4. **Restores missing rules** with remaining TTL

This ensures rules are preserved across:
- Container restarts
- Firewalld daemon restarts
- System reboots

## Security Considerations

### Running as Root

The firewalld integration requires the container to run as root for dbus system access. This introduces security considerations:

**Risks:**
- Increased attack surface if container is compromised
- Potential for privilege escalation
- Access to host system dbus

**Mitigations:**
1. **Enable firewalld only when necessary**
2. **Use read-only filesystem** where possible
3. **Limit container capabilities** to only what's needed
4. **Monitor container activity** for suspicious behavior
5. **Keep firewalld and container updated**
6. **Use network segmentation** to limit blast radius

### Firewall Priority

The knocker zone is created with high priority to ensure it takes precedence over other firewalld zones. Verify this doesn't conflict with your security policies.

### Input Validation

All IP addresses and ports are validated before being passed to firewall-cmd. However, always ensure your `monitored_ips` configuration is secure.

## Error Handling

### Firewalld Failures

If firewalld operations fail:

1. **HTTP 500 response** is returned to the client
2. **Detailed error logged** with full context
3. **whitelist.json is NOT updated** to maintain consistency
4. **Subsequent requests can retry** the operation

### Common Issues and Solutions

**Issue**: Container cannot access firewalld
```
ERROR: Failed to setup firewalld zone - firewalld integration may not work properly
```
**Solution**: Ensure system dbus is mounted and container runs as root

**Issue**: Zone creation fails
```
ERROR: Failed to create zone knocker: ZONE_ALREADY_EXISTS
```
**Solution**: This is normal on restart - the zone already exists

**Issue**: Rich rule creation fails
```
ERROR: Failed to add firewalld rule for 192.168.1.100:80/tcp: INVALID_RULE
```
**Solution**: Check IP address format and firewalld configuration

## Monitoring and Logging

### Log Messages

Firewalld integration produces detailed logs:

```
INFO: Firewalld integration is enabled
INFO: Firewalld zone setup completed successfully
INFO: Added firewalld rule for 192.168.1.100:80/tcp
ERROR: Failed to add firewalld rules for 192.168.1.100. Request from 10.0.0.1 rejected.
```

### Monitoring Rules

Query active rules:
```bash
# List all zones
firewall-cmd --list-all-zones

# List knocker zone rules
firewall-cmd --zone=knocker --list-rich-rules

# Monitor rule changes
journalctl -u firewalld -f
```

### Health Checks

The `/health` endpoint can be used to verify the service is running, but it doesn't specifically check firewalld status. Consider adding monitoring for:

- Firewalld daemon status
- Knocker zone existence
- Rule count consistency

## Testing

### Unit Tests

Run the comprehensive firewalld test suite:

```bash
PYTHONPATH=src python3 -m pytest tests/test_firewalld.py -v
```

### Integration Tests

Test with real firewalld daemon:

```bash
# Start test environment
cd dev/
./firewalld_integration_test.sh
```

### Manual Testing

1. **Enable firewalld integration** in configuration
2. **Start knocker with proper permissions**
3. **Perform knock request**
4. **Verify rules created**:
   ```bash
   firewall-cmd --zone=knocker --list-rich-rules
   ```
5. **Wait for expiration and verify cleanup**

## Troubleshooting

### Debug Mode

Enable debug logging in your configuration:

```yaml
logging:
  level: DEBUG
```

When the top-level logging level is set to DEBUG in your `knocker.yaml` (see `logging.level`), Knocker will log the exact executed `firewall-cmd` command at DEBUG level. This includes the full command and arguments (for example: `firewall-cmd --zone=knocker --add-rich-rule=... --timeout=...`). Use DEBUG logging with caution in production as it may expose IP addresses and rule details in logs.

### Common Commands

```bash
# Check firewalld status
systemctl status firewalld

# List all zones
firewall-cmd --list-all-zones

# Check knocker zone
firewall-cmd --zone=knocker --list-all

# Remove knocker zone (if needed)
firewall-cmd --permanent --delete-zone=knocker
firewall-cmd --reload

# Check dbus permissions
docker exec knocker-container firewall-cmd --state
```

### Performance Considerations

- **Rule creation**: Each knock creates N rules (where N = number of monitored ports)
- **Rule expiration**: Handled by firewalld's timeout mechanism
- **Startup recovery**: May take longer with many whitelist entries
- **Memory usage**: Proportional to number of active rules

## Best Practices

1. **Limit monitored ports** to only what's necessary
2. **Use appropriate TTL values** to balance security and usability
3. **Monitor firewalld logs** for anomalies
4. **Test backup/restore procedures** with firewalld integration
5. **Document firewall changes** for compliance
6. **Use network monitoring** to verify rule effectiveness

## Migration Guide

### Enabling on Existing Installation

1. **Update configuration** to include firewalld section
2. **Modify docker-compose.yml** for root access and dbus mount
3. **Restart containers** with new configuration
4. **Verify zone creation** and rule functionality
5. **Test knock operations** thoroughly

### Disabling Firewalld Integration

1. **Set `enabled: false`** in configuration
2. **Restart knocker** service
3. **Optionally remove knocker zone**:
   ```bash
   firewall-cmd --permanent --delete-zone=knocker
   firewall-cmd --reload
   ```
4. **Revert docker configuration** to non-root if desired

The firewalld integration is designed to be non-destructive and can be safely enabled/disabled as needed.