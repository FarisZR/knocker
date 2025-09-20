# Firewalld Integration

Knocker provides optional integration with firewalld to automatically manage firewall rules alongside IP whitelisting. When enabled, successful knocks will create runtime firewall rules that allow access to specified ports with automatic TTL-based expiration.

## Overview

The firewalld integration creates a dedicated firewalld zone (default: `knocker`) that:
- Defaults to DROP for all traffic to monitored ports
- Dynamically adds rich rules allowing specific IPs to access monitored ports
- Automatically removes rules when they expire (matching knock TTL)
- Reconciles state on startup to restore valid rules after service restarts
- Provides robust error handling and logging

## Architecture

```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐
│   Client    │    │   Knocker    │    │  firewalld   │
│             │    │   Service    │    │              │
└─────────────┘    └──────────────┘    └──────────────┘
       │                   │                   │
       │ POST /knock       │                   │
       ├──────────────────▶│                   │
       │                   │ 1. Validate       │
       │                   │ 2. Add firewall   │
       │                   │    rules          │
       │                   ├──────────────────▶│
       │                   │◀──────────────────┤
       │                   │ 3. Update         │
       │                   │    whitelist.json │
       │◀──────────────────┤    (only if #2    │
       │ 200 OK            │     succeeds)     │
       │                   │                   │
       
┌─────────────────┐
│ Background      │
│ Reconciliation  │
│ Thread          │
└─────────────────┘
       │ Every 30s (configurable)
       │ - Clean up expired rules
       │ - Restore missing valid rules
       │ - Update state metadata
```

## Configuration

Add the following section to your `knocker.yaml`:

```yaml
security:
  firewalld:
    # Enable firewalld integration
    enabled: true
    
    # Name of the firewalld zone to create and manage
    zone_name: "knocker"
    
    # List of ports to protect with firewalld rules
    # Format: "port/protocol" (e.g., "22/tcp", "443/udp")
    monitored_ports:
      - "22/tcp"
      - "443/tcp"
      - "80/tcp"
    
    # Optional: Restrict firewalld rules to specific source CIDRs
    # Empty list means allow rules for any IP (subject to knock validation)
    monitored_sources: []
    # Example with restrictions:
    # monitored_sources:
    #   - "10.0.0.0/8"
    #   - "192.168.0.0/16"
    
    # Path to store firewalld rule metadata for state persistence
    state_storage_path: "/data/firewalld_state.json"
    
    # Background reconciliation interval in seconds
    reconcile_interval_seconds: 30
    
    # Remove zone and rules when service shuts down
    # Useful for development/testing environments
    cleanup_on_exit: true
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable firewalld integration |
| `zone_name` | string | `"knocker"` | Firewalld zone name to create/manage |
| `monitored_ports` | list | `[]` | Ports to protect (max 200) |
| `monitored_sources` | list | `[]` | Optional CIDR restrictions |
| `state_storage_path` | string | `/data/firewalld_state.json` | State metadata file path |
| `reconcile_interval_seconds` | integer | `30` | Background cleanup interval |
| `cleanup_on_exit` | boolean | `true` | Clean up on service shutdown |

## Lifecycle

### Startup

1. **Zone Creation**: Creates dedicated firewalld zone if it doesn't exist
2. **Zone Configuration**: Sets zone target to DROP and adds monitored ports
3. **State Reconciliation**: Restores any valid rules that were lost during restart
4. **Background Thread**: Starts reconciliation thread for ongoing maintenance

### Knock Processing

1. **API Validation**: Standard knock validation (API key, IP, TTL, etc.)
2. **Firewalld Rule Addition**: Attempts to add rich rules for all monitored ports
3. **State Update**: Only updates `whitelist.json` if firewalld succeeds
4. **Error Handling**: Returns HTTP 500 if firewalld fails (no whitelist update)

### Background Maintenance

- **Periodic Cleanup**: Removes expired rules from metadata every 30s (configurable)
- **Rule Reconciliation**: Restores missing rules that are still valid
- **State Persistence**: Maintains metadata file for crash recovery

### Shutdown

- **Optional Cleanup**: Removes zone and all rules if `cleanup_on_exit: true`
- **Graceful Termination**: Stops background threads cleanly

## Security Considerations

### Container Requirements

**Root Privileges**: The container must run as root when firewalld integration is enabled because:
- Firewalld requires root access to modify iptables/nftables rules
- D-Bus system bus access needs elevated permissions  
- Zone creation and rule management are privileged operations

**D-Bus Access**: Container needs access to host D-Bus socket:
```yaml
volumes:
  - /var/run/dbus:/var/run/dbus:ro
```

### Network Security

**IP Spoofing**: Same considerations as standard knocker deployment
- Ensure `trusted_proxies` is properly configured
- Firewalld rules use the same IP validation as whitelist

**Rule Scope**: Firewalld rules are scoped to:
- Specific source IP/CIDR (from knock request)
- Specific destination ports (from `monitored_ports` config)
- Automatic TTL expiration (matches knock TTL)

### Access Control

**Monitored Sources**: Optional additional restriction layer
```yaml
monitored_sources:
  - "10.0.0.0/8"      # Only allow rules for private networks
  - "192.168.0.0/16"   # Reject rules for public IPs
```

**Port Limitations**: Maximum 200 monitored ports to prevent abuse

## Deployment

### Docker Requirements

Update your Dockerfile:
```dockerfile
# Install firewalld and dbus
RUN apt-get update && apt-get install -y firewalld dbus systemctl

# Container must run as root for firewalld
# (Remove USER directive or set USER root)

# Start services in CMD
CMD ["/bin/bash", "-c", "service dbus start && firewalld --nofork -D & uvicorn main:app --host 0.0.0.0 --port 8000"]
```

Update docker-compose.yml:
```yaml
knocker:
  user: root  # Required for firewalld
  privileged: true  # May be required for full functionality
  volumes:
    - /var/run/dbus:/var/run/dbus:ro
    - /sys/fs/cgroup:/sys/fs/cgroup:ro
```

### Host Requirements

**Firewalld Service**: Host should have firewalld installed and running
```bash
# Ubuntu/Debian
sudo apt-get install firewalld
sudo systemctl enable firewalld
sudo systemctl start firewalld

# RHEL/CentOS
sudo yum install firewalld
sudo systemctl enable firewalld
sudo systemctl start firewalld
```

**D-Bus**: D-Bus system service must be running (typically installed by default)

## Troubleshooting

### Common Issues

**"firewall-cmd not found"**
- Ensure firewalld package is installed in container
- Check Dockerfile includes firewalld installation

**"Failed to connect to D-Bus"**
- Verify D-Bus socket is mounted: `/var/run/dbus:/var/run/dbus:ro`
- Ensure container runs as root
- Check D-Bus service is running on host

**"Permission denied" errors**
- Container must run with root privileges
- May need `privileged: true` in docker-compose
- Check SELinux policies if applicable

**Rules not persisting after restart**
- Check `state_storage_path` is writable
- Verify volume mounting for data persistence
- Review reconciliation logs for errors

### Debugging

**Enable Debug Logging**:
```yaml
logging:
  level: DEBUG
```

**Check Firewalld Status**:
```bash
# In container or host
firewall-cmd --state
firewall-cmd --get-zones
firewall-cmd --zone=knocker --list-all
```

**Monitor Logs**:
```bash
# Container logs
docker logs knocker_container

# Firewalld logs
journalctl -u firewalld -f
```

### Log Messages

**Normal Operation**:
```
INFO - Firewalld integration initialized with zone 'knocker'
INFO - Successfully added firewalld rules for 192.168.1.100 (expires in 300s)
INFO - Firewalld state reconciliation complete: 0 restored, 2 expired
```

**Error Conditions**:
```
ERROR - Failed to add firewalld rule for 192.168.1.100:22/tcp
ERROR - firewall-cmd failed with return code 1
CRITICAL - Failed to initialize firewalld integration: [error details]
```

## Performance Considerations

### Rule Limits

- Maximum 200 monitored ports per configuration
- No hard limit on concurrent rules (limited by firewalld/system resources)
- Rules are removed automatically on TTL expiration

### Background Processing

- Reconciliation thread runs every 30s by default
- Cleanup operations are lightweight (metadata-only unless rules are expired)
- State file operations use atomic writes for safety

### Firewalld Performance

- Rich rules have minimal performance impact
- Zone-based approach is more efficient than individual rules
- Automatic timeout handling reduces manual cleanup overhead

## Migration and Backwards Compatibility

### Enabling on Existing Deployments

1. **Update Configuration**: Add firewalld section to `knocker.yaml`
2. **Update Container**: Rebuild with firewalld dependencies
3. **Update Deployment**: Add required volumes and privileges
4. **Gradual Rollout**: Can be enabled incrementally (existing whitelist continues to work)

### Disabling Integration

1. **Set `enabled: false`** in configuration
2. **Optional Cleanup**: Set `cleanup_on_exit: true` and restart service once
3. **Revert Container**: Can remove firewalld dependencies and root privileges

### Compatibility

- **Whitelist Behavior**: Standard whitelist functionality unchanged
- **API Compatibility**: All existing API endpoints work identically  
- **Configuration**: Existing configurations work without firewalld section
- **Performance**: No impact when disabled (`enabled: false`)

## Examples

### Basic SSH Protection

```yaml
security:
  firewalld:
    enabled: true
    zone_name: "knocker-ssh"
    monitored_ports:
      - "22/tcp"
    cleanup_on_exit: false  # Keep rules for production
```

### Multi-Service Setup

```yaml
security:
  firewalld:
    enabled: true
    zone_name: "knocker"
    monitored_ports:
      - "22/tcp"    # SSH
      - "443/tcp"   # HTTPS
      - "80/tcp"    # HTTP
      - "3306/tcp"  # MySQL
    monitored_sources:
      - "10.0.0.0/8"        # Internal networks only
      - "192.168.0.0/16"
    reconcile_interval_seconds: 60  # Less frequent cleanup
```

### Development Environment

```yaml
security:
  firewalld:
    enabled: true
    zone_name: "knocker-dev"
    monitored_ports:
      - "22/tcp"
      - "8080/tcp"
    cleanup_on_exit: true   # Auto-cleanup for dev
    reconcile_interval_seconds: 10  # Frequent cleanup
```