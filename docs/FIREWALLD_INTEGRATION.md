# Firewalld Integration

This document describes the firewalld integration feature in Caddy Knocker, which provides dynamic firewall rule management with automatic rule expiry.

## Overview

The firewalld integration allows Knocker to automatically create and manage firewall rules at the OS level, providing an additional layer of security beyond application-level access control. When enabled, Knocker will:

1. Create a dedicated `KNOCKER` firewalld zone with high priority
2. Set up deny-all rules for monitored ports
3. Add allow rules for always-allowed IPs
4. Dynamically create timed allow rules based on successful knock requests
5. Automatically clean up expired rules

## Features

- **Timed Rules**: Firewall rules automatically expire based on the TTL from knock requests
- **Port-Specific Protection**: Only specified ports are managed by firewalld rules
- **IPv4/IPv6 Support**: Full support for both IPv4 and IPv6 addresses and CIDR ranges  
- **Startup Synchronization**: Clean up orphaned rules on service restart
- **Always-Allowed Bypass**: IPs in the always-allowed list don't get unnecessary firewalld rules
- **Graceful Degradation**: Service continues to work even if firewalld is unavailable

## Configuration

Add the following section to your `knocker.yaml` configuration file:

```yaml
firewalld:
  # Enable/disable firewalld integration
  enabled: true
  
  # List of ports to monitor and protect with firewalld rules
  monitored_ports:
    - 80
    - 443
    - 8080
    - 8443
  
  # Name of the firewalld zone to create for knocker rules
  zone_name: "KNOCKER"
  
  # Priority for the KNOCKER zone (higher numbers = higher priority)
  priority: 100
```

### Configuration Options

- **`enabled`**: Boolean flag to enable/disable firewalld integration
- **`monitored_ports`**: List of TCP ports that should be protected by firewalld rules
- **`zone_name`**: Name of the firewalld zone created for Knocker rules (default: "KNOCKER")
- **`priority`**: Zone priority - higher values take precedence over lower priority zones

## Prerequisites

### System Requirements

1. **Firewalld installed and running**:
   ```bash
   # On RHEL/CentOS/Fedora
   sudo dnf install firewalld
   sudo systemctl enable --now firewalld
   
   # On Ubuntu/Debian
   sudo apt install firewalld
   sudo systemctl enable --now firewalld
   ```

2. **Python D-Bus bindings**:
   ```bash
   # Usually installed with firewalld, but if needed:
   sudo apt install python3-dbus python3-gi
   # or
   sudo dnf install python3-dbus python3-gobject
   ```

3. **Proper permissions**: The knocker service needs to communicate with firewalld via D-Bus

### Docker Considerations

When running Knocker in Docker with firewalld integration:

1. **Host networking** (recommended):
   ```yaml
   services:
     knocker:
       network_mode: "host"
       volumes:
         - /var/run/dbus/system_bus_socket:/var/run/dbus/system_bus_socket
   ```

2. **Privileged container** (alternative):
   ```yaml
   services:
     knocker:
       privileged: true
       volumes:
         - /var/run/dbus/system_bus_socket:/var/run/dbus/system_bus_socket
   ```

## How It Works

### Zone Setup

When Knocker starts with firewalld enabled:

1. **Creates KNOCKER zone** with high priority to override default rules
2. **Sets up default deny rules** for each monitored port:
   ```
   rule port port="80" protocol="tcp" reject
   rule port port="443" protocol="tcp" reject
   ```
3. **Adds always-allowed rules** for IPs in the `always_allowed_ips` configuration:
   ```
   rule family="ipv4" source address="192.168.1.0/24" port port="80" protocol="tcp" accept
   ```

### Dynamic Rule Creation

When a successful knock request is made:

1. **Validates the IP** isn't already in always-allowed list (to avoid redundant rules)
2. **Creates allow rules** for each monitored port:
   ```
   rule family="ipv4" source address="203.0.113.100" port port="80" protocol="tcp" accept
   rule family="ipv4" source address="203.0.113.100" port port="443" protocol="tcp" accept
   ```
3. **Tracks rule expiry** internally with the same TTL as the knock request
4. **Logs rule creation** for monitoring and debugging

### Rule Cleanup

Expired rules are automatically cleaned up:

1. **Periodic cleanup** runs during the regular whitelist cleanup process
2. **Startup synchronization** removes orphaned rules on service restart
3. **Manual cleanup** via the cleanup API endpoint (if implemented)

## Usage Examples

### Basic Setup

1. **Enable firewalld integration** in `knocker.yaml`:
   ```yaml
   firewalld:
     enabled: true
     monitored_ports: [80, 443]
   ```

2. **Restart knocker service**:
   ```bash
   sudo systemctl restart knocker
   ```

3. **Verify zone creation**:
   ```bash
   sudo firewall-cmd --list-all-zones | grep -A 10 KNOCKER
   ```

### Testing Rules

1. **Make a knock request**:
   ```bash
   curl -H "X-Api-Key: YOUR_API_KEY" \
        -H "X-Forwarded-For: 203.0.113.100" \
        http://your-knocker-server/knock
   ```

2. **Check created rules**:
   ```bash
   sudo firewall-cmd --zone=KNOCKER --list-rich-rules
   ```

3. **Monitor rule expiry** by checking logs and re-running the above command after TTL expires

## Troubleshooting

### Common Issues

1. **"Failed to connect to firewalld"**:
   - Ensure firewalld is running: `sudo systemctl status firewalld`
   - Check D-Bus is accessible: `dbus-send --system --print-reply --dest=org.fedoraproject.FirewallD1 /org/fedoraproject/FirewallD1 org.fedoraproject.FirewallD1.getDefaultZone`

2. **"Permission denied" errors**:
   - Ensure knocker service has proper D-Bus permissions
   - Check if running in Docker with proper privileges

3. **Rules not being created**:
   - Verify IP isn't in `always_allowed_ips` (these are bypassed)
   - Check knocker logs for firewalld error messages
   - Ensure monitored ports are configured correctly

### Debugging Commands

```bash
# Check firewalld status
sudo firewall-cmd --state

# List all zones
sudo firewall-cmd --list-all-zones

# Check KNOCKER zone specifically
sudo firewall-cmd --zone=KNOCKER --list-all

# View knocker logs
sudo journalctl -u knocker -f

# Test D-Bus connectivity
dbus-send --system --print-reply \
  --dest=org.fedoraproject.FirewallD1 \
  /org/fedoraproject/FirewallD1 \
  org.fedoraproject.FirewallD1.getDefaultZone
```

## Security Considerations

### Best Practices

1. **Principle of Least Privilege**: Only include necessary ports in `monitored_ports`
2. **Zone Priority**: Set appropriate priority to ensure KNOCKER rules take precedence
3. **Always-Allowed IPs**: Minimize the always-allowed IP list for security
4. **Regular Monitoring**: Monitor firewalld logs and knocker logs for suspicious activity

### Security Benefits

1. **OS-Level Protection**: Rules are enforced at the kernel level via iptables/nftables
2. **Defense in Depth**: Adds another layer beyond application-level access control
3. **Automatic Cleanup**: Expired rules are automatically removed, reducing attack surface
4. **Audit Trail**: All rule changes are logged by both knocker and firewalld

### Potential Risks

1. **Service Disruption**: Misconfigured rules could block legitimate traffic
2. **Rule Conflicts**: May conflict with existing firewalld rules
3. **Resource Usage**: Large numbers of rules may impact firewall performance
4. **Privilege Requirements**: Requires elevated privileges for D-Bus communication

## Integration with Other Components

### With Caddy

Firewalld rules work alongside Caddy's `forward_auth`:

1. **Firewalld** blocks/allows traffic at the network level
2. **Caddy** performs application-level authentication via knocker
3. Both layers must pass for traffic to reach the backend service

### With Docker

See [Docker Considerations](#docker-considerations) above for proper setup.

### With Existing Firewall Rules

The KNOCKER zone priority should be set higher than existing zones to ensure knocker rules take precedence. Monitor for conflicts with existing rules.

## Performance Considerations

- **Rule Limits**: Firewalld can handle thousands of rules, but performance may degrade with very large rule sets
- **Cleanup Frequency**: More frequent cleanup reduces rule accumulation but increases CPU usage
- **Zone Priority**: Higher priority zones are checked first, improving performance for knocker rules

## Advanced Configuration

### Custom Zone Settings

For advanced users, the KNOCKER zone can be customized after creation:

```bash
# Add custom services
sudo firewall-cmd --zone=KNOCKER --add-service=ssh --permanent

# Set custom target (default is "default")
sudo firewall-cmd --zone=KNOCKER --set-target=DROP --permanent

# Reload to apply changes
sudo firewall-cmd --reload
```

Note: Custom changes may be overwritten by knocker on restart.

### Integration with Configuration Management

For environments using Ansible, Puppet, or similar tools, consider:

1. **Managing firewalld installation** via configuration management
2. **Templating knocker.yaml** with appropriate firewalld settings
3. **Monitoring rule counts** and cleanup frequency
4. **Automated testing** of firewalld integration in CI/CD pipelines

## API Reference

The firewalld integration is transparent to the existing API. No new endpoints are added. However, successful knock requests will now create both:

1. **JSON whitelist entries** (existing behavior)
2. **Firewalld rules** (new behavior when enabled)

Both types of rules share the same TTL and expiry behavior.

## Limitations

1. **Linux Only**: Firewalld is only available on Linux systems
2. **Requires Root/Privileges**: Needs D-Bus permissions to communicate with firewalld
3. **TCP Only**: Currently only supports TCP rules (UDP support could be added)
4. **Port-Based Only**: Rules are port-based, not service-based
5. **Runtime Rules**: Rules are not persistent across firewalld restarts (by design)

## Future Enhancements

Potential future improvements:

1. **UDP Support**: Add support for UDP port rules
2. **Service-Based Rules**: Use firewalld services instead of individual ports
3. **Custom Actions**: Support for custom firewalld actions beyond accept/reject
4. **Rule Metrics**: Expose metrics about rule creation/deletion rates
5. **Web UI**: Administrative interface for viewing active firewalld rules