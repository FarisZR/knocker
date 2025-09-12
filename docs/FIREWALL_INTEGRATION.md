# Firewall Integration

Knocker supports integration with firewalld to provide automated, timed firewall rules that synchronize with the IP whitelist functionality. When enabled, successful knock requests will not only add IPs to the internal whitelist but also create corresponding firewall rules that automatically expire.

## Overview

The firewall integration creates a dedicated `knocker` firewalld zone with the highest priority (-1) that manages access to specified monitored ports. When an IP is successfully whitelisted via the `/knock` endpoint, firewall rules are automatically created to allow that IP access to the monitored ports for the duration of the TTL.

### Key Features

- **Timed Firewall Rules**: Rules automatically expire based on the TTL from knock requests
- **Startup Recovery**: On service restart, firewall rules are synchronized with the current whitelist state
- **Zone Isolation**: Uses a dedicated `knocker` zone to avoid conflicts with existing firewall configuration
- **Port Monitoring**: Configure which ports should be protected by dynamic firewall rules
- **Always Allowed IPs**: Automatically creates rules for IPs in the `always_allowed_ips` configuration
- **Graceful Degradation**: If firewalld is unavailable, the service continues to operate normally without firewall integration

## Configuration

### Enabling Firewall Integration

Add the following section to your `knocker.yaml` configuration file:

```yaml
firewall:
  enabled: true
  monitored_ports:
    - "80/tcp"    # HTTP
    - "443/tcp"   # HTTPS  
    - "22/tcp"    # SSH
    - "8080"      # Default protocol is tcp
```

### Configuration Options

- **`enabled`** (boolean): Whether to enable firewall integration. Default: `false`
- **`monitored_ports`** (list): Ports that should be protected by dynamic firewall rules
  - Format: `"port/protocol"` or just `"port"` (defaults to tcp)
  - Examples: `"80/tcp"`, `"53/udp"`, `"443"`

## Docker Setup

### Requirements

The firewall integration requires special Docker configuration to access the host's firewalld service:

1. **Privileged Mode**: The container needs privileged access to manage firewall rules
2. **Host Network**: Network mode should be set to `host` for proper firewall integration  
3. **D-Bus Access**: Access to the system D-Bus socket for firewalld communication

### Docker Compose Configuration

```yaml
services:
  knocker-firewall:
    build:
      context: .
      dockerfile: Dockerfile
    privileged: true
    network_mode: host
    environment:
      - KNOCKER_CONFIG_PATH=/app/knocker.yaml
      - DBUS_SYSTEM_BUS_ADDRESS=unix:path=/var/run/dbus/system_bus_socket
    volumes:
      - ./knocker.yaml:/app/knocker.yaml:ro
      - knocker_data:/data
      - /var/run/dbus:/var/run/dbus:ro
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
    depends_on:
      - firewalld
    ports:
      - "8000:8000"
```

### Host System Requirements

The host system must have:
- firewalld installed and running
- python3-firewall package installed
- D-Bus system service running

## How It Works

### Zone Creation

On startup, if firewall integration is enabled, knocker:

1. Creates a `knocker` firewalld zone if it doesn't exist
2. Sets the zone target to `DROP` (default deny)
3. Sets the zone priority to `-1` (highest priority)
4. Adds rules for `always_allowed_ips` from the configuration

### Dynamic Rule Management

When an IP is whitelisted via `/knock`:

1. The IP is added to the internal JSON whitelist
2. For each monitored port, a rich rule is created in the `knocker` zone:
   ```
   rule family="ipv4" source address="192.168.1.100" port port="80" protocol="tcp" accept
   ```
3. Rules are added to the runtime configuration (immediate effect)

### Rule Expiration

Rules are cleaned up through multiple mechanisms:

1. **Startup Sync**: On service startup, existing firewall rules are compared with the current whitelist state
2. **Periodic Cleanup**: When `cleanup_expired_ips()` is called, expired IPs are removed from both whitelist and firewall
3. **On-Demand Sync**: The `_sync_firewall_rules_with_whitelist()` function ensures consistency

### Rich Rule Format

Firewall rules use firewalld's rich rule syntax:
- **IPv4**: `rule family="ipv4" source address="1.2.3.4" port port="80" protocol="tcp" accept`
- **IPv6**: `rule family="ipv6" source address="2001:db8::1" port port="443" protocol="tcp" accept`  
- **CIDR**: `rule family="ipv4" source address="192.168.1.0/24" port port="22" protocol="tcp" accept`

## Security Considerations

### Zone Isolation

The `knocker` zone operates independently of other firewalld zones:
- Highest priority (-1) ensures knocker rules are evaluated first
- Default target `DROP` provides fail-safe behavior
- Rules only affect the specified monitored ports

### Always Allowed IPs

IPs in the `security.always_allowed_ips` configuration are automatically granted firewall access without expiration. These should be carefully configured to include only trusted networks.

### Privilege Requirements

The firewall integration requires elevated privileges:
- Container must run in privileged mode
- Access to system D-Bus socket
- Ability to modify firewall rules

### Rule Persistence

- Rules are created in the runtime configuration only (not permanent)
- Rules are recreated on firewalld service restart through knocker's startup sync
- This prevents accumulation of permanent rules over time

## Troubleshooting

### Common Issues

**Service Won't Start**
```
Firewalld is not available: [Errno 2] No such file or directory
```
- Ensure firewalld is installed and running on the host
- Check that python3-firewall package is installed in the container
- Verify D-Bus socket is accessible

**Permission Denied**
```
Failed to initialize firewall: Permission denied
```
- Ensure container is running in privileged mode
- Check D-Bus socket permissions
- Verify user has firewall management permissions

**Rules Not Applied**
```
Successfully whitelisted 1.2.3.4 for 3600 seconds
```
But no firewall rules visible with `firewall-cmd --zone=knocker --list-rich-rules`
- Check that firewall integration is enabled in configuration
- Verify monitored_ports are configured
- Check container has proper D-Bus access

### Debugging Commands

Check firewall integration status:
```bash
# List knocker zone rules
firewall-cmd --zone=knocker --list-rich-rules

# Check if knocker zone exists  
firewall-cmd --get-zones | grep knocker

# View zone configuration
firewall-cmd --zone=knocker --list-all

# Check firewalld service status
systemctl status firewalld
```

Check container D-Bus access:
```bash
# Inside container
ls -la /var/run/dbus/system_bus_socket

# Test D-Bus connection
python3 -c "import firewall.client; fw = firewall.client.FirewallClient(); print(fw.getDefaultZone())"
```

### Log Analysis

Firewall-related log messages:
```
INFO - Firewalld is available and accessible
INFO - Created firewall zone 'knocker'  
INFO - Added firewall rules for 192.168.1.100 until 1640995200
WARNING - Firewalld is not available: [Errno 111] Connection refused
ERROR - Failed to initialize firewall: Permission denied
```

## Testing

### Unit Tests

The firewall integration includes comprehensive unit tests:
```bash
PYTHONPATH=src python3 -m pytest tests/test_firewall.py -v
```

### Integration Tests

Test with actual firewalld:
```bash
# Requires root access and running firewalld
sudo ./dev/firewall_integration_tests.sh
```

### Development Environment

Use the provided Docker Compose setup for testing:
```bash
cd dev/
docker-compose up -d
./firewall_integration_tests.sh
```

## Migration Guide

### Enabling Firewall Integration

For existing knocker deployments:

1. **Update Configuration**: Add firewall section to `knocker.yaml`
2. **Update Docker Configuration**: Add privileged mode and D-Bus access
3. **Install Dependencies**: Ensure firewalld and python3-firewall are available
4. **Test Integration**: Use provided test scripts to verify functionality

### Disabling Firewall Integration

To disable firewall integration:

1. Set `firewall.enabled: false` in configuration
2. Remove privileged mode from Docker configuration (optional)
3. Clean up knocker zone: `firewall-cmd --delete-zone=knocker --permanent`

## Performance Considerations

### Rule Creation Overhead

- Each knock request creates N rules (where N = number of monitored ports)
- Rule creation involves D-Bus communication with firewalld
- Consider limiting the number of monitored ports for high-traffic scenarios

### Memory Usage

- Firewall rules are stored in firewalld's memory
- Large numbers of concurrent whitelisted IPs may increase firewalld memory usage
- Monitor firewalld performance with many active rules

### Cleanup Frequency

- Rule cleanup is performed during IP whitelist cleanup
- Frequent cleanup may impact performance but ensures accuracy
- Balance cleanup frequency with performance requirements

## API Integration  

The firewall integration is transparent to API users:
- `/knock` endpoint behavior remains unchanged
- Firewall rules are created/removed automatically
- No additional API endpoints are required

## Best Practices

1. **Monitor Ports Carefully**: Only include ports that actually need dynamic access control
2. **Limit Always Allowed IPs**: Keep the always_allowed_ips list minimal and specific
3. **Regular Monitoring**: Monitor firewalld performance and rule counts
4. **Backup Configuration**: Ensure firewall configuration is backed up
5. **Test Thoroughly**: Always test firewall integration in a development environment first
6. **Log Analysis**: Monitor logs for firewall-related errors or warnings

## CI Mocking with python3-dbusmock

CI systems (like GitHub Actions) do not permit privileged containers or system services such as firewalld on shared runners. To allow CI to validate the firewalld integration without requiring a real firewalld service, the project uses python-dbusmock to emulate the minimal D-Bus surface that the `src/firewall.py` module needs.

How it works in CI:
- The workflow installs the required system packages (python3-dbusmock, python3-dbus, python3-firewall, dbus) on the runner.
- A small pytest integration test starts a python-dbusmock server on a private system bus and registers minimal methods used by the code:
  - getDefaultZone()
  - getZones()
  - addRichRule(zone, rich_rule)
  - removeRichRule(zone, rich_rule)
  - getRichRules(zone)
- The unit/integration test triggers the firewall code paths (initialize_firewall, add_ip_to_firewall) against the mock. The mock logs method calls to stdout, which the test asserts on to ensure the expected D-Bus calls were made.

Running the CI-style mock locally:
1. Install system dependencies (Debian/Ubuntu):
   sudo apt-get update
   sudo apt-get install -y python3-dbusmock python3-dbus python3-firewall dbus
2. Run the specific pytest integration test:
   PYTHONPATH=src python3 -m pytest tests/integration/test_firewalld_dbusmock.py -q

Running real firewalld integration tests locally:
- The repository still includes the Docker compose setup and the script `dev/firewall_integration_tests.sh` to run tests against a real firewalld instance inside a privileged container. These are intentionally gated behind a compose "firewalld" profile so CI will not start them by default.
- To run the real-firewalld tests locally:
  cd dev
  docker compose --profile firewalld up -d --build
  ./firewall_integration_tests.sh

Notes:
- The python-dbusmock-based test verifies that the application makes the correct D-Bus calls but does not exercise the host firewall. Use the dockerized real-firewalld test for end-to-end validation when you have a host or CI runner with the necessary privileges.
- Keep both test modes to ensure CI coverage while retaining the option for full integration testing when needed.