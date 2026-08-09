# Security Hardening Guide

This document outlines the security improvements made to Caddy Knocker and best practices for secure deployment.

## Security Vulnerabilities Fixed

### 1. IP Spoofing Prevention (Critical)

**Issue**: The X-Forwarded-For header was trusted without validating the source IP, allowing attackers to spoof their IP address.

**Fix**: Implemented trusted proxy validation that only honors X-Forwarded-For headers from configured trusted sources.

If the direct peer is a configured proxy, a missing, malformed, or incomplete
`X-Forwarded-For` chain resolves to no client IP. Knocker never falls back to
the proxy address. Direct clients whose peer is not trusted continue to use
their direct address and cannot influence forwarded headers.

**Configuration**:
```yaml
server:
  trusted_proxies:
    - "172.29.238.0/24"  # Docker network
    - "127.0.0.1"        # Localhost
```

### 2. CIDR Range Abuse Prevention (High)

**Issue**: Attackers could whitelist overly broad IP ranges like `0.0.0.0/0` or `::/0`, effectively disabling all access controls.

**Fix**: Added validation to reject CIDR ranges that exceed reasonable size limits.

**Limits**:
- IPv4: Maximum 65,536 addresses per range
- IPv6: Minimum /64 prefix (broader ranges are rejected)

### 3. Request parsing and rate limiting

`POST /knock` authenticates and applies the failure limiter before reading the
body. The body is optional, must be `application/json` when present, may contain
only `ip_address` and `ttl`, and is bounded at 4096 bytes. Authenticated malformed
and oversized requests count as failures. The endpoint returns 413 for an
oversized body, 415 for non-JSON content, and 503 when the serialized firewall
mutation worker is unavailable or saturated.

### 4. Path Traversal Protection (Medium)

**Issue**: The excluded paths feature used simple string prefix matching, potentially vulnerable to path traversal attacks.

**Fix**: Implemented path normalization that resolves `..` and `.` components before checking exclusions.

**Example**: `/api/status/../../../etc/passwd` is normalized to `/etc/passwd` and properly rejected.

### 5. Race Condition Prevention (Medium)

**Issue**: Concurrent access to the whitelist file could cause data corruption or inconsistent state.

**Fix**: Added file locking and atomic writes using temporary files.

**Features**:
- Thread-safe operations with threading locks
- File locking (fcntl) for process-level safety
- Atomic file operations (write to temp, then rename)

### 6. Information Disclosure Reduction (Medium)

**Issue**: API key names were logged in plaintext, potentially exposing sensitive information.

**Fix**: Reduced logging verbosity to remove sensitive details from logs.

### 7. DoS Prevention via Size Limits (Low)

**Issue**: No limits on whitelist size could allow attackers to consume excessive disk space.

**Fix**: Configurable limits on whitelist entries with automatic cleanup of oldest entries.

**Configuration**:
```yaml
security:
  max_whitelist_entries: 10000  # Default limit
  knock_rate_limit:
    window_seconds: 60
    successful_requests: 20
    failed_requests: 30
```

### 8. Whitelist Storage Path Validation (Low)

**Issue**: A hostile configuration could point whitelist persistence at an unexpected path on disk.

**Fix**: Whitelist storage is normalized with `realpath` and constrained to known-safe roots before any file operation.

**Allowed roots**:
- The current working directory
- `/data`
- `/tmp`

### 9. Secure CORS Policy (Low)

**Issue**: Default CORS policy used wildcard origin (`*`), allowing any website to make requests.

**Fix**: Encourage explicit origin configuration in production.

**Configuration**:
```yaml
cors:
  allowed_origin: "https://your-trusted-domain.com"
```

## Security Best Practices

### 1. Network Configuration

- **Always configure trusted_proxies**: Only include the actual reverse proxy IPs/networks
- **Leave proxy-header resolution to Knocker**: Run Uvicorn with `--no-proxy-headers` so Knocker can resolve the direct peer from `request.client.host` before consulting `server.trusted_proxies`
- **Reject malformed forwarded chains**: If a trusted proxy sends an invalid `X-Forwarded-For` chain, Knocker now treats the client IP as unresolved instead of falling back to the proxy IP
- **Use Docker networks**: Isolate knocker service on a private Docker network
- **Firewall rules**: Restrict direct access to the knocker service port

### 2. API Key Management

- **Use strong, random API keys**: Generate cryptographically secure random strings
- **Do not reuse secrets across entries**: Avoid configuring the same secret twice
- **Principle of least privilege**: Set `allow_remote_whitelist: false` for most keys
- **Regular rotation**: Rotate API keys periodically
- **Separate keys for different purposes**: Use different keys for admin vs user access
- **Reject published placeholders**: The old example secrets, plus values containing `CHANGE_ME` or `REPLACE_WITH`, are rejected at startup.

### 3. Configuration Security

- **Restrict file permissions**: Ensure knocker.yaml is only readable by the service user
- **Environment variables**: Store the config path in `KNOCKER_CONFIG_PATH`
- **Always-allowed IPs**: Minimize the always-allowed IP list to only essential systems
- **Proxy networks are not allowlists**: Keep `always_allowed_ips` empty unless every address in the range is meant to bypass verification.
- **Use host-scoped exclusions**: Do not globally exclude `/knock`; put the dedicated knock hostname on a direct proxy route and protect other hosts with `forward_auth`.

### 4. Monitoring and Logging

- **Monitor failed authentication attempts**: Look for patterns that might indicate attacks
- **Set up alerts**: Alert on unusual whitelist activity or configuration changes
- **Log rotation**: Ensure logs don't consume excessive disk space

### 5. Regular Security Maintenance

- **Keep dependencies updated**: Regularly update Python packages and base container images
- **Review configurations**: Periodically audit trusted_proxies and always_allowed_ips
- **Test security controls**: Regularly verify that security measures are working correctly

### 6. Firewalld readiness and architecture

When `firewalld.enabled` is true, startup fails before readiness unless the
daemon, version, exact zone, configured priority/target/sources, default
blocking rules, reload, and all active whitelist restorations verify correctly.
Health performs only read-only storage checks and firewalld verification.

Firewall mutations run through one bounded in-process worker and return 503 when
capacity is unavailable. A remaining architectural risk is privileged root
container access to the host D-Bus and the root + host-firewalld trust boundary.
Moving mutations into a separately confined helper service remains future work;
this change intentionally does not implement that architecture.

## Security Testing

The project includes comprehensive security tests in `tests/test_security_fixes.py` that validate:

- Trusted proxy validation
- CIDR range limits
- Path traversal prevention
- Information disclosure protection
- Size limits and DoS prevention
- Rate limiting

Run security tests with:
```bash
uv run pytest tests/test_security_fixes.py -v
```

## Reporting Security Issues

If you discover security vulnerabilities not covered by these protections:

1. **Do not open public issues** for security vulnerabilities
2. Contact the maintainers privately
3. Provide detailed information about the vulnerability
4. Allow time for responsible disclosure

## Scope note

This guide describes implemented controls and configuration requirements. It is
not a claim that every deployment-specific or architectural risk has been
eliminated.
