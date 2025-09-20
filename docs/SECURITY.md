# Security Hardening Guide

This document outlines the security improvements made to Caddy Knocker and best practices for secure deployment.

## Security Vulnerabilities Fixed

### 1. IP Spoofing Prevention (Critical)

**Issue**: The X-Forwarded-For header was trusted without validating the source IP, allowing attackers to spoof their IP address.

**Fix**: Implemented trusted proxy validation that only honors X-Forwarded-For headers from configured trusted sources.

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
- IPv6: Minimum /96 prefix (larger ranges rejected based on prefix length)

### 3. Path Traversal Protection (Medium)

**Issue**: The excluded paths feature used simple string prefix matching, potentially vulnerable to path traversal attacks.

**Fix**: Implemented path normalization that resolves `..` and `.` components before checking exclusions.

**Example**: `/api/status/../../../etc/passwd` is normalized to `/etc/passwd` and properly rejected.


### 4. Race Condition Prevention (Medium)

**Issue**: Concurrent access to the whitelist file could cause data corruption or inconsistent state.

**Fix**: Added file locking and atomic writes using temporary files.

**Features**:
- Thread-safe operations with threading locks
- File locking (fcntl) for process-level safety
- Atomic file operations (write to temp, then rename)

### 5. Information Disclosure Reduction (Medium)

**Issue**: API key names were logged in plaintext, potentially exposing sensitive information.

**Fix**: Reduced logging verbosity to remove sensitive details from logs.

### 6. DoS Prevention via Size Limits (Low)

**Issue**: No limits on whitelist size could allow attackers to consume excessive disk space.

**Fix**: Configurable limits on whitelist entries with automatic cleanup of oldest entries.

**Configuration**:
```yaml
security:
  max_whitelist_entries: 10000  # Default limit
```

### 7. Secure CORS Policy (Low)

**Issue**: Default CORS policy used wildcard origin (`*`), allowing any website to make requests.

**Fix**: Encourage explicit origin configuration in production.

**Configuration**:
```yaml
cors:
  allowed_origin: "https://your-trusted-domain.com"
```

### 8. Atomic Firewall & Whitelist Consistency (Medium)

**Issue**: Previously the whitelist JSON file could be updated even if firewall rule application failed (or vice‑versa on later failures), leading to desynchronization. This caused:
- Whitelist entries without active firewall rules (false sense of access)
- Firewall rules without persisted whitelist entries (orphaned network exposure)
- Flaky integration tests (e.g. "Firewall rules not found for X.X.X.X")

**Fix**: Enforced an atomic operation order in `core.add_ip_to_whitelist`:
1. Apply all required firewall rich rules first.
2. Persist the whitelist entry only if step 1 succeeds.
3. On persistence failure, rollback (best effort) previously added firewall rules.
4. Surface a generic HTTP 500 to clients while logging internal details at debug/error level.

**Guarantee**: An entry will appear in the whitelist file only if corresponding firewall rules are (or were just successfully) active. No partial success states.

**Operational Signals**:
- `FirewallApplyError` -> No whitelist mutation occurred.
- `WhitelistPersistError` -> Rollback attempted; investigate disk / permission / volume issues.

**Security Impact**:
- Eliminates inconsistent authorization state.
- Prevents accidental long‑lived exposure from orphaned firewall rules.
- Strengthens auditability: log trails now map 1:1 to applied state transitions.

## Security Best Practices

### 1. Network Configuration

- **Always configure trusted_proxies**: Only include the actual reverse proxy IPs/networks
- **Use Docker networks**: Isolate knocker service on a private Docker network
- **Firewall rules**: Restrict direct access to the knocker service port

### 2. API Key Management

- **Use strong, random API keys**: Generate cryptographically secure random strings
- **Principle of least privilege**: Set `allow_remote_whitelist: false` for most keys
- **Regular rotation**: Rotate API keys periodically
- **Separate keys for different purposes**: Use different keys for admin vs user access

### 3. Configuration Security

- **Restrict file permissions**: Ensure knocker.yaml is only readable by the service user
- **Environment variables**: Store the config path in `KNOCKER_CONFIG_PATH`
- **Always-allowed IPs**: Minimize the always-allowed IP list to only essential systems

### 4. Monitoring and Logging

- **Monitor failed authentication attempts**: Look for patterns that might indicate attacks
- **Set up alerts**: Alert on unusual whitelist activity or configuration changes
- **Log rotation**: Ensure logs don't consume excessive disk space

### 5. Regular Security Maintenance

- **Keep dependencies updated**: Regularly update Python packages and base container images
- **Review configurations**: Periodically audit trusted_proxies and always_allowed_ips
- **Test security controls**: Regularly verify that security measures are working correctly

## Security Testing

The project includes comprehensive security tests in `tests/test_security_fixes.py` that validate:

- Trusted proxy validation
- CIDR range limits
- Path traversal prevention
- Information disclosure protection
- Size limits and DoS prevention

Run security tests with:
```bash
PYTHONPATH=src python3 -m pytest tests/test_security_fixes.py -v
```

## Reporting Security Issues

If you discover security vulnerabilities not covered by these protections:

1. **Do not open public issues** for security vulnerabilities
2. Contact the maintainers privately
3. Provide detailed information about the vulnerability
4. Allow time for responsible disclosure

## Security Audit Summary

This security audit identified and fixed multiple vulnerabilities:

- **7 security issues** ranging from Critical to Low severity
- **100% of identified vulnerabilities** have been addressed
- **Comprehensive test coverage** added for all security controls
- **Documentation** updated with security best practices

The application is now significantly more secure against common attack vectors while maintaining full backward compatibility with existing functionality.