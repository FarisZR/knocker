# Security Policy

## Supported Versions

We actively support the latest stable release of Knocker. Security updates will be provided for the most recent version.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| main    | :construction: Development branch - use at your own risk |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in Knocker, please report it privately:

1. **Email the maintainer**: Create a security advisory through GitHub's private reporting feature
2. **Provide details**: Include steps to reproduce, potential impact, and any suggested fixes
3. **Wait for acknowledgment**: We aim to acknowledge reports within 48 hours
4. **Responsible disclosure**: Please allow us time to address the issue before public disclosure

### What to Report

Please report any security issues including but not limited to:

- Authentication bypass vulnerabilities
- IP spoofing or validation bypasses
- Path traversal or injection attacks
- Denial of Service (DoS) vulnerabilities
- Information disclosure issues
- Race conditions in critical paths
- Cryptographic weaknesses
- Configuration vulnerabilities

## Security Best Practices

For secure deployment of Knocker, please review our comprehensive security documentation:

- [Security Hardening Guide](./docs/SECURITY.md) - Detailed security configuration
- [Security Audit Summary](./docs/SECURITY_AUDIT_SUMMARY.md) - Known vulnerabilities and fixes
- [Project Overview](./docs/Project-OVERVIEW.md) - Architecture and deployment guidance

### Critical Security Considerations

1. **Always change default API keys** - Never use the example keys in production
2. **Configure trusted_proxies correctly** - Prevents IP spoofing attacks
3. **Use strong API keys** - Generate cryptographically secure random strings
4. **Restrict CORS origins** - Don't use wildcard `*` in production
5. **Keep whitelist size limited** - Configure appropriate `max_whitelist_entries`
6. **Monitor logs** - Watch for suspicious activity and rejected requests
7. **Regular updates** - Keep Knocker updated to receive security patches

### Docker Security

When running Knocker in Docker:

- Use the official images from `ghcr.io/fariszr/knocker`
- Verify image signatures when available
- Run as non-root user (default) unless firewalld integration is required
- Isolate on a dedicated Docker network
- Mount configuration files as read-only when possible

### Firewalld Integration Security

If using firewalld integration:

- **Requires root access** - Understand the security implications
- Configure `monitored_ips` carefully - Don't use `0.0.0.0/0` without careful consideration
- Start with narrow IP ranges and expand carefully
- Monitor firewalld logs regularly
- See [FirewallD Integration Guide](./docs/FIREWALLD_INTEGRATION.md) for details

## Security Improvements in Recent Versions

### Version 1.0.0+

- ✅ Timing-attack resistant API key validation
- ✅ Trusted proxy validation to prevent IP spoofing
- ✅ CIDR range size limits to prevent abuse
- ✅ Path traversal prevention in excluded paths
- ✅ Race condition protection in whitelist operations
- ✅ DoS prevention via whitelist size limits
- ✅ Reduced information disclosure in logs and errors
- ✅ Atomic file operations for whitelist persistence
- ✅ Input size validation for all endpoints
- ✅ Comprehensive edge case handling

See [Security Audit Summary](./docs/SECURITY_AUDIT_SUMMARY.md) for complete details.

## Acknowledgments

We appreciate responsible security researchers who help keep Knocker secure. Security researchers who report valid vulnerabilities will be acknowledged in our security advisories (with permission).
