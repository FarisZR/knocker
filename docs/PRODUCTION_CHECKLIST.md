# Production Deployment Checklist

Use this checklist before deploying Knocker to production to ensure security and reliability.

## ✅ Configuration Security

### API Keys
- [ ] **Change ALL default API keys** - Never use `CHANGE_ME_*` keys from examples
- [ ] Generate cryptographically secure random keys (minimum 32 characters)
  ```bash
  # Example: Generate secure API key
  openssl rand -base64 32
  ```
- [ ] Use different keys for different purposes (admin, user, guest)
- [ ] Set appropriate `max_ttl` values for each key
- [ ] Minimize keys with `allow_remote_whitelist: true`
- [ ] Document which keys are for what purpose

### Network Configuration
- [ ] Configure `trusted_proxies` to match your Docker network subnet
  ```bash
  # Find your Docker network subnet
  docker network inspect <network_name>
  ```
- [ ] **DO NOT use wildcard CORS origins in production**
  - Change `allowed_origin: "*"` to your specific domain
  - Example: `allowed_origin: "https://knock.yourdomain.com"`
- [ ] Verify `trusted_proxies` includes ONLY your reverse proxy IPs

### File Permissions
- [ ] Set `knocker.yaml` to read-only (chmod 400)
- [ ] Ensure knocker.yaml is owned by the container user
- [ ] Verify `whitelist.json` path is writable by container user
- [ ] Check data directory permissions (should be 750 or 700)

### Storage Configuration
- [ ] Set appropriate `max_whitelist_entries` based on expected usage
  - Default is 10,000 entries
  - Estimate: max_concurrent_users × 2
- [ ] Ensure whitelist storage path is on persistent volume
- [ ] Configure backup strategy for whitelist.json

## ✅ Docker Security

### Image Security
- [ ] Use official images: `ghcr.io/fariszr/knocker:latest`
- [ ] Pin to specific version tag for production (e.g., `v1.0.0`)
- [ ] Verify image signatures when available
- [ ] Scan images for vulnerabilities
  ```bash
  docker scan ghcr.io/fariszr/knocker:latest
  ```

### Container Configuration
- [ ] Run as non-root user (default, unless using firewalld)
- [ ] Use read-only filesystem where possible
- [ ] Mount configuration as read-only volume
  ```yaml
  volumes:
    - ./knocker.yaml:/knocker.yaml:ro
  ```
- [ ] Limit container resources (CPU, memory)
- [ ] Use dedicated Docker network, not host networking
- [ ] Enable IPv6 only if needed

### Firewalld Integration (Optional)
If using firewalld integration:
- [ ] Understand security implications of running as root
- [ ] Verify firewalld is installed and running on host
- [ ] Test `monitored_ips` configuration carefully
- [ ] **DO NOT use `0.0.0.0/0` or `::/0` without careful consideration**
- [ ] Start with narrow IP ranges
- [ ] Monitor firewall logs regularly
- [ ] Document firewall rule behavior

## ✅ Reverse Proxy Configuration

### Caddy/Nginx/Traefik
- [ ] Configure forward_auth directive correctly
- [ ] Ensure X-Forwarded-For header is passed
- [ ] Test authorization failures return 401
- [ ] Verify excluded paths work as expected
- [ ] Configure appropriate timeouts
- [ ] Enable HTTPS/TLS for all endpoints
- [ ] Use strong TLS configuration (TLS 1.2+)

### Network Isolation
- [ ] Knocker service should NOT be exposed directly to internet
- [ ] Only reverse proxy should reach Knocker service
- [ ] Use Docker networks for isolation
- [ ] Consider using firewall rules at host level

## ✅ Monitoring & Logging

### Health Checks
- [ ] Configure health check endpoint monitoring
  ```yaml
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
    interval: 30s
    timeout: 10s
    retries: 3
  ```
- [ ] Set up alerts for health check failures
- [ ] Monitor service uptime

### Logging
- [ ] Configure appropriate log level (INFO for production)
- [ ] Set up log aggregation (ELK, Grafana, etc.)
- [ ] Monitor for rejected authentication attempts
- [ ] Watch for suspicious IP patterns
- [ ] Alert on configuration errors
- [ ] Rotate logs regularly

### Metrics (Optional)
- [ ] Track whitelist size over time
- [ ] Monitor API key usage patterns
- [ ] Track authentication success/failure rates
- [ ] Monitor request latency

## ✅ Backup & Recovery

### Data Backup
- [ ] Regular backups of whitelist.json
- [ ] Backup knocker.yaml configuration
- [ ] Test restore procedure
- [ ] Document recovery steps
- [ ] Store backups securely (encrypted)

### Disaster Recovery
- [ ] Document full deployment procedure
- [ ] Test recovery from backup
- [ ] Have rollback plan ready
- [ ] Document troubleshooting steps

## ✅ Testing Before Production

### Functional Testing
- [ ] Test knock endpoint with all API keys
- [ ] Verify whitelist expiration works
- [ ] Test CIDR range whitelisting
- [ ] Verify excluded paths work
- [ ] Test always_allowed_ips configuration
- [ ] Verify TTL limits are enforced
- [ ] Test with both IPv4 and IPv6

### Security Testing
- [ ] Test with invalid API keys (should fail)
- [ ] Verify IP spoofing is prevented
- [ ] Test CIDR range limits (should reject 0.0.0.0/0)
- [ ] Verify path traversal is blocked
- [ ] Test rate limiting behavior
- [ ] Verify CORS policy is enforced
- [ ] Check error messages don't leak info

### Load Testing
- [ ] Test with expected concurrent users
- [ ] Verify performance under load
- [ ] Check memory usage patterns
- [ ] Monitor CPU usage
- [ ] Test whitelist cleanup performance

## ✅ Documentation

### Internal Documentation
- [ ] Document API key purposes
- [ ] Record network configuration
- [ ] Document monitoring setup
- [ ] Create runbook for common issues
- [ ] Document escalation procedures

### User Documentation
- [ ] Provide knock instructions to users
- [ ] Document TTL limits
- [ ] Explain authorization failures
- [ ] Provide troubleshooting guide

## ✅ Maintenance Plan

### Regular Tasks
- [ ] Weekly: Review authentication logs
- [ ] Monthly: Rotate API keys (if policy requires)
- [ ] Monthly: Update to latest stable version
- [ ] Quarterly: Security audit
- [ ] Yearly: Review and update configuration

### Update Strategy
- [ ] Test updates in staging first
- [ ] Have rollback plan
- [ ] Schedule maintenance windows
- [ ] Notify users of planned downtime

## ✅ Security Incident Response

### Preparation
- [ ] Document incident response plan
- [ ] Identify security contact
- [ ] Have emergency API key rotation procedure
- [ ] Document how to block malicious IPs
- [ ] Prepare communication templates

### Detection
- [ ] Monitor for unusual authentication patterns
- [ ] Watch for brute force attempts
- [ ] Alert on configuration changes
- [ ] Track whitelist size anomalies

## 🚨 Critical Security Reminders

1. **NEVER commit knocker.yaml to version control**
2. **NEVER use example API keys in production**
3. **ALWAYS use HTTPS for knock endpoint**
4. **ALWAYS configure trusted_proxies correctly**
5. **NEVER expose Knocker directly to internet**
6. **ALWAYS monitor authentication logs**
7. **ALWAYS test configuration changes in staging**

## Need Help?

- 📖 [Security Guide](SECURITY.md)
- 📖 [Project Overview](Project-OVERVIEW.md)
- 🐛 [GitHub Issues](https://github.com/FarisZR/knocker/issues)
- 🔒 [Security Policy](../SECURITY.md)
