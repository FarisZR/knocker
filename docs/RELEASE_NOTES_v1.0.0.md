# Knocker v1.0.0 - Initial Stable Release

## 🎉 Production Ready!

This is the first stable release of Knocker, a secure, self-hosted IP whitelisting service for homelabs and production environments.

## ✨ Key Features

### Core Functionality
- **HTTP-based knock-knock authorization** - Simple API for dynamic IP whitelisting
- **Multi-tenant API keys** - Separate keys with different permissions and TTLs
- **Remote IP whitelisting** - Admin keys can whitelist any IP or CIDR range
- **Time-based expiration** - Automatic cleanup of expired whitelist entries
- **Path-based exclusions** - Exclude health checks and public endpoints
- **IPv4 and IPv6 support** - First-class support for both protocols

### Integration Features
- **Reverse proxy integration** - Works with Caddy, Nginx, Traefik via forward_auth
- **FirewallD integration** - Optional network-level firewall rules with automatic expiration
- **Docker-native** - Pre-built multi-arch images (AMD64, ARM64, ARMv7)
- **Interactive API documentation** - Optional Swagger/ReDoc interfaces

### Security Features
- **Timing-attack resistant** - Constant-time API key validation
- **IP spoofing prevention** - Trusted proxy validation
- **CIDR range limits** - Prevents overly broad ranges
- **Input validation** - Comprehensive validation of all inputs
- **Path traversal prevention** - Secure configuration and file handling
- **Race condition protection** - Thread-safe whitelist operations
- **DoS prevention** - Whitelist size limits and rate limiting

## 🔒 Security Improvements

This release includes comprehensive security hardening:

### Vulnerabilities Fixed
1. **Timing attack vulnerability (Critical)** - API key validation now uses constant-time comparison
2. **Missing input validation (High)** - All inputs validated for type, length, and range
3. **Configuration injection (Medium)** - Path traversal prevention in config loading
4. **Missing .dockerignore (Medium)** - Sensitive files excluded from images
5. **Incomplete edge case handling (Medium)** - Comprehensive TTL validation
6. **Information disclosure (Low)** - Generic error messages

### Security Controls
- ✅ Constant-time API key comparison using `hmac.compare_digest()`
- ✅ Maximum TTL limit (10 years) to prevent overflow
- ✅ IP address string length validation (max 100 chars)
- ✅ Duplicate API key detection at startup
- ✅ Empty API keys list validation
- ✅ Configuration path validation (no path traversal)
- ✅ Health check dependency verification
- ✅ .dockerignore prevents sensitive file leaks

## 📦 Installation

### Quick Start with Docker

```bash
# Pull the latest stable release
docker pull ghcr.io/fariszr/knocker:latest

# Or pin to specific version
docker pull ghcr.io/fariszr/knocker:v1.0.0

# Download example configuration
curl -O https://raw.githubusercontent.com/FarisZR/knocker/main/knocker.example.yaml
mv knocker.example.yaml knocker.yaml

# IMPORTANT: Change the default API keys!
# Edit knocker.yaml and change all CHANGE_ME_* keys

# Run with docker-compose
docker-compose up -d
```

### Available Image Tags

- `latest` - Latest stable release (this version)
- `v1.0.0` - This specific version
- `1.0.0` - Version without 'v' prefix
- `1.0` - Latest 1.0.x patch version
- `1` - Latest 1.x.x version
- `main` - Development branch (unstable, not recommended for production)

## 🚀 Migration from Pre-Release

If you were using the `main` tag before this release:

1. **Change your docker-compose.yml**:
   ```yaml
   # Old (development builds)
   image: ghcr.io/fariszr/knocker:main
   
   # New (stable releases)
   image: ghcr.io/fariszr/knocker:latest
   ```

2. **Review security settings** - See the [Production Checklist](PRODUCTION_CHECKLIST.md)

3. **Update configuration** - No breaking changes, but review:
   - `trusted_proxies` configuration
   - CORS `allowed_origin` (change from `*` to specific domain)
   - `max_whitelist_entries` limit

4. **Test before deploying** - All changes are backward compatible

## 📚 Documentation

- **[Production Deployment Checklist](PRODUCTION_CHECKLIST.md)** - Pre-deployment security checklist
- **[Security Guide](SECURITY.md)** - Comprehensive security documentation
- **[Project Overview](Project-OVERVIEW.md)** - Architecture and features
- **[FirewallD Integration](FIREWALLD_INTEGRATION.md)** - Advanced firewall setup
- **[API Specification](API_SPEC.md)** - Complete API documentation

## 🧪 Testing

This release includes:
- **163 comprehensive tests** (100% passing)
- **24 production hardening tests**
- **16 security fix validation tests**
- **13 security vulnerability tests**
- Full edge case coverage

## 🏗️ CI/CD

### Automated Workflows
- ✅ Test suite runs on every PR
- ✅ Integration tests with Docker Compose
- ✅ Multi-arch Docker image builds
- ✅ Automatic GitHub releases with changelogs
- ✅ Semantic versioning support

### Build Information
- **Python**: 3.13
- **Architectures**: linux/amd64, linux/arm/v8, linux/arm/v7
- **Base Image**: python:3.13-slim
- **Security**: Runs as non-root user by default

## 🐛 Known Issues

None in this release. If you discover any issues:
1. Check the [troubleshooting guide](Project-OVERVIEW.md)
2. Search existing [GitHub Issues](https://github.com/FarisZR/knocker/issues)
3. Report new issues with details

## 🔐 Security Disclosure

To report security vulnerabilities:
1. **Do not open public issues**
2. See our [Security Policy](../SECURITY.md)
3. Use GitHub's private security advisory feature
4. We aim to respond within 48 hours

## 🙏 Acknowledgments

This project was developed with AI assistance (Gemini 2.5 Pro, GitHub Copilot, GPT-4o). Special thanks to:
- The FastAPI team for the excellent framework
- The Python community for robust libraries
- Early testers and contributors

## 📝 License

This project is open source. See [LICENSE](../LICENSE) for details.

## 🔗 Links

- **GitHub**: https://github.com/FarisZR/knocker
- **Docker Images**: https://github.com/FarisZR/knocker/pkgs/container/knocker
- **Documentation**: https://github.com/FarisZR/knocker/tree/main/docs

---

**Ready to deploy?** Check out the [Production Deployment Checklist](PRODUCTION_CHECKLIST.md) first!
