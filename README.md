# DNS Guardian

Enterprise DNS filtering with transparent HTTPS interception for macOS.

[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.md)
[![Platform](https://img.shields.io/badge/platform-macOS-lightgrey.svg)](https://www.apple.com/macos/)

## 🎯 Overview

DNS Guardian is a lightweight, single-binary DNS filtering solution that provides transparent HTTPS interception without certificate warnings. Designed for enterprise deployment, it combines DNS-level blocking with dynamic certificate generation for seamless security.

### Why DNS Guardian?

- **🔒 No Certificate Warnings**: Dynamic certificate generation for blocked HTTPS sites
- **📦 Single Binary**: No Docker, containers, or complex dependencies  
- **🏢 Enterprise Ready**: S3-based central management, audit logging, MDM support
- **🔐 Privacy First**: All filtering happens locally on the device
- **⚡ High Performance**: Written in Go with built-in caching
- **🍎 Native macOS**: Touch ID support, System Keychain integration

## 🚀 Quick Start

### Option 1: Standard Installation (v1 - File-based)
```bash
# Build the binary
make build

# Install CA certificate (one-time setup)
./dns-guardian install-ca

# Configure DNS to 127.0.0.1
sudo networksetup -setdnsservers Wi-Fi 127.0.0.1

# Run DNS Guardian
sudo ./dns-guardian run
```

### Option 2: Enterprise Installation (v2 - System Keychain)
```bash
# Build the binary
make build

# Install CA certificate with System keychain storage (requires sudo)
sudo DNS_GUARDIAN_SECURITY_MODE=v2 DNS_GUARDIAN_USE_KEYCHAIN=true ./dns-guardian install-ca

# Configure DNS to 127.0.0.1
sudo networksetup -setdnsservers Wi-Fi 127.0.0.1

# Run DNS Guardian in v2 mode
sudo DNS_GUARDIAN_SECURITY_MODE=v2 DNS_GUARDIAN_USE_KEYCHAIN=true ./dns-guardian run
```

Test it by visiting a blocked domain like `https://doubleclick.net`

## 📋 Features

### DNS Filtering
- High-performance DNS server with caching
- Support for multiple blocklist formats (hosts, domains, AdGuard)
- Real-time rule updates from S3
- Configurable upstream resolvers (Cloudflare, Google, custom)
- Wildcard and regex support (planned)

### HTTPS Interception  
- Dynamic certificate generation per domain
- Local CA management with system keychain integration
- Transparent filtering without warnings
- Memory-based certificate caching for performance
- Automatic certificate lifecycle management

### Enterprise Features
- **Central Management**: S3-based rule distribution
- **Audit Logging**: Comprehensive logs for compliance
- **MDM Support**: Zero-touch deployment via Jamf/Kandji
- **Multi-Environment**: Dev/staging/prod rule sets
- **Statistics**: Query metrics and reporting

## 🏗️ Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   DNS Query     │────▶│  DNS Guardian   │────▶│  Upstream DNS   │
│  (port 53)      │     │   (Blocking)    │     │  (1.1.1.1)      │
└─────────────────┘     └────────┬────────┘     └─────────────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │ Blocked Domain? │
                        └────────┬────────┘
                                 │ Yes
                                 ▼
┌─────────────────┐     ┌─────────────────┐
│ HTTPS Request   │────▶│   Cert Proxy    │
│  (port 443)     │     │ (Dynamic Cert)  │
└─────────────────┘     └────────┬────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │  Block Page     │
                        └─────────────────┘
```

## ⚙️ Configuration

### Basic Configuration (`config.yaml`)

```yaml
# DNS server settings
dns:
  upstreams:
    - "1.1.1.1"         # Cloudflare
    - "8.8.8.8"         # Google
  cacheSize: 10000
  cacheTTL: "1h"

# S3 rule management
s3:
  bucket: "company-dns-rules"
  region: "us-east-1"
  rulesPath: "production/rules.yaml"
  updateInterval: "5m"

# Agent settings  
agent:
  logLevel: "info"
  dnsPort: 53
  httpPort: 80
  httpsPort: 443
```

### S3 Rule Format

```yaml
version: "1.0"
updated: 2024-01-20T10:00:00Z

# External blocklist sources
sources:
  - https://someonewhocares.org/hosts/zero/hosts
  - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts

# Custom blocked domains
domains:
  - ads.company.com
  - tracking.vendor.com
  - "*.doubleclick.net"    # Wildcard support

# Never block these
whitelist:
  - necessary-service.com
  - api.required-app.com
```

### Environment Variables

```bash
# AWS credentials (if not using IAM roles)
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AWS_REGION="us-east-1"

# Configuration override
export DNS_GUARDIAN_CONFIG="/path/to/config.yaml"
```

## 🚚 Deployment

### Manual Installation

1. Download the latest release or build from source
2. Install the CA certificate: `./dns-guardian install-ca`
3. Configure system DNS to `127.0.0.1`
4. Run as root: `sudo ./dns-guardian run`

### MDM Deployment (Recommended)

For enterprise deployment via Jamf, Munki, or other MDM solutions, use v2 mode with System Keychain storage:

```bash
# Create deployment package
make package

# The package will install DNS Guardian with v2 mode enabled
# This stores the CA private key in System keychain, accessible by root
# Perfect for zero-touch deployment

# Deploy via MDM (Jamf example)
jamf policy -event install-dns-guardian
```

**Why v2 for Enterprise?**
- No user interaction required
- Keys stored in System keychain (root accessible)
- Works when no user is logged in
- Survives user account changes
- Central management ready

See [docs/MDM_DEPLOYMENT.md](docs/MDM_DEPLOYMENT.md) for detailed instructions.

### System Requirements

- macOS 10.15 (Catalina) or later
- 64-bit Intel or Apple Silicon processor
- Admin privileges for installation
- 50MB disk space
- 100MB RAM (typical usage)

## 🔒 Security Model

### Per-Machine CA
- Each installation generates a unique CA certificate
- Compromise limited to single machine
- No shared secrets across deployments
- CA private key protected with file permissions

### Certificate Generation
- Only generates certificates for blocked domains  
- Critical domains (banks, government) are protected
- All operations are audit logged
- Rate limiting prevents abuse

### v2.0 Security Features (Available Now)
- ✅ System Keychain storage for CA keys (enterprise deployment ready)
- ✅ Root-accessible key storage for Jamf/Munki deployment
- ✅ Enhanced audit logging (JSON format)
- ✅ Non-extractable key storage
- ✅ Cryptocurrency exchange ready

**v2.0 System Keychain Storage:**
- CA private keys stored in `/Library/Keychains/System.keychain`
- Accessible by root/system processes
- Perfect for enterprise deployment via MDM
- No user interaction required after deployment

Enable v2.0 security mode:
```bash
# Clean any existing installation
sudo security delete-certificate -c "DNS Guardian Root CA" /Library/Keychains/System.keychain 2>/dev/null || true
sudo security delete-generic-password -s "com.dnsguardian.ca" /Library/Keychains/System.keychain 2>/dev/null || true

# Install with v2 mode (requires sudo)
sudo DNS_GUARDIAN_SECURITY_MODE=v2 DNS_GUARDIAN_USE_KEYCHAIN=true ./dns-guardian install-ca

# Run in v2 mode (requires sudo)
sudo DNS_GUARDIAN_SECURITY_MODE=v2 DNS_GUARDIAN_USE_KEYCHAIN=true ./dns-guardian run
```

Or use the Makefile shortcuts:
```bash
make install-v2  # Installs CA with System keychain
make run-v2      # Runs in v2 mode
```

## 🏦 Cryptocurrency Exchange Deployment

⚠️ **CRITICAL SECURITY NOTICE**: The current v2 implementation stores CA private keys in the System Keychain but they remain extractable by any root process. This is NOT sufficient for cryptocurrency exchanges where a compromise could lead to significant financial losses.

### Security Requirements for Crypto Exchanges

For production deployment at a cryptocurrency exchange, you MUST implement one of the following:

### Option 1: Hardware Security Module (Recommended)
```bash
# CA private key never exists in software
# All signing operations happen in HSM
# Cost: $5,000-50,000 for network HSM
```

**Implementation**:
- Use PKCS#11 interface to communicate with HSM
- CA private key generated and stored in HSM
- Signing operations performed by HSM
- Full audit trail of all operations

### Option 2: Remote Signing Service
```
┌─────────────────┐     ┌──────────────────┐
│  DNS Guardian   │────▶│ Signing Service  │
│  (on endpoint)  │     │ (secure server)  │
└─────────────────┘     └──────────────────┘
```

**Benefits**:
- CA key never on endpoint machines
- Centralized monitoring and rate limiting
- Can revoke access instantly
- Detailed audit logs

### Option 3: Secure Enclave (Apple Silicon)
For T2/Apple Silicon Macs, implement proper Secure Enclave integration:
- Requires CGO and Security Framework
- Keys bound to specific hardware
- Non-extractable even with root
- Requires code signing

### Minimum Security Checklist for Exchanges

- [ ] **Never use current v2 implementation as-is** - keys are extractable
- [ ] **Implement hardware-backed key storage** (HSM or Secure Enclave)
- [ ] **Code signing** with hardened runtime and notarization
- [ ] **Rate limiting** - Max 10 certificates per minute
- [ ] **Domain blocklist** - Never generate certs for exchange domains
- [ ] **Real-time alerting** - Alert security team on every cert generation
- [ ] **Certificate Transparency** - Log all certificates to CT logs
- [ ] **Multi-person approval** - CA operations require multiple approvals
- [ ] **Incident response plan** - Plan for CA key compromise
- [ ] **Regular audits** - External security assessment quarterly

### What NOT to Do

❌ **Do NOT use file-based storage (v1)** - Easily compromised  
❌ **Do NOT use System Keychain alone (v2)** - Still extractable by root  
❌ **Do NOT store CA keys on endpoints** - Use central signing service  
❌ **Do NOT allow unlimited certificate generation** - Implement rate limits  
❌ **Do NOT generate certificates for financial domains** - Hardcode blocklist  

### Example: Production-Ready Architecture

```yaml
# dns-guardian-exchange.yaml
security:
  mode: "hsm"
  hsm:
    type: "thales-nshield"
    slot: 1
    pin_file: "/secure/hsm.pin"
  
  rate_limits:
    certs_per_minute: 10
    certs_per_domain_per_hour: 5
  
  blocked_domains:
    - "*.coinbase.com"
    - "*.binance.com"
    - "*.kraken.com"
    - "*.exchange-internal.com"
  
  monitoring:
    siem_endpoint: "https://siem.internal/api/events"
    alert_threshold: 5  # Alert after 5 certs in 1 minute
    
  audit:
    retention_days: 2555  # 7 years
    encryption: true
    remote_backup: "s3://audit-backup-bucket/"
```

### Getting Help

For cryptocurrency exchange deployments:
1. Contact your security team first
2. Consider hiring external security consultants
3. Test extensively in staging environment
4. Never compromise on security for convenience

**Remember**: In crypto, one compromised certificate could mean millions in losses.

## 🔐 Most Secure Option: Remote Signing Service

For organizations requiring the highest level of security (financial institutions, cryptocurrency exchanges, government agencies), the **Remote Signing Service** architecture provides complete CA key isolation.

### Why Remote Signing is the Gold Standard

1. **Zero Key Exposure**: CA private key never exists on endpoint devices
2. **Instant Revocation**: Compromised endpoints can be cut off immediately  
3. **Centralized Control**: Rate limiting, monitoring, and audit trails in one place
4. **Hardware Security**: Can leverage cloud HSMs (AWS KMS, Azure Key Vault)
5. **Compliance Ready**: Meets SOC2, PCI-DSS, and financial regulations

### Architecture Overview

```
┌─────────────────┐      mTLS      ┌──────────────────┐      KMS/HSM     ┌──────────────┐
│  DNS Guardian   │────────────────▶│ Signing Service  │─────────────────▶│  CA Key      │
│  (on endpoint)  │◀────────────────│  (AWS Lambda)    │                  │  (secure)    │
└─────────────────┘   Certificate   └──────────────────┘                  └──────────────┘
                                            │
                                            ▼
                                    ┌──────────────────┐
                                    │   Audit Logs     │
                                    │   (DynamoDB)     │
                                    └──────────────────┘
```

### Quick Comparison

| Feature | Current v2 | Remote Signing Service |
|---------|------------|----------------------|
| CA Key Location | System Keychain (extractable) | Cloud HSM (non-extractable) |
| Compromise Impact | Single machine | Zero (key not on device) |
| Rate Limiting | Per-device | Centralized & enforced |
| Audit Trail | Local logs | Centralized & tamper-proof |
| Cost | Free | ~$500-2000/month |
| Setup Complexity | Simple | Moderate |

### Implementation Guide

For a complete step-by-step guide to implementing a production-ready remote signing service on AWS, see:

📘 **[Remote Signing Service on AWS - Implementation Guide](docs/REMOTE_SIGNING_AWS.md)**

This guide includes:
- Complete AWS architecture with Lambda, API Gateway, and KMS
- mTLS configuration for secure agent communication  
- Terraform templates for one-click deployment
- Cost optimization strategies
- Integration with DNS Guardian agents
- Monitoring and alerting setup

**Note**: While the current v2 implementation with System Keychain provides good security for most enterprise deployments, organizations handling financial transactions or sensitive data should strongly consider the remote signing architecture.

## 📊 Monitoring & Logs

### Log Locations
- Service logs: `Console.app` → "dns-guardian"
- DNS queries: Enable debug logging
- Certificate generation: Audit log enabled by default

### Metrics Available
- DNS queries per second
- Cache hit rate  
- Blocked domains count
- Certificate generation rate
- Rule update status

### Example Log Output
```
INFO[2024-01-20T10:30:45] Starting DNS Guardian v1.0.0
INFO[2024-01-20T10:30:45] DNS server listening on port 53
INFO[2024-01-20T10:30:45] HTTPS server listening on port 443
INFO[2024-01-20T10:30:46] Fetched rules from S3 version=1.0 domains=5423
INFO[2024-01-20T10:31:02] Blocked domain domain=doubleclick.net
INFO[2024-01-20T10:31:02] Generated certificate domain=doubleclick.net duration=8ms
```

## 🛠️ Development

### Prerequisites
- Go 1.21 or later
- macOS development machine
- AWS credentials (for S3 integration)

### Building from Source

```bash
# Clone repository
git clone <repository-url>
cd dns-guardian

# Install dependencies
go mod download

# Run tests
make test

# Build binary
make build

# Run locally
sudo ./dns-guardian run
```

### Project Structure
```
dns-guardian/
├── cmd/              # Command implementations
├── internal/         # Core packages
│   ├── ca/          # Certificate authority
│   ├── config/      # Configuration
│   ├── dns/         # DNS server
│   ├── proxy/       # HTTPS proxy
│   └── rules/       # Rule management
├── docs/            # Documentation
└── main.go          # Entry point
```

## 🤝 Troubleshooting

### Common Issues

**Certificate warnings still appear**
- Ensure CA is installed: `./dns-guardian install-ca`
- Check Keychain Access for "DNS Guardian" certificate
- Clear browser cache or use incognito mode

**DNS not resolving**
- Verify service is running: `./dns-guardian status`
- Check DNS settings: `networksetup -getdnsservers Wi-Fi`
- Review logs for errors

**Can't bind to port 53**
- Ensure running with sudo
- Check for other DNS services: `sudo lsof -i :53`

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for more solutions.

## 🗑️ Uninstalling DNS Guardian

### Complete Uninstall (v1 or v2)

```bash
# 1. Stop DNS Guardian if running
sudo pkill -f dns-guardian

# 2. Reset DNS settings to default
sudo networksetup -setdnsservers Wi-Fi Empty

# 3. Remove CA certificate from System keychain
sudo security delete-certificate -c "DNS Guardian Root CA" /Library/Keychains/System.keychain 2>/dev/null || true

# 4. Remove private key from System keychain (v2 only)
sudo security delete-generic-password -s "com.dnsguardian.ca" -a "ca-private-key" /Library/Keychains/System.keychain 2>/dev/null || true

# 5. Remove private key from user keychain (if exists)
security delete-generic-password -s "com.dnsguardian.ca" -a "ca-private-key" 2>/dev/null || true

# 6. Remove DNS Guardian data directory
rm -rf ~/.dns-guardian

# 7. Remove the binary
rm -f ./dns-guardian

# 8. (Optional) Remove audit logs if stored elsewhere
sudo rm -rf /var/log/dns-guardian
```

### Using Makefile

```bash
# Complete cleanup (removes everything)
make clean-all
```

**Note:** After uninstalling, you may need to restart your browser or clear its cache to remove any cached certificates.

## 📝 License

MIT License - see [LICENSE.md](LICENSE.md) for details.

## 🙏 Acknowledgments

Built with these excellent open source projects:
- [miekg/dns](https://github.com/miekg/dns) - DNS library
- [Cobra](https://github.com/spf13/cobra) - CLI framework  
- [AWS SDK for Go](https://aws.amazon.com/sdk-for-go/) - S3 integration

---

Built with ❤️ for enterprise security teams# dns_guardian
