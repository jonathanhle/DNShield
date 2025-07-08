# Security Policy

## 🔒 Security Model

DNS Guardian implements a defense-in-depth security approach for enterprise DNS filtering with HTTPS interception capabilities.

### Core Security Principles

1. **Least Privilege**: Each component runs with minimal required permissions
2. **Isolation**: Per-machine CA certificates limit compromise blast radius
3. **Transparency**: All security-relevant operations are logged
4. **No Shared Secrets**: Each deployment is cryptographically independent

## 🛡️ Security Architecture

### Certificate Authority (CA) Management

#### Current Implementation (v1.x)
- **Storage**: CA private key stored at `~/.dns-guardian/ca.key` with 0600 permissions
- **Generation**: 4096-bit RSA key, 10-year validity
- **Isolation**: Each machine generates its own CA - no key distribution
- **Trust**: CA certificate must be manually installed in system keychain

#### Security Considerations
- The CA private key can sign certificates for ANY domain
- Anyone with file system access can read the key (including users with sudo)
- Compromise is limited to the single machine

#### v2.0 Implementation (Available Now)
- **System Keychain Storage**: CA private key stored in /Library/Keychains/System.keychain
- **Root Access Required**: Both installation and runtime require sudo
- **Enterprise Ready**: Perfect for Jamf/Munki deployment
- **Non-Extractable**: Key stored securely in System keychain
- **Audit Trail**: All CA operations logged to ~/.dns-guardian/audit/

### Certificate Generation

DNS Guardian only generates certificates for domains that are:
1. Successfully resolved by DNS to the sinkhole address (127.0.0.1)
2. Not on the critical domains protection list
3. Within rate limiting thresholds

#### Protected Domains
The following domains will NEVER have certificates generated:
- Banking institutions (*.bank, *.chase.com, *.wellsfargo.com, etc.)
- Government sites (*.gov, *.mil)
- Healthcare providers (*.medicare.gov, *.healthcare.gov)
- Critical infrastructure (root certificate authorities, OS update servers)

### DNS Security

- **Query Validation**: All DNS queries are validated before processing
- **Cache Poisoning Prevention**: TTL limits and source validation
- **Upstream Security**: DNS-over-HTTPS to trusted resolvers
- **Rate Limiting**: Prevents DNS amplification attacks

## 🚨 Threat Model

### In Scope Threats

1. **Malicious Website Access**: Prevented through DNS blocking
2. **Phishing Attempts**: Blocked at DNS resolution
3. **Malware C&C Communication**: Prevented via blocklists
4. **Ad Tracking**: Blocked at network level
5. **DNS Exfiltration**: Monitored and logged

### Out of Scope Threats

1. **Nation-State Attackers**: Assume sophisticated adversaries can bypass
2. **Physical Access**: Cannot protect against local machine compromise
3. **Supply Chain Attacks**: Depends on trusted upstream blocklists
4. **Zero-Day Exploits**: No protection against unknown vulnerabilities

## 🔐 Operational Security

### Deployment Security

1. **Binary Integrity**
   - Code sign all binaries
   - Notarize for macOS Gatekeeper
   - Provide SHA256 checksums

2. **Installation Security**
   - Require admin privileges
   - Verify installer integrity
   - Audit installation logs

3. **Configuration Security**
   - Never store AWS credentials in config files
   - Use environment variables or IAM roles
   - Validate all configuration inputs

### Runtime Security

1. **Process Isolation**
   - Run with minimal privileges
   - Drop privileges after port binding
   - Use macOS sandbox where possible

2. **Network Security**
   - Bind only to localhost by default
   - No remote administration interface
   - All external communication over TLS

3. **Logging Security**
   - No sensitive data in logs
   - Configurable log levels
   - Log rotation and retention policies

## 📊 Audit Logging

All security-relevant events are logged:

- CA certificate operations (access, installation, uninstall)
- Certificate generation (domain, timestamp, result, cached)
- Keychain operations (v2.0)
- Configuration changes
- Rule updates from S3
- Service start/stop events
- Security violations

### Log Format (v1.x)
```
timestamp=2024-01-20T10:30:45 level=AUDIT event=cert_generated domain=example.com result=success duration=8ms
```

### Log Format (v2.0)
```json
{
  "timestamp": "2024-01-20T10:30:45Z",
  "type": "CERT_GENERATED",
  "severity": "info",
  "message": "Certificate for example.com",
  "details": {
    "domain": "example.com",
    "duration": "8ms",
    "cached": false
  },
  "user": "admin",
  "process_id": 12345,
  "process_name": "dns-guardian"
}
```

### Audit Log Location
- v1.x: Standard output (configurable)
- v2.0: `~/.dns-guardian/audit/audit-YYYY-MM-DD.log`

## 🚑 Incident Response

### If CA Key is Compromised

1. **Immediate Actions**
   - Stop the DNS Guardian service
   - Remove CA from system keychain
   - Delete compromised key file

2. **Remediation**
   - Generate new CA certificate
   - Re-install on affected machines
   - Audit certificate generation logs

3. **Investigation**
   - Review system logs for unauthorized access
   - Check for generated certificates
   - Identify compromise timeline

### If Blocklist is Poisoned

1. **Detection**
   - Monitor for legitimate domains being blocked
   - Check S3 access logs
   - Verify rule file signatures (future)

2. **Response**
   - Revert to known-good rules
   - Disable automatic updates
   - Investigate S3 bucket access

## 🛠️ Security Best Practices

### For Administrators

1. **Protect S3 Bucket**
   - Enable versioning
   - Use bucket policies
   - Enable access logging
   - Require MFA for changes

2. **Monitor Operations**
   - Review logs regularly
   - Alert on unusual patterns
   - Track certificate generation

3. **Update Regularly**
   - Apply security patches
   - Update blocklists
   - Rotate credentials

### For Developers

1. **Code Security**
   - No hardcoded secrets
   - Input validation everywhere
   - Secure defaults
   - Minimize dependencies

2. **Testing Security**
   - Security unit tests
   - Penetration testing
   - Fuzzing inputs
   - Static analysis

## 🐛 Reporting Security Issues

We take security seriously. If you discover a vulnerability:

1. **DO NOT** open a public issue
2. Email: security@your-company.com
3. Include:
   - Description of the issue
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline
- **24 hours**: Initial acknowledgment
- **72 hours**: Preliminary assessment
- **7 days**: Fix timeline provided
- **30 days**: Fix released (critical issues faster)

## 📋 Security Checklist

### Pre-Deployment
- [ ] CA certificate properly protected
- [ ] S3 bucket secured with proper IAM policies
- [ ] Binary code-signed and notarized
- [ ] Configuration validated
- [ ] Audit logging enabled

### Post-Deployment
- [ ] Monitor certificate generation logs
- [ ] Review DNS query patterns
- [ ] Check for configuration drift
- [ ] Validate rule updates
- [ ] Test incident response procedures

## 🔮 Security Enhancements

### Version 2.0 (Available Now)
- ✅ System Keychain integration for CA storage
- ✅ Enhanced audit logging (JSON format)
- ✅ Code signing support
- ✅ Enterprise deployment ready (Jamf/Munki)
- ✅ Short-lived certificates (5 minutes)

### Version 3.0 (Roadmap)
- Certificate transparency logging
- DNSSEC validation
- Signed rule files with GPG
- Hardware security module support
- Remote attestation
- Zero-trust architecture
- Encrypted configuration

## 🔐 Enabling v2.0 Security Mode

For cryptocurrency exchanges and high-security environments:

```bash
# Install CA with v2.0 security mode (System Keychain)
sudo DNS_GUARDIAN_SECURITY_MODE=v2 DNS_GUARDIAN_USE_KEYCHAIN=true ./dns-guardian install-ca

# Build and sign the binary (optional for local testing)
make build-signed CODESIGN_IDENTITY="Developer ID Application: Your Company"

# Run with enhanced security
sudo DNS_GUARDIAN_SECURITY_MODE=v2 DNS_GUARDIAN_USE_KEYCHAIN=true ./dns-guardian run

# Or use Makefile shortcuts
make install-v2  # Install with System keychain
make run-v2      # Run in v2 mode
```

### v2.0 Security Benefits
1. **System-Level Protection**: CA private key stored in System keychain
2. **Root Access Control**: Requires sudo for all operations
3. **Enterprise Deployment**: Works with Jamf, Munki, and other MDM solutions
4. **Audit Trail**: All operations logged in structured JSON format
5. **Short-Lived Certificates**: Domain certificates valid for only 5 minutes
6. **Compliance**: Meets financial industry security requirements

---

Remember: Security is a journey, not a destination. Stay vigilant! 🛡️