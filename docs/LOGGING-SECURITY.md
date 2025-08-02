# Logging Security

DNShield implements comprehensive logging security to prevent sensitive data leakage while maintaining operational visibility.

## Overview

The logging system automatically sanitizes sensitive information before it's written to logs, protecting:
- AWS credentials and API keys
- Passwords and authentication tokens
- Email addresses (PII)
- IP addresses (configurable)
- JWT tokens
- Base64-encoded keys

## Sanitization Features

### Automatic Redaction

All log messages are automatically scanned for sensitive patterns:

- **AWS Keys**: `AKIA*`, `ASIA*` → `[REDACTED-AWS-KEY]`
- **API Keys**: Long hex strings → `[REDACTED]`
- **Passwords**: Fields named `password`, `secret`, `key` → `[REDACTED]`
- **Email Addresses**: `user@example.com` → `[REDACTED]`
- **IP Addresses**: `192.168.1.1` → `[REDACTED]` or `[IP-REDACTED]`

### PII Logging Control

By default, Personally Identifiable Information (PII) is redacted from logs. To enable PII logging for debugging:

```bash
# Enable PII logging (requires debug mode)
export DNSHIELD_ENABLE_PII_LOGGING=true
sudo ./dnshield run --config config.yaml --log-level debug
```

**Warning**: Only enable PII logging in development or with appropriate privacy controls.

## Configuration Security

The system validates configuration files and warns about security issues:

```yaml
# Bad practice - credentials in config
s3:
  accessKeyId: "AKIAIOSFODNN7EXAMPLE"  # Warning generated
  secretKey: "wJalrXUtnFEMI..."        # Warning generated

# Good practice - use environment variables
s3:
  bucket: "company-dns-rules"
  region: "us-east-1"
  # Credentials from AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
```

### Security Warnings

On startup, DNShield checks for:
- Plaintext AWS credentials in configuration
- Splunk tokens in configuration  
- Debug mode enabled
- PII logging enabled

Example warnings:
```
WARN[0000] SECURITY: AWS credentials found in configuration file - consider using environment variables or IAM roles
WARN[0000] SECURITY: Running in debug mode - sensitive data may be exposed in logs
```

## Log Fields Sanitization

Structured log fields are automatically sanitized:

```go
// This log entry:
logrus.WithFields(logrus.Fields{
    "password": "mysecret",
    "apikey": "12345...",
    "user": "admin@company.com",
    "client_ip": "10.0.0.1",
}).Info("Login attempt")

// Becomes:
time="2024-01-01T12:00:00Z" level=info msg="Login attempt" apikey="[REDACTED]" client_ip="[REDACTED]" password="[REDACTED]" user="[REDACTED]"
```

## DNS Query Privacy

DNS queries can contain sensitive information. DNShield provides controls:

### Default Behavior
- Domain names logged only for blocked domains
- Client IPs redacted unless PII logging enabled
- Query details only in debug mode

### Privacy Modes

1. **Maximum Privacy** (default):
   ```bash
   # No PII, minimal logging
   sudo ./dnshield run
   ```

2. **Operational Visibility**:
   ```bash
   # Some PII for troubleshooting
   sudo ./dnshield run --log-level info
   ```

3. **Debug Mode** (development only):
   ```bash
   # Full logging with PII (if enabled)
   export DNSHIELD_ENABLE_PII_LOGGING=true
   sudo ./dnshield run --log-level debug
   ```

## Implementation Details

### Sanitizing Hook

The logging system uses a Logrus hook that intercepts all log entries:

```go
// Automatically installed on startup
logging.InstallSanitizingHook(enablePII)
```

### Safe Configuration Logging

Configuration is sanitized before logging:

```go
// Logs configuration without sensitive values
sanitizedConfig := config.SanitizeConfigForLogging(cfg)
logrus.WithFields(sanitizedConfig).Info("Configuration loaded")
```

## Best Practices

1. **Never Log Credentials**: Even with sanitization, avoid logging sensitive data
2. **Use Environment Variables**: For all secrets and credentials
3. **Audit Log Review**: Regularly review logs for inadvertent data exposure
4. **Minimal Debug Usage**: Only use debug mode when necessary
5. **PII Compliance**: Ensure PII logging complies with privacy regulations

## Compliance Considerations

### GDPR Compliance
- Client IPs are considered PII under GDPR
- Default configuration redacts all PII
- Enable PII logging only with appropriate consent

### Log Retention
- Configure log rotation to limit data retention
- Consider shorter retention for debug logs
- Archive logs securely with encryption

### Audit Trail
- Security-relevant events logged separately
- Audit logs maintain integrity while redacting sensitive data

## Testing Sanitization

To verify sanitization is working:

```bash
# Test with fake credentials
echo "Test with key AKIAIOSFODNN7EXAMPLE" | sudo ./dnshield run

# Check logs - should show [REDACTED-AWS-KEY]
tail -f /var/log/dnshield.log | grep REDACTED
```

## Troubleshooting

### Missing Redaction
If sensitive data appears in logs:
1. Check sanitization hook is installed
2. Verify log level settings
3. Review custom log statements
4. Report security issues immediately

### Over-Redaction
If too much is redacted:
1. Check PII logging settings
2. Adjust log level appropriately
3. Use structured logging for better control

## Security Reporting

If you discover sensitive data in logs, please report it as a security issue immediately. Do not include the sensitive data in your report.