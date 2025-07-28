# DNShield Logging Architecture

## Overview
DNShield agents will log audit events to both Splunk (primary) and S3 (archive) for comprehensive security monitoring and compliance.

## Log Destinations

### 1. Splunk HTTP Event Collector (Primary)
- Real-time streaming of audit events
- Immediate alerting on security violations
- Centralized search and analytics

### 2. S3 Archive (Secondary)
- Hourly batch uploads
- Long-term retention (configurable)
- Compressed JSON format

## Log Types

### Security Audit Events
- Certificate generation (domain, timestamp, cached)
- CA access attempts
- Keychain operations
- Security violations

### Operational Events
- Service start/stop
- Configuration changes
- Rule updates
- DNS query metrics (aggregated)

## Implementation Design

### Configuration
```yaml
logging:
  splunk:
    enabled: true
    endpoint: "https://splunk.company.com:8088/services/collector"
    token: "${SPLUNK_HEC_TOKEN}"
    index: "dnshield-audit"
    sourcetype: "dnshield:audit"
    tls:
      verifyServerCert: true
    retry:
      maxAttempts: 3
      backoffSeconds: 5
  
  s3:
    enabled: true
    bucket: "${DNS_RULES_BUCKET}"  # Same bucket as rules
    prefix: "audit-logs/"
    region: "${AWS_REGION}"
    batchInterval: "1h"
    compression: "gzip"
    retention: "90d"
  
  local:
    bufferSize: 10000  # In-memory buffer for reliability
    fallbackPath: "~/.dnshield/audit/buffer"
```

### Log Format
```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "host": "mac-001.company.com",
  "agent_version": "1.0.0",
  "event_type": "CERT_GENERATED",
  "severity": "info",
  "message": "Certificate generated for doubleclick.net",
  "details": {
    "domain": "doubleclick.net",
    "duration_ms": 45,
    "cached": false,
    "user": "jdoe",
    "process_id": 12345
  },
  "correlation_id": "uuid-here"
}
```

## Reliability Features

### Buffering Strategy
1. In-memory ring buffer (10k events)
2. Local disk spillover when Splunk unavailable
3. Automatic retry with exponential backoff

### Failure Modes
- **Splunk unavailable**: Buffer locally, retry
- **S3 unavailable**: Continue with Splunk only
- **Both unavailable**: Write to local audit files

## Security Considerations

### Sensitive Data
- Never log private keys or passwords
- Redact user credentials from config changes
- Hash sensitive domains if configured

### Transport Security
- TLS 1.2+ for Splunk HEC
- IAM roles for S3 access
- Encrypted tokens in config

## Monitoring

### Metrics to Track
- Log delivery success rate
- Buffer utilization
- Network failures
- Certificate generation patterns

### Alerting Rules (Splunk)
```spl
# Alert on certificate generation for critical domains
index=dnshield-audit event_type="CERT_GENERATED" 
| where match(domain, "^(.*\.)?(google\.com|github\.com|company\.com)$")
| alert

# Alert on repeated CA access failures
index=dnshield-audit event_type="CA_ACCESS" success=false
| bucket _time span=5m
| stats count by host
| where count > 5
| alert
```

## Performance Impact

### Expected Overhead
- CPU: < 1% for logging operations
- Memory: ~10MB for buffer
- Network: ~1KB/event average
- Disk I/O: Minimal (emergency buffer only)

### Optimization
- Async logging (non-blocking)
- Batch compression for S3
- Connection pooling for Splunk