# DNShield Logging Setup Guide

This guide covers setting up remote logging for DNShield agents to send audit logs to Splunk and archive to S3.

## Prerequisites

- Splunk Enterprise/Cloud with admin access
- AWS S3 bucket (can use existing rules bucket)
- DNShield v1.0+ installed

## 1. Splunk HEC Configuration

### Step 1: Create HEC Token in Splunk

1. Log into Splunk Web UI as admin
2. Navigate to **Settings** → **Data Inputs**
3. Click **HTTP Event Collector**
4. Click **New Token**

5. Configure the token:
   ```
   Name: dnshield-audit
   Description: DNShield audit logging
   Source type: Manual → dnshield:audit
   ```

6. On Input Settings:
   ```
   Default Index: Create new → dnshield-audit
   (or use existing security/audit index)
   ```

7. Review and submit. Save the token value!

### Step 2: Configure HEC Settings

1. Go to **Settings** → **Data Inputs** → **HTTP Event Collector**
2. Click **Global Settings**
3. Ensure these settings:
   ```
   All Tokens: Enabled
   Default Source Type: json
   Default Index: main (or your preference)
   Use SSL: Yes (recommended)
   HTTP Port: 8088
   ```

### Step 3: Create Splunk Index (if new)

```bash
# Via CLI (on Splunk server)
splunk add index dnshield-audit \
  -maxDataSize 10000 \
  -maxHotBuckets 10 \
  -maxWarmDBCount 300

# Or via Web UI:
# Settings → Indexes → New Index
# Name: dnshield-audit
# Max Size: 500GB (adjust as needed)
# Retention: 90 days
```

### Step 4: Verify HEC Endpoint

Test the endpoint from a DNShield host:
```bash
# Test connectivity
curl -k https://splunk.company.com:8088/services/collector/health

# Test token (should return {"text":"Success","code":0})
curl -k https://splunk.company.com:8088/services/collector \
  -H "Authorization: Splunk YOUR-HEC-TOKEN" \
  -d '{"event": "test", "sourcetype": "manual"}'
```

## 2. DNShield Configuration

### Step 1: Set Environment Variables

Add to `/etc/environment` or your shell profile:
```bash
export SPLUNK_HEC_TOKEN="your-hec-token-here"
export AWS_REGION="us-east-1"  # If not using IAM role
```

### Step 2: Update config.yaml

```yaml
# Enable logging destinations
logging:
  splunk:
    enabled: true
    endpoint: "https://splunk.company.com:8088/services/collector"
    token: "${SPLUNK_HEC_TOKEN}"
    index: "dnshield-audit"
    sourcetype: "dnshield:audit"
    verifyServerCert: true  # Set false for self-signed certs
    retryMaxAttempts: 3
    retryBackoffSecs: 5
  
  s3:
    enabled: true
    batchInterval: "1h"
    compression: "gzip"
    retention: "90d"

# S3 configuration (if using same bucket)
s3:
  bucket: "company-dns-rules"
  region: "us-east-1"
  rulesPath: "production/rules.yaml"
  logPrefix: "audit-logs/"  # Logs go to different prefix
```

### Step 3: Restart DNShield

```bash
# Restart to apply configuration
sudo dnshield stop
sudo dnshield run --config /etc/dnshield/config.yaml
```

## 3. S3 Archive Setup

### Step 1: Configure S3 Bucket Policy

Add this policy to allow log uploads:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowDNShieldLogUpload",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT:role/dnshield-role"
      },
      "Action": [
        "s3:PutObject",
        "s3:PutObjectAcl"
      ],
      "Resource": "arn:aws:s3:::company-dns-rules/audit-logs/*"
    }
  ]
}
```

### Step 2: Set Up Lifecycle Policy (Optional)

Configure auto-deletion after retention period:
```json
{
  "Rules": [{
    "Id": "DeleteOldAuditLogs",
    "Status": "Enabled",
    "Prefix": "audit-logs/",
    "Expiration": {
      "Days": 90
    }
  }]
}
```

### Step 3: Configure IAM Role

If using IAM roles (recommended):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::company-dns-rules",
        "arn:aws:s3:::company-dns-rules/production/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::company-dns-rules/audit-logs/*"
    }
  ]
}
```

## 4. Testing and Verification

### Test Splunk Logging

1. Generate test events:
```bash
# Visit a blocked domain
curl -k https://doubleclick.net

# Check Splunk for events
index=dnshield-audit earliest=-5m
| table _time host event_type message details.domain
```

2. Verify event fields:
```spl
index=dnshield-audit 
| stats count by event_type
| sort -count
```

### Test S3 Archive

1. Wait for batch interval (1 hour) or restart DNShield to force upload
2. Check S3 bucket:
```bash
aws s3 ls s3://company-dns-rules/audit-logs/
# Should see: audit-mac-001.company.com-20240115-103045.json.gz

# Download and verify
aws s3 cp s3://company-dns-rules/audit-logs/audit-mac-001.company.com-20240115-103045.json.gz .
gunzip -c audit-*.json.gz | jq '.'
```

## 5. Monitoring and Alerts

### Splunk Alerts

Create alerts for security events:

1. **Certificate Generation for Critical Domains**
```spl
index=dnshield-audit event_type="CERT_GENERATED" 
| regex details.domain="^(.*\.)?(google\.com|github\.com|yourcompany\.com)$"
| table _time host user details.domain
```
Alert condition: When results > 0

2. **CA Access Failures**
```spl
index=dnshield-audit event_type="CA_ACCESS" details.success="false"
| bucket _time span=5m
| stats count by host
| where count > 5
```
Alert condition: When count > 5

3. **Service Disruptions**
```spl
index=dnshield-audit event_type="SERVICE_STOP"
| dedup host
| table _time host message
```
Alert condition: Real-time alert

### Dashboards

Create a DNShield dashboard with these panels:

1. **Event Volume**
```spl
index=dnshield-audit 
| timechart span=1h count by event_type
```

2. **Top Blocked Domains**
```spl
index=dnshield-audit event_type="CERT_GENERATED"
| top details.domain limit=20
```

3. **Agent Health**
```spl
index=dnshield-audit 
| stats latest(_time) as last_seen by host
| eval mins_ago=round((now()-last_seen)/60)
| where mins_ago > 10
```

## 6. Troubleshooting

### Splunk Connection Issues

1. **Check connectivity:**
```bash
# From DNShield host
telnet splunk.company.com 8088
curl -k https://splunk.company.com:8088/services/collector/health
```

2. **Verify token:**
```bash
# Check token is valid
curl -k -X POST https://splunk.company.com:8088/services/collector \
  -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
  -d '{"event": "test"}'
```

3. **Check DNShield logs:**
```bash
sudo journalctl -u dnshield -f | grep -i splunk
```

### S3 Upload Issues

1. **Verify permissions:**
```bash
# Test S3 access
aws s3 ls s3://company-dns-rules/audit-logs/
```

2. **Check credentials:**
```bash
# Verify AWS credentials
aws sts get-caller-identity
```

3. **Monitor upload logs:**
```bash
grep -i "s3\|upload" ~/.dnshield/audit/*.log
```

### Buffer Issues

If logs aren't being sent:

1. **Check buffer status:**
```bash
# Look for buffer overflow messages
grep -i buffer ~/.dnshield/audit/*.log
```

2. **Verify local fallback:**
```bash
ls -la ~/.dnshield/audit/buffer/
```

3. **Force flush (restart):**
```bash
sudo dnshield stop
# Logs will be flushed on shutdown
sudo dnshield run
```

## 7. Performance Tuning

### Optimize Splunk HEC

1. **Increase HEC limits** (if high volume):
```bash
# In limits.conf
[http_input]
max_content_length = 2097152  # 2MB
max_number_of_tokens = 10000
```

2. **Use load balancer** for multiple indexers:
```yaml
# In config.yaml
endpoint: "https://splunk-lb.company.com:8088/services/collector"
```

### Optimize S3 Uploads

1. **Adjust batch interval** based on volume:
```yaml
s3:
  batchInterval: "30m"  # More frequent for high volume
```

2. **Increase buffer size** if needed:
```yaml
local:
  bufferSize: 50000  # For high-volume environments
```

## 8. Security Best Practices

1. **Rotate HEC tokens** quarterly:
   - Create new token in Splunk
   - Update DNShield config
   - Disable old token after verification

2. **Use TLS everywhere**:
   - Splunk HEC over HTTPS
   - S3 uploads use TLS by default

3. **Restrict network access**:
   - Firewall rules for HEC port (8088)
   - S3 bucket policies with IP restrictions

4. **Monitor for anomalies**:
   ```spl
   index=dnshield-audit 
   | eval hour=strftime(_time,"%H")
   | where hour<6 OR hour>22
   | stats count by host event_type
   ```

## Next Steps

1. Set up Splunk alerts for your security team
2. Create compliance reports using S3 archives
3. Integrate with SIEM/SOAR platforms
4. Configure retention policies based on compliance needs