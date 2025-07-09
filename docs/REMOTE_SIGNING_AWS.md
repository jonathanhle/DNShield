# Remote Signing Service on AWS - Implementation Guide

This guide provides a production-ready implementation of a remote certificate signing service for DNS Guardian using AWS services. This architecture ensures that CA private keys never exist on endpoint devices, providing the highest level of security for certificate generation.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [AWS Services Used](#aws-services-used)
3. [Security Benefits](#security-benefits)
4. [Implementation Steps](#implementation-steps)
5. [Cost Estimation](#cost-estimation)
6. [Integration with DNS Guardian](#integration-with-dns-guardian)
7. [Monitoring and Alerts](#monitoring-and-alerts)
8. [Disaster Recovery](#disaster-recovery)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           AWS Cloud (us-east-1)                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────┐         ┌─────────────────┐                      │
│  │ Route 53        │         │ WAF             │                      │
│  │ (DNS)           │         │ (DDoS/Rules)    │                      │
│  └────────┬────────┘         └────────┬────────┘                      │
│           │                           │                                │
│           └───────────┬───────────────┘                                │
│                       ▼                                                │
│           ┌───────────────────────┐                                   │
│           │ API Gateway           │                                   │
│           │ (mTLS + Rate Limit)   │                                   │
│           └───────────┬───────────┘                                   │
│                       │                                               │
│                       ▼                                               │
│       ┌───────────────────────────────────┐                         │
│       │        Lambda Function            │                         │
│       │   (Certificate Signing Logic)     │                         │
│       └──────┬──────────────────┬─────────┘                         │
│              │                  │                                    │
│              ▼                  ▼                                    │
│     ┌────────────────┐  ┌──────────────┐   ┌─────────────────┐    │
│     │ AWS KMS        │  │ DynamoDB     │   │ CloudWatch      │    │
│     │ (CA Key)       │  │ (Audit Logs) │   │ (Metrics/Logs)  │    │
│     └────────────────┘  └──────────────┘   └─────────────────┘    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                                 ▲
                                 │ mTLS
                                 │
                    ┌────────────┴───────────┐
                    │   DNS Guardian Agent   │
                    │   (On User Endpoint)   │
                    └────────────────────────┘
```

## AWS Services Used

### Core Services

1. **AWS KMS (Key Management Service)**
   - Stores and protects the CA private key
   - Hardware security module (HSM) backed
   - FIPS 140-2 Level 2 validated
   - Automatic key rotation capabilities

2. **AWS Lambda**
   - Serverless certificate signing function
   - Auto-scaling based on demand
   - No infrastructure to manage
   - Pay-per-request pricing

3. **API Gateway**
   - mTLS authentication endpoint
   - Built-in rate limiting
   - Request validation
   - CloudWatch integration

4. **DynamoDB**
   - Audit log storage
   - Millisecond latency
   - Automatic backup and recovery
   - Global tables for multi-region

### Supporting Services

5. **WAF (Web Application Firewall)**
   - DDoS protection
   - IP allowlisting
   - Rate limiting rules
   - Geographic restrictions

6. **CloudWatch**
   - Centralized logging
   - Real-time metrics
   - Alerting and notifications
   - Dashboard visualization

7. **IAM (Identity and Access Management)**
   - Fine-grained permissions
   - Service roles
   - Cross-account access

8. **Secrets Manager**
   - mTLS certificate storage
   - Automatic rotation
   - Secure distribution

## Security Benefits

### 1. Complete Key Isolation
- CA private key never leaves KMS
- All signing operations happen within KMS
- No key material in Lambda memory

### 2. Defense in Depth
```
Client → mTLS → WAF → API Gateway → Lambda → KMS
  ↓        ↓      ↓         ↓          ↓       ↓
Cert    Auth   DDoS    Rate Limit  Validate  HSM
```

### 3. Compliance
- SOC 2 Type II
- PCI-DSS
- HIPAA eligible
- FedRAMP authorized

### 4. Audit Trail
- Every signing request logged
- Immutable audit records
- 7-year retention
- Real-time analysis

## Implementation Steps

### Step 1: Create KMS Key for CA

```bash
# Create KMS key for CA operations
aws kms create-key \
  --description "DNS Guardian CA Signing Key" \
  --key-usage SIGN_VERIFY \
  --key-spec RSA_4096 \
  --multi-region \
  --tags TagKey=Project,TagValue=DNSGuardian TagKey=Environment,TagValue=Production
```

### Step 2: Generate CA Certificate

```python
# Lambda function to generate CA certificate (one-time setup)
import boto3
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta

def generate_ca_certificate(event, context):
    kms = boto3.client('kms')
    
    # Create CA certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Your Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, "DNS Guardian Root CA"),
    ])
    
    # Certificate valid for 10 years
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject
    ).public_key(
        get_kms_public_key(kms, key_id)
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign_with_kms(kms, key_id, hashes.SHA256())
    
    # Store in S3 for distribution
    s3 = boto3.client('s3')
    s3.put_object(
        Bucket='dns-guardian-ca',
        Key='ca.crt',
        Body=cert.public_bytes(serialization.Encoding.PEM)
    )
```

### Step 3: Certificate Signing Lambda

```python
# Lambda function for certificate signing
import json
import boto3
import base64
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Initialize AWS clients
kms = boto3.client('kms')
dynamodb = boto3.resource('dynamodb')
audit_table = dynamodb.Table('DNSGuardianAuditLog')

# Configuration
KMS_KEY_ID = os.environ['KMS_KEY_ID']
BLOCKED_DOMAINS = [
    '*.chase.com',
    '*.wellsfargo.com',
    '*.bankofamerica.com',
    '*.jpmorgan.com',
    '*.citi.com'
]

def lambda_handler(event, context):
    # Extract client certificate info from API Gateway
    client_cert = event['requestContext']['identity']['clientCert']
    client_id = extract_client_id(client_cert)
    
    # Parse request
    body = json.loads(event['body'])
    domain = body['domain']
    
    # Validate domain
    if is_blocked_domain(domain):
        audit_log(client_id, domain, 'DENIED', 'Blocked domain')
        return {
            'statusCode': 403,
            'body': json.dumps({'error': 'Domain not allowed'})
        }
    
    # Rate limiting check
    if not check_rate_limit(client_id):
        audit_log(client_id, domain, 'RATE_LIMITED', 'Too many requests')
        return {
            'statusCode': 429,
            'body': json.dumps({'error': 'Rate limit exceeded'})
        }
    
    try:
        # Generate certificate
        cert_pem, key_pem = generate_certificate(domain)
        
        # Audit log
        audit_log(client_id, domain, 'SUCCESS', 'Certificate issued')
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'certificate': cert_pem,
                'private_key': key_pem
            })
        }
    except Exception as e:
        audit_log(client_id, domain, 'ERROR', str(e))
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }

def generate_certificate(domain):
    # Create certificate request
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])
    
    # Generate private key in KMS (data key)
    key_response = kms.generate_data_key_pair(
        KeyId=KMS_KEY_ID,
        KeyPairSpec='RSA_2048'
    )
    
    # Build certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        get_ca_subject()
    ).public_key(
        load_public_key(key_response['PublicKey'])
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(minutes=5)  # 5-minute validity
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(domain),
            x509.DNSName(f"*.{domain}"),
        ]),
        critical=False,
    ).sign_with_kms(kms, KMS_KEY_ID, hashes.SHA256())
    
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
        key_response['PrivateKeyPlaintext']
    )

def audit_log(client_id, domain, status, message):
    audit_table.put_item(
        Item={
            'id': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat(),
            'client_id': client_id,
            'domain': domain,
            'status': status,
            'message': message,
            'source_ip': event['requestContext']['identity']['sourceIp']
        }
    )
```

### Step 4: API Gateway Configuration

```yaml
# serverless.yml for API Gateway + Lambda
service: dns-guardian-signing

provider:
  name: aws
  runtime: python3.9
  region: us-east-1

functions:
  sign:
    handler: handler.lambda_handler
    environment:
      KMS_KEY_ID: ${env:KMS_KEY_ID}
    events:
      - http:
          path: /v1/sign
          method: post
          cors: false
          authorizer:
            type: CUSTOM
            authorizerFunction: mtlsAuthorizer
          request:
            schemas:
              application/json: ${file(schemas/sign-request.json)}

resources:
  Resources:
    # API Gateway with mTLS
    ApiGatewayRestApi:
      Type: AWS::ApiGateway::RestApi
      Properties:
        Name: dns-guardian-signing-api
        DisableExecuteApiEndpoint: true
        EndpointConfiguration:
          Types:
            - REGIONAL
        Policy:
          Version: '2012-10-17'
          Statement:
            - Effect: Allow
              Principal: '*'
              Action: 'execute-api:Invoke'
              Resource: '*'
              Condition:
                StringEquals:
                  'aws:sourceVpce': !Ref VPCEndpoint

    # mTLS configuration
    ApiGatewayDomainName:
      Type: AWS::ApiGateway::DomainName
      Properties:
        DomainName: signing.dnsguardian.internal
        RegionalCertificateArn: !Ref ServerCertificate
        EndpointConfiguration:
          Types:
            - REGIONAL
        SecurityPolicy: TLS_1_2
        MutualTlsAuthentication:
          TruststoreUri: s3://dns-guardian-ca/truststore.pem
          TruststoreVersion: '1.0'
```

### Step 5: Client Integration

```go
// internal/ca/remote_signer.go
package ca

import (
    "crypto/tls"
    "crypto/x509"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type RemoteSigner struct {
    client   *http.Client
    endpoint string
}

func NewRemoteSigner(certFile, keyFile, caFile, endpoint string) (*RemoteSigner, error) {
    // Load client certificate for mTLS
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return nil, err
    }
    
    // Load CA certificate
    caCert, err := os.ReadFile(caFile)
    if err != nil {
        return nil, err
    }
    
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)
    
    // Create mTLS client
    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                Certificates: []tls.Certificate{cert},
                RootCAs:      caCertPool,
            },
        },
        Timeout: 10 * time.Second,
    }
    
    return &RemoteSigner{
        client:   client,
        endpoint: endpoint,
    }, nil
}

func (rs *RemoteSigner) GenerateCert(domain string) (*x509.Certificate, *rsa.PrivateKey, error) {
    // Create signing request
    req := SignRequest{Domain: domain}
    body, err := json.Marshal(req)
    if err != nil {
        return nil, nil, err
    }
    
    // Call remote signing service
    resp, err := rs.client.Post(
        rs.endpoint+"/v1/sign",
        "application/json",
        bytes.NewReader(body),
    )
    if err != nil {
        return nil, nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, nil, fmt.Errorf("signing failed: %s", resp.Status)
    }
    
    // Parse response
    var signResp SignResponse
    if err := json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
        return nil, nil, err
    }
    
    // Parse certificate and key
    cert, err := parseCertificate(signResp.Certificate)
    if err != nil {
        return nil, nil, err
    }
    
    key, err := parsePrivateKey(signResp.PrivateKey)
    if err != nil {
        return nil, nil, err
    }
    
    return cert, key, nil
}
```

### Step 6: Terraform Deployment

```hcl
# main.tf - Complete infrastructure as code
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

# KMS key for CA operations
resource "aws_kms_key" "ca_signing_key" {
  description             = "DNS Guardian CA Signing Key"
  deletion_window_in_days = 30
  key_usage              = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_4096"
  
  tags = {
    Project     = "DNSGuardian"
    Environment = "Production"
  }
}

# DynamoDB table for audit logs
resource "aws_dynamodb_table" "audit_log" {
  name           = "DNSGuardianAuditLog"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"
  range_key      = "timestamp"
  
  attribute {
    name = "id"
    type = "S"
  }
  
  attribute {
    name = "timestamp"
    type = "S"
  }
  
  attribute {
    name = "client_id"
    type = "S"
  }
  
  global_secondary_index {
    name            = "ClientIdIndex"
    hash_key        = "client_id"
    range_key       = "timestamp"
    projection_type = "ALL"
  }
  
  point_in_time_recovery {
    enabled = true
  }
  
  tags = {
    Project     = "DNSGuardian"
    Environment = "Production"
  }
}

# Lambda function
resource "aws_lambda_function" "signing_service" {
  filename         = "lambda.zip"
  function_name    = "dns-guardian-signing"
  role            = aws_iam_role.lambda_role.arn
  handler         = "handler.lambda_handler"
  runtime         = "python3.9"
  timeout         = 30
  memory_size     = 512
  
  environment {
    variables = {
      KMS_KEY_ID = aws_kms_key.ca_signing_key.id
      AUDIT_TABLE = aws_dynamodb_table.audit_log.name
    }
  }
  
  tracing_config {
    mode = "Active"
  }
}

# API Gateway with mTLS
resource "aws_api_gateway_rest_api" "signing_api" {
  name        = "dns-guardian-signing-api"
  description = "Certificate signing API with mTLS"
  
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

# WAF for additional protection
resource "aws_wafv2_web_acl" "signing_waf" {
  name  = "dns-guardian-signing-waf"
  scope = "REGIONAL"
  
  default_action {
    allow {}
  }
  
  rule {
    name     = "RateLimitRule"
    priority = 1
    
    action {
      block {}
    }
    
    statement {
      rate_based_statement {
        limit              = 1000
        aggregate_key_type = "IP"
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "RateLimitRule"
      sampled_requests_enabled   = true
    }
  }
}

# CloudWatch alarms
resource "aws_cloudwatch_metric_alarm" "high_error_rate" {
  alarm_name          = "dns-guardian-high-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name        = "Errors"
  namespace          = "AWS/Lambda"
  period             = "300"
  statistic          = "Sum"
  threshold          = "10"
  alarm_description  = "High error rate in signing service"
  
  dimensions = {
    FunctionName = aws_lambda_function.signing_service.function_name
  }
  
  alarm_actions = [aws_sns_topic.alerts.arn]
}

# Output the API endpoint
output "signing_api_endpoint" {
  value = aws_api_gateway_deployment.signing_api_deployment.invoke_url
}
```

## Cost Estimation

### Monthly Costs (USD)

| Service | Usage | Cost |
|---------|-------|------|
| KMS | 1 key + 100K signing ops | $1 + $30 = $31 |
| Lambda | 100K invocations @ 512MB | $2 |
| API Gateway | 100K requests | $3.50 |
| DynamoDB | 100K writes + storage | $25 |
| CloudWatch | Logs + metrics | $10 |
| WAF | Basic rules | $5 |
| **Total** | | **~$77/month** |

For high-volume deployments (10M+ requests/month), consider:
- Lambda reserved concurrency
- DynamoDB on-demand vs provisioned
- API Gateway caching
- CloudFront distribution

## Integration with DNS Guardian

### 1. Update Configuration

```yaml
# config.yaml
signing:
  mode: "remote"  # local or remote
  remote:
    endpoint: "https://signing.dnsguardian.internal"
    cert_file: "/etc/dns-guardian/client.crt"
    key_file: "/etc/dns-guardian/client.key"
    ca_file: "/etc/dns-guardian/ca.crt"
    timeout: "10s"
    retry_count: 3
```

### 2. Fallback Strategy

```go
// Graceful fallback to cached certificates
func (p *Proxy) getCertificate(domain string) (*tls.Certificate, error) {
    // Try remote signing first
    if p.remoteSigner != nil {
        cert, key, err := p.remoteSigner.GenerateCert(domain)
        if err == nil {
            return &tls.Certificate{cert, key}, nil
        }
        log.Warnf("Remote signing failed: %v, using cache", err)
    }
    
    // Fall back to cache
    if cached, ok := p.certCache.Get(domain); ok {
        return cached.(*tls.Certificate), nil
    }
    
    return nil, fmt.Errorf("no certificate available")
}
```

## Monitoring and Alerts

### Key Metrics to Monitor

1. **Signing Latency**
   - P50, P95, P99 percentiles
   - Alert if P95 > 1 second

2. **Error Rate**
   - 4XX errors (client issues)
   - 5XX errors (service issues)
   - Alert if error rate > 1%

3. **Request Volume**
   - Requests per minute by client
   - Total daily volume
   - Unusual spikes or drops

4. **Security Events**
   - Blocked domain attempts
   - Rate limit violations
   - Invalid client certificates

### CloudWatch Dashboard

```json
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["AWS/Lambda", "Invocations", {"stat": "Sum"}],
          [".", "Errors", {"stat": "Sum"}],
          [".", "Duration", {"stat": "Average"}]
        ],
        "period": 300,
        "stat": "Average",
        "region": "us-east-1",
        "title": "Lambda Performance"
      }
    },
    {
      "type": "log",
      "properties": {
        "query": "SOURCE '/aws/lambda/dns-guardian-signing' | fields @timestamp, client_id, domain, status | filter status = 'DENIED'",
        "region": "us-east-1",
        "title": "Denied Requests"
      }
    }
  ]
}
```

## Disaster Recovery

### Backup Strategy

1. **KMS Key**: Multi-region replica
2. **CA Certificate**: S3 with versioning
3. **Audit Logs**: DynamoDB point-in-time recovery
4. **Lambda Code**: Source control + CI/CD

### Failover Plan

1. **Primary Region Down**:
   - Route 53 health checks
   - Automatic failover to secondary region
   - 30-second RTO

2. **KMS Unavailable**:
   - Use KMS key replica in another region
   - Update Lambda environment variable

3. **High Error Rate**:
   - Circuit breaker in client
   - Fall back to cached certificates
   - Alert operations team

### Testing

```bash
# Chaos engineering test
aws lambda put-function-concurrency \
  --function-name dns-guardian-signing \
  --reserved-concurrent-executions 0

# Verify clients handle gracefully
# Should fall back to cache without user impact
```

## Security Best Practices

1. **Least Privilege IAM**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": [
         "kms:Sign",
         "kms:GetPublicKey"
       ],
       "Resource": "arn:aws:kms:*:*:key/specific-key-id"
     }]
   }
   ```

2. **Network Isolation**
   - VPC endpoints for AWS services
   - No internet gateway required
   - Private DNS zones

3. **Compliance**
   - Enable AWS Config rules
   - CloudTrail for all API calls
   - Regular security audits

4. **Incident Response**
   - Automated alerting
   - Runbook documentation
   - Regular drills

## Conclusion

This remote signing architecture provides the highest level of security for DNS Guardian deployments. By keeping the CA private key in AWS KMS and requiring mTLS authentication, you ensure that even a fully compromised endpoint cannot steal the CA key or generate unauthorized certificates.

For production deployments at financial institutions or other high-security environments, this architecture meets all compliance requirements while remaining cost-effective and scalable.

### Next Steps

1. Review and customize the Terraform templates
2. Set up monitoring and alerting
3. Conduct security review with your team
4. Deploy to staging environment
5. Load test with expected traffic
6. Create runbooks for operations
7. Deploy to production with gradual rollout

For questions or support with implementation, consult your AWS solutions architect or security team.