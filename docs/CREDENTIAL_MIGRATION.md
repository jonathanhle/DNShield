# AWS Credential Migration Guide

## Overview

Starting with DNShield v2.0, storing AWS credentials in the configuration file is deprecated for security reasons. This guide helps you migrate to secure credential management.

## Why This Change?

Storing credentials in configuration files poses significant security risks:
- Credentials can be accidentally committed to version control
- Configuration files are often shared or copied without sanitization
- Plaintext credentials are visible to anyone with file system access
- Credentials cannot be rotated without updating config files

## Migration Steps

### Option 1: Environment Variables (Recommended for Development)

1. Remove `accessKeyId` and `secretKey` from your `config.yaml`
2. Set environment variables:
   ```bash
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"
   export AWS_REGION="us-east-1"
   ```
3. Add to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.) for persistence

### Option 2: IAM Roles (Recommended for Production)

For EC2 instances:
1. Create an IAM role with S3 read permissions
2. Attach the role to your EC2 instance
3. Remove all credential configuration - DNShield will automatically use the role

For ECS/Fargate:
1. Create an IAM role with S3 read permissions
2. Assign the role to your task definition
3. No credential configuration needed

### Option 3: AWS CLI Credentials File

1. Configure AWS CLI: `aws configure`
2. Credentials will be stored in `~/.aws/credentials`
3. DNShield will automatically use these credentials

## Security Best Practices

1. **Never commit credentials** to version control
2. **Use IAM roles** whenever possible (EC2, ECS, Lambda)
3. **Rotate credentials** regularly
4. **Use minimal permissions** - only grant S3 read access to specific buckets
5. **Monitor access** using AWS CloudTrail

## Example IAM Policy

Minimal permissions for DNShield:

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
        "arn:aws:s3:::your-dns-rules-bucket",
        "arn:aws:s3:::your-dns-rules-bucket/*"
      ]
    }
  ]
}
```

## Verification

After migration, DNShield will log the credential source on startup:
- `Using AWS credentials from: iam-role` - Using IAM role (most secure)
- `Using AWS credentials from: environment` - Using environment variables
- `Using AWS credentials from: config` - Using config file (deprecated, will show warning)

## Troubleshooting

If DNShield cannot access S3 after migration:

1. Check DNShield logs for credential source
2. Verify environment variables are set: `env | grep AWS`
3. Test AWS access: `aws s3 ls s3://your-bucket/`
4. Check IAM role permissions in AWS Console

## Timeline

- **v2.0**: Config file credentials deprecated with warnings
- **v3.0**: Config file credential support will be removed

Please migrate as soon as possible to ensure continued functionality.