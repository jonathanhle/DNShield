# API Role-Based Access Control (RBAC)

DNShield now includes role-based access control for the API to ensure secure configuration management and prevent unauthorized access to sensitive operations.

## Overview

The RBAC system provides three roles with different permission levels:

- **Admin**: Full access to all API endpoints, including configuration modification
- **Operator**: Can control DNS operations (pause/resume, refresh rules, clear cache) but cannot modify configuration
- **Viewer**: Read-only access to status and statistics

## Generating API Keys

Use the `dnshield apikey` command to manage API keys:

```bash
# Generate an admin key (never expires)
sudo ./dnshield apikey generate --role admin

# Generate an operator key with 30-day expiration
sudo ./dnshield apikey generate --role operator --expires 30d

# Generate a viewer key with 24-hour expiration
sudo ./dnshield apikey generate --role viewer --expires 24h

# List all API keys
sudo ./dnshield apikey list

# Revoke an API key (using first 16 characters)
sudo ./dnshield apikey revoke 1234567890abcdef
```

## Using API Keys

Include the API key in the Authorization header:

```bash
# Example: Get status (viewer access)
curl -H "Authorization: Bearer YOUR_API_KEY_HERE" \
  http://localhost:5353/api/status

# Example: Pause protection (operator access)
curl -X POST \
  -H "Authorization: Bearer YOUR_API_KEY_HERE" \
  -H "Content-Type: application/json" \
  -d '{"duration": "30m"}' \
  http://localhost:5353/api/pause

# Example: Update configuration (admin access only)
curl -X PUT \
  -H "Authorization: Bearer YOUR_API_KEY_HERE" \
  -H "Content-Type: application/json" \
  -d '{"allow_pause": false}' \
  http://localhost:5353/api/config/update
```

## Permission Matrix

| Endpoint | Admin | Operator | Viewer | Description |
|----------|-------|----------|---------|-------------|
| GET /api/health | ✓ | ✓ | ✓ | Public endpoint (no auth required) |
| GET /api/status | ✓ | ✓ | ✓ | View protection status |
| GET /api/statistics | ✓ | ✓ | ✓ | View DNS statistics |
| GET /api/recent-blocked | ✓ | ✓ | ✓ | View recently blocked domains |
| GET /api/config | ✓ | ✓ | ✓ | View current configuration |
| PUT /api/config/update | ✓ | ✗ | ✗ | Modify configuration |
| POST /api/pause | ✓ | ✓ | ✗ | Pause DNS protection |
| POST /api/resume | ✓ | ✓ | ✗ | Resume DNS protection |
| POST /api/refresh-rules | ✓ | ✓ | ✗ | Refresh blocking rules |
| POST /api/clear-cache | ✓ | ✓ | ✗ | Clear DNS cache |

## Security Considerations

1. **Key Storage**: API keys are stored in `~/.dnshield/api_keys.json` with file permissions 0600
2. **Key Format**: Keys are 64-character hexadecimal strings (256-bit entropy)
3. **Expiration**: Keys can have optional expiration times
4. **Revocation**: Keys can be revoked without deletion (marked as disabled)
5. **Audit Logging**: All configuration changes are logged with the role and IP address

## Migration from Unauthenticated API

If you have existing integrations using the API without authentication:

1. Generate appropriate API keys for your use cases
2. Update your scripts/applications to include the Authorization header
3. Test thoroughly before deploying to production

## Example Integration

### Menu Bar App Integration
```swift
// Add to your API client
let apiKey = "YOUR_API_KEY_HERE"
var request = URLRequest(url: url)
request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
```

### Python Script Integration
```python
import requests

API_KEY = "YOUR_API_KEY_HERE"
headers = {"Authorization": f"Bearer {API_KEY}"}

# Get status
response = requests.get("http://localhost:5353/api/status", headers=headers)
```

### Shell Script Integration
```bash
#!/bin/bash
API_KEY="YOUR_API_KEY_HERE"

# Pause protection
curl -X POST \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"duration": "30m"}' \
  http://localhost:5353/api/pause
```

## Best Practices

1. **Principle of Least Privilege**: Generate keys with the minimum required role
2. **Key Rotation**: Regularly rotate API keys, especially for admin access
3. **Secure Storage**: Store API keys securely, never commit them to version control
4. **Monitoring**: Monitor API access logs for suspicious activity
5. **Expiration**: Use expiring keys for temporary access or scripts