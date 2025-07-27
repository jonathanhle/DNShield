# Enterprise DNS Filtering with DNShield

This guide explains how to configure DNShield for enterprise deployments with user-based policies.

## Overview

The enterprise configuration allows you to:
- Assign different DNS filtering rules based on user identity
- Group users into policy groups (marketing, engineering, etc.)
- Override rules for specific users
- Track which user/device triggered DNS blocks
- Scale to 1000+ endpoints efficiently

## S3 Bucket Structure

```
company-dns-rules/
├── base.yaml                    # Base rules for everyone
├── groups/
│   ├── marketing.yaml          # Marketing team rules
│   ├── engineering.yaml        # Engineering team rules
│   ├── finance.yaml           # Finance team rules
│   ├── executives.yaml        # Executive team rules
│   └── restricted.yaml        # Restricted access (contractors/guests)
└── users/
    ├── device-mapping.yaml     # User → Devices mapping
    ├── user-groups.yaml        # User → Group assignment
    └── overrides/              # Per-user rule overrides
        └── john.doe@company.com.yaml
```

## How It Works

1. **Device Identity**: Each DNShield client identifies itself by hostname
2. **User Lookup**: The hostname is matched to a user email in `device-mapping.yaml`
3. **Group Resolution**: The user's group is determined from `user-groups.yaml`
4. **Rule Assembly**: Rules are loaded in order:
   - Base rules (everyone)
   - Group rules (if applicable)
   - User overrides (if exist)
5. **Rule Precedence**: Allowlist always wins over blocklist

## Configuration

### 1. Update config.yaml

Use the enterprise configuration:

```yaml
s3:
  bucket: "company-dns-rules"
  region: "us-east-1"
  updateInterval: "5m"
  updateJitter: "30s"  # Prevents thundering herd
  
  paths:
    base: "base.yaml"
    deviceMapping: "users/device-mapping.yaml"
    userGroups: "users/user-groups.yaml"
    groupsDir: "groups/"
    userOverridesDir: "users/overrides/"
```

### 2. Create S3 Bucket

```bash
aws s3 mb s3://company-dns-rules
```

### 3. Upload Example Files

```bash
# Upload the example structure
aws s3 sync examples/s3-structure/ s3://company-dns-rules/
```

## File Formats

### base.yaml
```yaml
version: "2024.01.15"
description: "Base blocking rules applied to all clients"

block_domains:
  - doubleclick.net
  - malware-site.com

block_sources:  # External blocklists
  - https://someonewhocares.org/hosts/hosts

allow_domains:  # Never block these
  - company-intranet.com
```

### users/device-mapping.yaml
```yaml
version: "2024.01.15"
description: "Maps users to their devices"

users:
  john.doe@company.com:
    devices:
      - "Johns-MacBook-Pro"
      - "johns-imac"
```

### users/user-groups.yaml
```yaml
version: "2024.01.15"
description: "Maps users to policy groups"

group_assignments:
  marketing:
    - john.doe@company.com
    - "*@marketing.company.com"
  
  engineering:
    - sarah.smith@company.com
    - "*@eng.company.com"

user_overrides:  # Direct assignments
  contractor1@external.com: restricted
```

### groups/marketing.yaml
```yaml
version: "2024.01.15"
description: "Additional rules for marketing team"

allow_domains:  # Marketing needs social media
  - facebook.com
  - twitter.com
  - linkedin.com
```

## Allow-Only Mode (High Security)

For highly restricted environments, you can enable "allow-only mode" where EVERYTHING is blocked except explicitly allowed domains.

### Use Cases
- Kiosk computers
- Contractor workstations  
- Public terminals
- High-security environments
- Compliance requirements (PCI, HIPAA)

### Configuration

Enable in any rules file:
```yaml
version: "2024.01.15"
description: "Restricted access - Allow-only mode"

# This enables allow-only mode
allow_only_mode: true

# ONLY these domains are accessible
allow_domains:
  - company-portal.com
  - timesheet.company.com
  - wiki.company.com
  - google.com  # For search only
  
# In allow-only mode, these are ignored:
block_domains: []     # Ignored
block_sources: []     # Ignored
```

### How It Works
1. When `allow_only_mode: true` is set in ANY applicable rule file (base, group, or user)
2. The system blocks ALL domains except those in `allow_domains`
3. Allowlists are merged from all sources (base + group + user)
4. External blocklists are NOT downloaded to save bandwidth

### Example: Restricted Group
```yaml
# groups/restricted.yaml
version: "2024.01.15"
description: "Contractors and kiosks - Maximum restrictions"

allow_only_mode: true

allow_domains:
  # Work tools only
  - jira.company.com
  - github.com
  - stackoverflow.com
  
  # Essential services
  - google.com
  - wikipedia.org
```

## Deployment

### 1. Test Configuration Locally

```bash
# Use the enterprise config
sudo ./dnshield run -c config-enterprise.yaml
```

### 2. Monitor Logs

Logs now include user/group information:

```
INFO[0001] Blocked domain                               domain=facebook.com user=john.doe@company.com group=engineering
```

### 3. Unknown Devices

Devices not in `device-mapping.yaml` get base rules only:

```
WARN[0001] Device not found in mapping, applying base rules only  device=unknown-laptop
```

## Managing Rules

### Add a New User

1. Add device mapping in `users/device-mapping.yaml`:
```yaml
new.user@company.com:
  devices:
    - "new-user-laptop"
```

2. Assign to group in `users/user-groups.yaml`:
```yaml
group_assignments:
  engineering:
    - new.user@company.com
```

### Create User Override

Create `users/overrides/new.user@company.com.yaml`:
```yaml
version: "2024.01.15"
description: "Specific rules for new.user@company.com"

allow_domains:
  - special-tool.com
```

### Update Rules

Changes are picked up automatically every 5 minutes (+ random jitter).

## Performance

- **ETag Caching**: Only downloads changed files
- **Update Jitter**: Random 0-30s delay prevents thundering herd
- **Efficient Lookups**: Rules are indexed in memory
- **S3 Costs**: ~$0.004 per 1000 requests

## Monitoring

### Blocked Domains by User
```bash
grep "Blocked domain" /var/log/dnshield.log | grep "user=john.doe"
```

### Unknown Devices
```bash
grep "Device not found in mapping" /var/log/dnshield.log
```

### Rule Updates
```bash
grep "Enterprise rules updated" /var/log/dnshield.log
```

### Allow-Only Mode
```bash
# See which users/groups are in allow-only mode
grep "mode=allow-only" /var/log/dnshield.log

# Example log output:
# INFO Enterprise rules updated blocked=1000 allowed=25 user=contractor1@external.com group=restricted mode=allow-only
```

## Troubleshooting

### Device Not Getting Correct Rules

1. Check device name:
```bash
hostname
```

2. Verify in `device-mapping.yaml`
3. Check user group assignment
4. Look for override files

### Rules Not Updating

1. Check S3 connectivity
2. Verify IAM permissions
3. Check ETag cache is working
4. Look for update errors in logs

## Security

- S3 bucket should have restricted access
- Use IAM roles on EC2/endpoints
- Enable S3 access logging
- Version control rule files
- Review unknown devices regularly