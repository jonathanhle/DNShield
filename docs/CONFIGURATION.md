# Configuration Reference

DNShield uses YAML configuration files with sensible defaults. Configuration can be provided via file or environment variables.

## Configuration File Location

DNShield looks for configuration in the following order:
1. Command line flag: `--config /path/to/config.yaml`
2. Current directory: `./config.yaml`
3. System location: `/etc/dnshield/config.yaml`
4. Environment variable: `$DNSHIELD_CONFIG`

## Complete Configuration Reference

```yaml
# Agent configuration
agent:
  # DNS server port (requires root to bind to 53)
  dnsPort: 53
  
  # HTTP redirect server port
  httpPort: 80
  
  # HTTPS server port for block pages
  httpsPort: 443
  
  # Logging level: debug, info, warn, error
  logLevel: "info"
  
  # Allow users to pause DNS filtering (enterprise policy)
  allowPause: true
  
  # Allow users to disable DNS filtering entirely
  allowDisable: false

# DNS server configuration
dns:
  # Upstream DNS servers (tried in order)
  upstreams:
    - "1.1.1.1"          # Cloudflare
    - "1.0.0.1"          # Cloudflare secondary
    - "8.8.8.8"          # Google
    - "8.8.4.4"          # Google secondary
  
  # Cache configuration
  cacheSize: 10000       # Number of entries
  cacheTTL: "1h"         # Cache time-to-live
  
  # Query timeout for upstream servers
  timeout: "5s"

# S3 configuration for rule management
s3:
  # S3 bucket name containing rules
  bucket: "company-dns-rules"
  
  # AWS region
  region: "us-east-1"
  
  # Path to rules file in bucket
  rulesPath: "production/rules.yaml"
  
  # How often to check for rule updates
  updateInterval: "5m"
  
  # AWS credentials (optional - uses IAM role by default)
  # accessKeyId: "AKIAXXXXXXXX"
  # secretKey: "XXXXXXXX"

# Blocking configuration
blocking:
  # Default action: "block" or "allow"
  defaultAction: "block"
  
  # Block type: "sinkhole", "nxdomain", or "refused"
  blockType: "sinkhole"
  
  # TTL for blocked responses
  blockTTL: "10s"

# Test domains (remove in production)
testDomains:
  - "example-blocked.com"
  - "test.doubleclick.net"
```

## DNS Configuration Options

DNShield provides intelligent network-aware DNS management:

### Command Line Options

```bash
# Configure DNS on all interfaces
sudo ./dnshield configure-dns

# Restore previous DNS settings
sudo ./dnshield configure-dns --restore

# Force configuration without prompts
sudo ./dnshield configure-dns --force

# Run with automatic DNS configuration
sudo ./dnshield run --auto-configure-dns
```

### Auto-Configuration Behavior

When running with `--auto-configure-dns`:
- DNS is automatically set to 127.0.0.1 on all interfaces at startup
- DNS settings are monitored every minute
- Any changes are automatically corrected
- Previous settings are saved for restoration

### Network-Aware DNS Management

DNShield automatically:
- Detects network changes (WiFi, Ethernet, VPN)
- Stores DNS configuration per network
- Restores network-specific DNS when paused
- Handles sleep/wake cycles gracefully

Network configurations are stored in `~/.dnshield/network-dns/`

## Environment Variables

All configuration options can be set via environment variables:

```bash
# AWS credentials
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-east-1"

# Override config file location
export DNSHIELD_CONFIG="/etc/dnshield/config.yaml"

# Set log level
export LOG_LEVEL="debug"

# Enable v2.0 security mode (System Keychain storage)
export DNSHIELD_SECURITY_MODE="v2"
export DNSHIELD_USE_KEYCHAIN="true"
```

## S3 Rule File Format

The S3 rules file (`rules.yaml`) format:

```yaml
# Rule file version
version: "1.0"

# Last updated timestamp
updated: 2024-01-20T10:00:00Z

# External blocklist sources (fetched and parsed)
sources:
  - https://someonewhocares.org/hosts/zero/hosts
  - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
  - https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
  - s3://another-bucket/custom-blocklist.txt

# Direct domain blocks
domains:
  - "ads.example.com"
  - "tracking.company.com"
  - "*.doubleclick.net"         # Wildcard support
  - "~^ad[0-9]+\.example\.com$"  # Regex support (future)

# Never block these domains
whitelist:
  - "necessary-tracking.com"
  - "company-analytics.com"
  - "*.internal.company.com"

# Regex patterns (future feature)
regex:
  - "^track[0-9]+\."
  - ".*\.metric\.gstatic\.com$"
```

## Configuration Examples

### Minimal Configuration

```yaml
dns:
  upstreams: ["1.1.1.1"]
```

### Enterprise Configuration

```yaml
agent:
  logLevel: "info"

dns:
  upstreams:
    - "10.0.0.1"  # Internal DNS
    - "10.0.0.2"  # Internal DNS backup
    - "1.1.1.1"   # External fallback
  cacheSize: 50000
  cacheTTL: "4h"

s3:
  bucket: "company-dns-security"
  region: "us-east-1"
  rulesPath: "production/dns-rules.yaml"
  updateInterval: "1m"

blocking:
  defaultAction: "block"
  blockType: "sinkhole"
```

### Development Configuration

```yaml
agent:
  logLevel: "debug"

dns:
  upstreams: ["1.1.1.1"]
  cacheSize: 1000
  cacheTTL: "1m"

testDomains:
  - "test-blocked.local"
  - "malware-test.local"
  - "phishing-test.local"
```

## v2.0 Security Mode Configuration

For enterprise deployments with enhanced security:

```bash
# Enable v2.0 mode with System Keychain storage
export DNSHIELD_SECURITY_MODE="v2"
export DNSHIELD_USE_KEYCHAIN="true"

# Install CA (requires sudo for System Keychain)
sudo DNSHIELD_SECURITY_MODE=v2 DNSHIELD_USE_KEYCHAIN=true ./dnshield install-ca

# Run in v2 mode
sudo DNSHIELD_SECURITY_MODE=v2 DNSHIELD_USE_KEYCHAIN=true ./dnshield run
```

## Advanced Configuration

### Multiple Environment Support

Use different S3 paths for different environments:

```yaml
# Development
s3:
  rulesPath: "development/rules.yaml"

# Staging  
s3:
  rulesPath: "staging/rules.yaml"

# Production
s3:
  rulesPath: "production/rules.yaml"
```

### Custom Upstream Resolvers

```yaml
dns:
  upstreams:
    # DNS-over-HTTPS endpoints
    - "https://cloudflare-dns.com/dns-query"
    - "https://dns.google/dns-query"
    
    # DNS-over-TLS (future)
    - "tls://1.1.1.1"
    
    # Traditional DNS
    - "8.8.8.8:53"
```

### Performance Tuning

```yaml
# High-traffic environment
dns:
  cacheSize: 100000      # Larger cache
  cacheTTL: "6h"         # Longer TTL
  timeout: "2s"          # Faster timeout

# Low-memory environment  
dns:
  cacheSize: 1000        # Smaller cache
  cacheTTL: "30m"        # Shorter TTL
```

## Pause Functionality Configuration

Configure pause behavior:

```yaml
agent:
  allowPause: true       # Allow temporary pause
  allowDisable: false    # Prevent complete disable
```

When paused:
- DNShield restores the original DNS servers for the current network
- Each network's DNS configuration is remembered separately
- Automatic resume after specified duration (5min, 30min, 1hr)

## Validation

DNShield validates configuration on startup:
- Required fields must be present
- Port numbers must be valid (1-65535)
- Time durations must be parseable
- S3 bucket must be accessible
- DNS upstreams must be reachable

Invalid configuration will prevent startup with clear error messages.

## Hot Reload (Future)

Configuration hot reload is planned for v2.0:
```bash
# Send SIGHUP to reload configuration
kill -HUP <pid>

# Or use the CLI
dnshield reload
```