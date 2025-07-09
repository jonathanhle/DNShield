# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DNShield is an enterprise DNS filtering solution with transparent HTTPS interception for macOS. It's a single-binary Go application that provides DNS-level ad blocking with dynamic certificate generation, eliminating browser certificate warnings for blocked sites.

## Key Commands

### Build and Development
```bash
# Build the binary
make build

# Run with sudo (required for port 53/443)
make run

# Run with automatic DNS configuration on all interfaces
make run-auto

# Format code
make fmt

# Download dependencies
make deps

# Run tests (note: no tests currently exist)
make test

# Build universal binary (Intel + Apple Silicon)
make build-universal

# Build with code signing for production
make build-signed  # Requires Apple Developer ID

# Create distribution package with universal binary
make dist

# Demo setup (install + instructions)
make demo
```

### Installation Modes
```bash
# Standard Mode - File-based CA storage (simpler)
make install

# Secure Mode - System Keychain CA storage (enterprise-ready)
make install-secure

# Complete secure setup and run with auto DNS in one command
make secure

# Check current mode
make show-mode

# Complete cleanup
make uninstall
```

### DNS Configuration
```bash
# Configure DNS on all interfaces to 127.0.0.1
make configure-dns

# Restore previous DNS settings
make restore-dns

# Or use the command directly
sudo ./dnshield configure-dns
sudo ./dnshield configure-dns --restore
```

### Testing Blocked Domains
```bash
# Test blocking (after DNS is configured)
curl -I https://doubleclick.net  # Should show block page
```

## Architecture

### Project Structure
```
single-binary-version/
├── cmd/                 # CLI command implementations
│   ├── install_ca.go   # CA certificate installation
│   ├── run.go          # Main DNS server runtime
│   ├── status.go       # Service status checking
│   └── uninstall.go    # Uninstallation logic
├── internal/           # Core packages
│   ├── audit/          # Audit logging
│   ├── ca/             # Certificate Authority management
│   ├── config/         # Configuration handling
│   ├── dns/            # DNS server (blocking, caching)
│   ├── proxy/          # HTTPS proxy with cert generation
│   ├── rules/          # Rule fetching and parsing
│   └── security/       # Security constants
└── docs/               # Documentation
```

### Key Technical Details
- **Language**: Go 1.21+
- **CLI Framework**: Cobra
- **DNS Library**: miekg/dns
- **Ports**: 53 (DNS), 80 (HTTP redirect), 443 (HTTPS)
- **CA Key Size**: 4096-bit RSA
- **Certificate Cache**: In-memory for performance

### Security Modes
1. **Standard (File-based)**: CA private key stored in `~/.dnshield/ca.key`
2. **Secure (Keychain-based)**: CA private key in System Keychain (enterprise deployment)

## Working with the Codebase

### Adding New Features
When adding features, follow the existing patterns:
- Commands go in `cmd/` using Cobra
- Core logic goes in appropriate `internal/` package
- Use structured logging with logrus
- Follow Go conventions (no custom linting config exists)

### Configuration
Edit `config.yaml` for runtime settings:
```yaml
dns:
  upstreams: ["1.1.1.1", "8.8.8.8"]
  cacheSize: 10000
  cacheTTL: "1h"

s3:  # Optional S3 rule management
  bucket: "company-dns-rules"
  region: "us-east-1"
```

### Common Development Tasks
```bash
# Check DNS server logs
sudo ./dnshield run  # Logs to stdout

# Force rule update from S3
sudo ./dnshield update-rules

# Check certificate generation
# Certificates are generated on-demand when visiting blocked HTTPS sites

# Debug blocked domains
# Add debug logging in internal/dns/handler.go
```

### Testing Notes
- No automated tests exist currently
- Testing is manual via blocked domain verification
- Test domains configured in `config.yaml` under `testDomains`

## Important Considerations

### macOS Specifics
- Requires sudo for binding to ports 53/443
- Uses macOS Keychain APIs for v2 mode
- Supports Touch ID via System Preferences
- Code signing required for production deployment

### Certificate Generation
- Only generates certificates for blocked domains
- Critical domains are protected (see internal/security/domains.go)
- Certificates cached in memory for performance
- Each installation has unique CA (security by design)

### No Docker Version
This is the single-binary version. The Docker-based version referenced in some docs is in a different directory structure.