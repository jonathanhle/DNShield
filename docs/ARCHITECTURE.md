# DNS Guardian Architecture

## System Overview

DNS Guardian is a native macOS DNS filtering solution that combines DNS sinkholing with dynamic HTTPS certificate generation to provide transparent content filtering without browser warnings.

## Core Components

### 1. DNS Server (`internal/dns/`)

The DNS server is the first line of defense, intercepting all DNS queries on port 53.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  DNS Query  │────▶│   Handler   │────▶│   Blocker   │
│   Port 53   │     │             │     │             │
└─────────────┘     └──────┬──────┘     └──────┬──────┘
                           │                    │
                           ▼                    ▼
                    ┌─────────────┐      ┌─────────────┐
                    │    Cache    │      │  Blocked?   │
                    └─────────────┘      └──────┬──────┘
                                               │
                                               ▼
                                        ┌─────────────┐
                                        │  127.0.0.1  │
                                        │      or     │
                                        │  Upstream   │
                                        └─────────────┘
```

**Key Features:**
- Concurrent UDP and TCP support
- LRU cache for performance
- Configurable upstream resolvers
- Hierarchical domain matching

### 2. HTTPS Certificate Proxy (`internal/proxy/`)

When a browser attempts to connect to a blocked HTTPS site, the proxy intercepts the connection and serves a block page with a dynamically generated certificate.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│HTTPS Request│────▶│  TLS Hello  │────▶│   CertGen   │
│   Port 443  │     │   (SNI)     │     │             │
└─────────────┘     └──────┬──────┘     └──────┬──────┘
                           │                    │
                           ▼                    ▼
                    ┌─────────────┐      ┌─────────────┐
                    │  Get Domain │      │  Generate   │
                    └─────────────┘      │    Cert     │
                                        └──────┬──────┘
                                               │
                                               ▼
                                        ┌─────────────┐
                                        │ Block Page  │
                                        └─────────────┘
```

**Key Features:**
- SNI-based domain detection
- On-demand certificate generation
- In-memory certificate caching
- Custom HTML block page

### 3. Certificate Authority (`internal/ca/`)

Manages the local CA that signs certificates for blocked domains.

```
┌─────────────────────────────────────┐
│         CA Management               │
├─────────────────────────────────────┤
│  • Generate 4096-bit RSA CA         │
│  • Store in ~/.dns-guardian/        │
│  • Install in System Keychain       │
│  • Sign domain certificates         │
└─────────────────────────────────────┘
```

**Security Model:**
- Per-machine CA (no shared secrets)
- File-based storage (v1.0)
- System Keychain storage (v2.0 - Available Now)
- 2-year validity period

### 4. Rule Management (`internal/rules/`)

Fetches and parses blocklists from S3 for enterprise-wide policy management.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  S3 Bucket  │────▶│   Fetcher   │────▶│   Parser    │
│             │     │             │     │             │
└─────────────┘     └──────┬──────┘     └──────┬──────┘
                           │                    │
                           ▼                    ▼
                    ┌─────────────┐      ┌─────────────┐
                    │  Download   │      │Parse Formats│
                    │   Rules     │      │ • Hosts     │
                    └─────────────┘      │ • Domains   │
                                        │ • Regex     │
                                        └─────────────┘
```

**Supported Formats:**
- Hosts files (0.0.0.0 domain.com)
- Domain lists (one per line)
- YAML rule definitions
- External blocklist URLs

## Data Flow

### DNS Query Flow

1. **Query Received**: DNS query arrives on port 53
2. **Cache Check**: Look for cached response
3. **Block Check**: Verify if domain is blocked
4. **Response**:
   - Blocked: Return 127.0.0.1
   - Allowed: Forward to upstream resolver
5. **Cache Store**: Cache the response

### HTTPS Interception Flow

1. **Connection**: Browser connects to 127.0.0.1:443
2. **SNI Reading**: Extract domain from TLS ClientHello
3. **Certificate Cache**: Check for existing certificate
4. **Certificate Generation**: Create new cert if needed
5. **TLS Handshake**: Complete with generated certificate
6. **Block Page**: Serve custom HTML page

## Performance Characteristics

### DNS Server
- **Latency**: <1ms for cached queries
- **Throughput**: 10,000+ queries/second
- **Cache Size**: Configurable (default 10,000 entries)
- **Memory**: ~50MB with full cache

### Certificate Generation
- **First Generation**: 5-10ms
- **Cached Certificate**: <1ms
- **Memory**: ~100KB per cached certificate
- **Cache Size**: Unlimited (process lifetime)

## Security Boundaries

### Trust Model
```
┌─────────────────────────────────────┐
│         System Trust                │
├─────────────────────────────────────┤
│  macOS Keychain                     │
│      ↓                             │
│  DNS Guardian CA                    │
│      ↓                             │
│  Generated Certificates             │
│      ↓                             │
│  Browser Trust                      │
└─────────────────────────────────────┘
```

### Isolation
- Each machine has unique CA
- No network communication for CA operations
- DNS and HTTPS run as separate services
- Configuration isolated from binary

## Deployment Architecture

### Standalone Mode (Current)
```
┌─────────────────────────────────────┐
│         macOS System                │
├─────────────────────────────────────┤
│  DNS Guardian (root)                │
│   • Port 53 (DNS)                   │
│   • Port 443 (HTTPS)                │
│   • Port 80 (HTTP redirect)         │
│                                     │
│  System DNS → 127.0.0.1             │
└─────────────────────────────────────┘
```

### Enterprise Mode (MDM)
```
┌─────────────────────────────────────┐
│         MDM Server                  │
├─────────────────────────────────────┤
│  • Deploy Package                   │
│  • Configure DNS                    │
│  • Install CA                       │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│       Fleet of macOS Devices        │
├─────────────────────────────────────┤
│  Device 1    Device 2    Device N   │
│     ↓           ↓           ↓       │
│  S3 Rules   S3 Rules   S3 Rules    │
└─────────────────────────────────────┘
```

## Future Enhancements

### Version 2.0 (Available Now)
- ✅ System Keychain-based CA storage
- ✅ Process-specific ACLs
- ✅ Enhanced audit logging
- ✅ Short-lived certificates (5 minutes)
- Certificate transparency (planned)
- DNSSEC validation (planned)

### Version 3.0
- Hardware security module
- Remote attestation
- Split-tunnel VPN support
- Multi-platform support