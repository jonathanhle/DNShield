# Rule Integrity Verification

DNShield supports SHA256 checksum verification for downloaded blocklist rules to ensure they haven't been tampered with during transit.

## Configuration

Add checksums to your rules configuration:

```yaml
version: "1.0"
updated: 2024-01-15T10:00:00Z

# External blocklist URLs
block_sources:
  - https://example.com/blocklist.txt
  - https://another.com/ads.txt

# SHA256 checksums for each blocklist URL
checksums:
  "https://example.com/blocklist.txt": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
  "https://another.com/ads.txt": "b3a8e0e1f9ab1bfe3a36f231f676f78bb30a519d2b21e6c530c0eee8ebb4a5d0"

# Direct domain blocks
block_domains:
  - malware.example.com
  - phishing.example.net
```

## How It Works

1. When DNShield fetches external blocklists from `block_sources`, it will:
   - Download the content
   - Calculate the SHA256 hash of the downloaded data
   - Compare it with the expected checksum from the `checksums` map
   - Reject the blocklist if the checksum doesn't match

2. If no checksum is provided for a URL, the blocklist will be accepted without verification (backward compatibility).

## Generating Checksums

To generate a SHA256 checksum for your blocklist:

```bash
# On macOS/Linux
sha256sum blocklist.txt

# Or using openssl
openssl dgst -sha256 blocklist.txt

# Or using curl and sha256sum
curl -s https://example.com/blocklist.txt | sha256sum
```

## Security Benefits

1. **Integrity**: Ensures blocklists haven't been modified in transit
2. **Authentication**: When combined with HTTPS, provides strong assurance of source authenticity
3. **Protection against MITM**: Detects man-in-the-middle attacks that modify blocklist content
4. **Compliance**: Meets security requirements for integrity verification

## Best Practices

1. Always use HTTPS URLs for blocklist sources
2. Update checksums whenever blocklist content changes
3. Store checksums in a secure, version-controlled location
4. Implement monitoring for checksum verification failures
5. Consider automating checksum updates as part of your blocklist management process

## Implementation Details

The integrity verification is implemented in `internal/rules/parser.go` with:
- SSRF protection (validates URLs, blocks private IPs)
- Size limits to prevent DoS attacks
- SHA256 checksum verification
- Detailed logging of verification results
