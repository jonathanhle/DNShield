# Security Hardening

DNShield implements multiple security hardening measures to protect against attacks and minimize the impact of potential vulnerabilities.

## Overview

While DNShield cannot use the macOS App Sandbox due to its requirement to bind to privileged ports (53, 80, 443) and execute system commands, it implements comprehensive security hardening through other mechanisms.

## Hardening Measures

### 1. Hardened Runtime Entitlements

The application uses macOS Hardened Runtime with the following security features:

- **Hardened Runtime**: Prevents code injection and library hijacking
- **Restricted DYLD**: Prevents dynamic library environment variable attacks
- **No Unsigned Memory**: Blocks execution of unsigned code in memory
- **Library Validation**: Only allows loading of properly signed libraries

### 2. Process Security Hardening

When DNShield starts, it automatically applies the following security measures:

#### Resource Limits
- **Memory Limit**: 512MB default (prevents memory exhaustion attacks)
- **File Descriptor Limit**: 1024 (prevents fd exhaustion)
- **Core Dumps Disabled**: Prevents memory disclosure through crash dumps

#### Environment Sanitization
- Clears sensitive environment variables:
  - `AWS_ACCESS_KEY_ID`
  - `AWS_SECRET_ACCESS_KEY`
  - `AWS_SESSION_TOKEN`
  - `DNSHIELD_API_KEY`
  - `SPLUNK_HEC_TOKEN`

#### File Security
- **Secure Umask**: Sets umask to 0077 (owner-only access for new files)
- **Secure File Permissions**: All configuration and key files are created with restrictive permissions

### 3. Privilege Separation (Planned)

After binding to privileged ports, DNShield attempts to drop privileges to an unprivileged user:

1. Checks for suitable unprivileged users: `_dnshield`, `nobody`, `daemon`
2. Drops from root to unprivileged user after port binding
3. Continues operation with reduced privileges

**Note**: Full privilege dropping is complex on macOS and requires:
- Creating a dedicated `_dnshield` user
- Changing ownership of configuration files
- Handling keychain access permissions

### 4. API Security

- **Role-Based Access Control (RBAC)**: Three-tier permission system
- **Bearer Token Authentication**: All API endpoints require authentication
- **Rate Limiting**: Prevents API abuse
- **Audit Logging**: All configuration changes are logged

### 5. Network Security

- **Certificate Verification**: Only generates certificates for blocked domains
- **Input Validation**: All user inputs are validated and sanitized
- **Command Injection Prevention**: Shell command arguments are validated
- **Path Traversal Prevention**: File paths are sanitized and validated

## Implementation Details

### Entitlements File (`dnshield.entitlements`)

```xml
<!-- Hardened Runtime -->
<key>com.apple.security.runtime.hardened</key>
<true/>

<!-- Disable unsigned executable memory -->
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<false/>

<!-- Restrict dyld environment variables -->
<key>com.apple.security.cs.restrict-dyld</key>
<true/>
```

### Hardening Code (`internal/security/hardening.go`)

The hardening module is automatically applied at startup:

```go
hardening := security.NewHardening()
if err := hardening.ApplyHardening(); err != nil {
    logrus.WithError(err).Warn("Failed to apply security hardening")
}
```

## Building with Security

When building DNShield, the Makefile automatically applies security entitlements:

```bash
make build          # Standard build with entitlements
make build-universal # Universal binary with entitlements
make build-signed   # Signed build with Developer ID
```

## Security Best Practices

1. **Run with Least Privilege**: Use `sudo` only when necessary
2. **Regular Updates**: Keep DNShield updated for security patches
3. **Monitor Logs**: Check audit logs for suspicious activity
4. **Secure Configuration**: Use environment variables for sensitive data
5. **API Key Management**: Rotate API keys regularly

## Future Enhancements

1. **Full Privilege Separation**: Complete implementation of privilege dropping
2. **Seccomp-style Filtering**: System call filtering (when available on macOS)
3. **Network Namespace Isolation**: Process isolation for network operations
4. **Mandatory Access Control**: Integration with macOS TCC framework

## Limitations

Due to DNShield's architecture and requirements, some security features cannot be implemented:

- **App Sandbox**: Incompatible with privileged port binding
- **System Extension**: Would require significant architecture changes
- **Full Process Isolation**: Limited by need to modify system settings

## Security Reporting

If you discover a security vulnerability in DNShield, please report it to the maintainers through the appropriate channels. Do not disclose security issues publicly until they have been addressed.