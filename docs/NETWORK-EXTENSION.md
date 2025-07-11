# Network Extension Mode Documentation

This document provides comprehensive information about DNShield's Network Extension mode, including building, signing, and deployment.

## Table of Contents

1. [Overview](#overview)
2. [Requirements](#requirements)
3. [Building the Network Extension](#building-the-network-extension)
4. [Code Signing](#code-signing)
5. [Installation and Deployment](#installation-and-deployment)
6. [Troubleshooting](#troubleshooting)
7. [Technical Architecture](#technical-architecture)

## Overview

The Network Extension mode provides kernel-level DNS filtering that cannot be bypassed by applications. Unlike the DNS takeover mode which modifies system DNS settings, the Network Extension intercepts DNS queries at the network layer.

### Benefits

- **Unbypassable**: Applications cannot circumvent the filtering
- **Captive Portal Compatible**: Works with airplane WiFi and hotel networks
- **No DNS Changes**: Doesn't modify system DNS settings
- **Enhanced Security**: Runs at the kernel level with system protections

### Limitations

- Requires macOS 10.15 (Catalina) or later
- Must be code signed with an Apple Developer ID
- Requires user approval for installation
- More complex deployment than DNS mode

## Requirements

### System Requirements

- macOS 10.15 (Catalina) or later
- Admin privileges for installation
- System Integrity Protection (SIP) enabled (recommended)

### Development Requirements

- Xcode Command Line Tools
- Swift compiler (included with Xcode)
- Go 1.21 or later
- Apple Developer ID certificate (for production)

## Building the Network Extension

### 1. Build the Main Binary

```bash
# Build with Network Extension support
make build-with-extension
```

### 2. Build the Extension Bundle

```bash
# Build the Network Extension
cd network-extension
./build.sh
cd ..
```

### 3. Create the App Bundle

```bash
# Create complete app bundle with embedded extension
./build-app-bundle.sh
```

This creates `DNShield.app` with the following structure:
```
DNShield.app/
├── Contents/
│   ├── Info.plist
│   ├── MacOS/
│   │   └── dnshield
│   └── Library/
│       └── SystemExtensions/
│           └── DNShieldExtension.systemextension/
```

## Code Signing

**Important**: Network Extensions MUST be code signed to work on production systems.

### Obtaining a Developer Certificate

1. **Join Apple Developer Program**
   - Visit [developer.apple.com](https://developer.apple.com)
   - Enroll in the Apple Developer Program ($99/year)
   - Download and install your certificates

2. **Create Certificates**
   - Open Xcode
   - Go to Preferences > Accounts
   - Manage Certificates
   - Create a "Developer ID Application" certificate

### Signing the Extension

1. **Find your Developer ID**:
   ```bash
   security find-identity -v -p codesigning
   ```
   Look for "Developer ID Application: Your Name (TEAMID)"

2. **Set the Developer ID**:
   ```bash
   export DEVELOPER_ID="Developer ID Application: Your Name (TEAMID)"
   ```

3. **Build with Signing**:
   ```bash
   # The build scripts will automatically sign if DEVELOPER_ID is set
   ./build-app-bundle.sh
   ```

### Manual Signing

If you need to sign manually:

```bash
# Sign the Network Extension
codesign --force \
         --sign "$DEVELOPER_ID" \
         --timestamp \
         --options runtime \
         --entitlements network-extension/DNShieldExtension.systemextension/Contents/Entitlements.plist \
         DNShield.app/Contents/Library/SystemExtensions/DNShieldExtension.systemextension

# Sign the main app
codesign --force \
         --sign "$DEVELOPER_ID" \
         --timestamp \
         --options runtime \
         --entitlements DNShield.entitlements \
         DNShield.app
```

### Notarization

For distribution outside the App Store:

1. **Create a ZIP for notarization**:
   ```bash
   ditto -c -k --keepParent DNShield.app DNShield.zip
   ```

2. **Submit for notarization**:
   ```bash
   xcrun notarytool submit DNShield.zip \
         --apple-id your-apple-id@example.com \
         --team-id TEAMID \
         --wait
   ```

3. **Staple the notarization**:
   ```bash
   xcrun stapler staple DNShield.app
   ```

## Installation and Deployment

### Development Installation

For unsigned extensions during development:

1. **Disable SIP** (not recommended for production):
   - Restart in Recovery Mode (Command+R)
   - Open Terminal
   - Run: `csrutil disable`
   - Restart

2. **Install the extension**:
   ```bash
   sudo DNShield.app/Contents/MacOS/dnshield extension install
   ```

### Production Installation

For signed extensions:

1. **Install the extension**:
   ```bash
   sudo DNShield.app/Contents/MacOS/dnshield extension install
   ```

2. **Approve in System Settings**:
   - Open System Settings > Privacy & Security
   - Look for the extension approval prompt
   - Click "Allow"

3. **Run in extension mode**:
   ```bash
   sudo DNShield.app/Contents/MacOS/dnshield run --mode=extension
   ```

### MDM Deployment

For enterprise deployment via MDM:

1. **Pre-approve the extension** using a configuration profile:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
            "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
       <key>PayloadContent</key>
       <array>
           <dict>
               <key>PayloadType</key>
               <string>com.apple.system-extension-policy</string>
               <key>PayloadVersion</key>
               <integer>1</integer>
               <key>PayloadIdentifier</key>
               <string>com.company.dnshield.extension-policy</string>
               <key>PayloadUUID</key>
               <string>UNIQUE-UUID-HERE</string>
               <key>AllowedSystemExtensions</key>
               <dict>
                   <key>TEAMID</key>
                   <array>
                       <string>com.dnshield.network-extension</string>
                   </array>
               </dict>
           </dict>
       </array>
   </dict>
   </plist>
   ```

2. **Deploy via MDM** with the pre-approval profile

## Troubleshooting

### Extension Won't Install

1. **Check signing**:
   ```bash
   codesign -dv --verbose=4 DNShield.app
   ```

2. **Check logs**:
   ```bash
   # In Console.app, filter for:
   - "DNShield"
   - "SystemExtensions"
   - "neagent"
   ```

3. **Verify bundle structure**:
   ```bash
   # Extension should be at:
   ls DNShield.app/Contents/Library/SystemExtensions/
   ```

### Extension Installed but Not Working

1. **Check status**:
   ```bash
   systemextensionsctl list
   DNShield.app/Contents/MacOS/dnshield extension status
   ```

2. **Check Network Extension settings**:
   - System Settings > General > Login Items & Extensions > Network Extensions
   - Ensure DNShield is enabled

3. **Restart the service**:
   ```bash
   sudo DNShield.app/Contents/MacOS/dnshield extension uninstall
   sudo DNShield.app/Contents/MacOS/dnshield extension install
   ```

### Development Issues

1. **"Extension requires valid code signature"**:
   - The extension must be signed
   - Use DNS mode for development without signing

2. **"Not running from app bundle"**:
   - Always run from: `DNShield.app/Contents/MacOS/dnshield`
   - Not from: `./dnshield`

## Technical Architecture

### Components

1. **Main Application** (`dnshield`)
   - Manages extension lifecycle
   - Provides CLI interface
   - Handles configuration

2. **System Extension** (`DNShieldExtension.systemextension`)
   - Implements `NEDNSProxyProvider`
   - Filters DNS queries
   - Runs in kernel space

3. **HTTPS Proxy**
   - Still runs in main app
   - Provides block pages for filtered domains

### Data Flow

1. DNS query → System Extension
2. Extension checks against block list
3. Blocked domains → Return 127.0.0.1
4. HTTPS request to 127.0.0.1 → Main app proxy
5. Proxy shows block page

### Configuration

Extension configuration in `config.yaml`:
```yaml
extension:
  bundleId: "com.dnshield.network-extension"
  updateInterval: "5m"
  enabled: true
```

### Security Considerations

- Extension runs with system privileges
- Cannot access user files directly
- Communications with main app are limited
- Block lists are loaded at startup

## Summary

The Network Extension mode provides the highest level of DNS filtering security but requires proper code signing for production use. For development and testing, use DNS takeover mode (`make secure-mode-dns`) which doesn't require signing.

For production deployment:
1. Obtain an Apple Developer ID
2. Build and sign the extension
3. Notarize for distribution
4. Deploy via MDM for enterprise