#!/bin/bash

# Build script for DNShield Network Extension

set -e

EXTENSION_NAME="DNShieldExtension"
BUNDLE_DIR="${EXTENSION_NAME}.systemextension"
CONTENTS_DIR="${BUNDLE_DIR}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"

echo "Building DNShield Network Extension..."

# Create bundle structure
mkdir -p "${MACOS_DIR}"

# Compile Swift code into executable
echo "Compiling Swift DNS Proxy Provider..."
swiftc -target x86_64-apple-macos10.15 \
       -framework NetworkExtension \
       -framework Foundation \
       -framework os.log \
       -parse-as-library \
       -emit-executable \
       -o "${MACOS_DIR}/${EXTENSION_NAME}" \
       DNSProxyProvider.swift

# Make it universal binary if on Apple Silicon
if [[ $(uname -m) == "arm64" ]]; then
    echo "Creating universal binary..."
    swiftc -target arm64-apple-macos10.15 \
           -framework NetworkExtension \
           -framework Foundation \
           -framework os.log \
           -parse-as-library \
           -emit-executable \
           -o "${MACOS_DIR}/${EXTENSION_NAME}-arm64" \
           DNSProxyProvider.swift
    
    lipo -create \
         -output "${MACOS_DIR}/${EXTENSION_NAME}" \
         "${MACOS_DIR}/${EXTENSION_NAME}" \
         "${MACOS_DIR}/${EXTENSION_NAME}-arm64"
    
    rm "${MACOS_DIR}/${EXTENSION_NAME}-arm64"
fi

# Sign the extension if DEVELOPER_ID is set
if [ -n "$DEVELOPER_ID" ]; then
    echo "Signing Network Extension..."
    codesign --force \
             --sign "$DEVELOPER_ID" \
             --entitlements "${CONTENTS_DIR}/Entitlements.plist" \
             --timestamp \
             --options runtime \
             "${BUNDLE_DIR}"
    
    echo "✅ Extension signed successfully"
else
    echo "⚠️  Warning: DEVELOPER_ID not set. Extension is not signed."
    echo "   For production use, set: export DEVELOPER_ID='Developer ID Application: Your Name (TEAMID)'"
fi

echo "✅ Build complete: ${BUNDLE_DIR}"