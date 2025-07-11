#!/bin/bash

# Build script for DNShield app bundle with Network Extension

set -e

APP_NAME="DNShield"
BUNDLE_DIR="${APP_NAME}.app"
BINARY_NAME="dnshield"

echo "Building DNShield app bundle with Network Extension..."

# Clean existing bundle
if [ -d "$BUNDLE_DIR" ]; then
    echo "Cleaning existing app bundle..."
    rm -rf "$BUNDLE_DIR"
fi

# Create bundle structure
echo "Creating app bundle structure..."
mkdir -p "${BUNDLE_DIR}/Contents/MacOS"
mkdir -p "${BUNDLE_DIR}/Contents/Resources"
mkdir -p "${BUNDLE_DIR}/Contents/Library/SystemExtensions"

# Copy Info.plist (create it first if needed)
if [ ! -f "${BUNDLE_DIR}/Contents/Info.plist" ]; then
    cat > "${BUNDLE_DIR}/Contents/Info.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>dnshield</string>
    <key>CFBundleIdentifier</key>
    <string>com.dnshield.app</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>DNShield</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>LSUIElement</key>
    <true/>
    <key>NSSystemExtensionUsageDescription</key>
    <string>DNShield needs to install a system extension to filter DNS queries at the kernel level.</string>
</dict>
</plist>
EOF
fi

# Build the main binary with extension support
echo "Building main binary with extension support..."
if [ ! -f "$BINARY_NAME" ]; then
    make build-with-extension
fi

# Copy the binary to the app bundle
echo "Copying binary to app bundle..."
cp "$BINARY_NAME" "${BUNDLE_DIR}/Contents/MacOS/"

# Build the Network Extension if not already built
if [ ! -d "network-extension/DNShieldExtension.systemextension" ]; then
    echo "Building Network Extension..."
    cd network-extension
    ./build.sh
    cd ..
fi

# Copy the Network Extension to the app bundle
echo "Copying Network Extension to app bundle..."
cp -R "network-extension/DNShieldExtension.systemextension" "${BUNDLE_DIR}/Contents/Library/SystemExtensions/"

# Create a simple icon (optional)
touch "${BUNDLE_DIR}/Contents/Resources/DNShield.icns"

# Sign the app bundle if DEVELOPER_ID is set
if [ -n "$DEVELOPER_ID" ]; then
    echo "Signing app bundle..."
    # First sign the embedded extension
    codesign --force \
             --sign "$DEVELOPER_ID" \
             --timestamp \
             --options runtime \
             "${BUNDLE_DIR}/Contents/Library/SystemExtensions/DNShieldExtension.systemextension"
    
    # Then sign the main app
    codesign --force \
             --sign "$DEVELOPER_ID" \
             --entitlements DNShield.entitlements \
             --timestamp \
             --options runtime \
             "${BUNDLE_DIR}"
    
    echo "✅ App bundle signed successfully"
else
    echo "⚠️  Warning: DEVELOPER_ID not set. App bundle is not signed."
    echo "   Network Extensions require code signing to function properly."
    echo ""
    echo "   See docs/NETWORK-EXTENSION.md for signing instructions."
fi

echo ""
echo "✅ App bundle created: ${BUNDLE_DIR}"
echo ""
echo "To install the Network Extension:"
echo "  sudo ${BUNDLE_DIR}/Contents/MacOS/dnshield extension install"
echo ""
echo "To run DNShield in extension mode:"
echo "  sudo ${BUNDLE_DIR}/Contents/MacOS/dnshield run --mode=extension"