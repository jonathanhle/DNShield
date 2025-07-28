#!/bin/bash

# Build script for DNShield Menu Bar App

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
APP_NAME="DNShield Status"
BUILD_DIR="$SCRIPT_DIR/build"
APP_DIR="$BUILD_DIR/$APP_NAME.app"

echo "Building DNShield Menu Bar App..."

# Clean previous build
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Build the Swift package
cd "$SCRIPT_DIR/DNShieldStatusBar"
swift build -c release --arch arm64 --arch x86_64

# Create app bundle structure
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"

# Copy executable
cp ".build/apple/Products/Release/DNShieldStatusBar" "$APP_DIR/Contents/MacOS/DNShieldStatus"

# Create Info.plist
cat > "$APP_DIR/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>DNShieldStatus</string>
    <key>CFBundleIdentifier</key>
    <string>com.dnshield.statusbar</string>
    <key>CFBundleName</key>
    <string>DNShield Status</string>
    <key>CFBundleDisplayName</key>
    <string>DNShield Status</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSSupportsAutomaticGraphicsSwitching</key>
    <true/>
</dict>
</plist>
EOF

# Sign the app if developer ID is available
if security find-identity -p codesigning | grep -q "Developer ID Application"; then
    echo "Signing app..."
    codesign --force --deep --sign "Developer ID Application" "$APP_DIR"
else
    echo "No Developer ID found, app will not be signed"
fi

echo "Build complete: $APP_DIR"

# Create DMG for distribution
echo "Creating DMG..."
DMG_NAME="DNShieldStatus-1.0.0.dmg"
DMG_PATH="$BUILD_DIR/$DMG_NAME"

# Create a temporary directory for DMG contents
DMG_TEMP="$BUILD_DIR/dmg_temp"
mkdir -p "$DMG_TEMP"
cp -r "$APP_DIR" "$DMG_TEMP/"

# Create Applications symlink
ln -s /Applications "$DMG_TEMP/Applications"

# Create DMG
hdiutil create -volname "DNShield Status" -srcfolder "$DMG_TEMP" -ov -format UDZO "$DMG_PATH"

# Clean up
rm -rf "$DMG_TEMP"

echo "DMG created: $DMG_PATH"
echo ""
echo "Installation:"
echo "1. Open $DMG_NAME"
echo "2. Drag 'DNShield Status' to Applications"
echo "3. Launch from Applications"
echo "4. The app will appear in your menu bar"