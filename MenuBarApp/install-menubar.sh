#!/bin/bash

# Install script for DNShield Menu Bar App

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
APP_NAME="DNShield Status"
LAUNCH_AGENT_PLIST="com.dnshield.statusbar.plist"

echo "Installing DNShield Menu Bar App..."

# Build the app first
echo "Building app..."
"$SCRIPT_DIR/build.sh"

# Check if app was built
if [ ! -d "$SCRIPT_DIR/build/$APP_NAME.app" ]; then
    echo "Error: App not found at $SCRIPT_DIR/build/$APP_NAME.app"
    exit 1
fi

# Copy to Applications
echo "Installing to /Applications..."
sudo cp -R "$SCRIPT_DIR/build/$APP_NAME.app" "/Applications/"

# Install LaunchAgent for auto-start
echo "Setting up auto-start..."
cp "$SCRIPT_DIR/$LAUNCH_AGENT_PLIST" "$HOME/Library/LaunchAgents/"

# Load the LaunchAgent
launchctl load "$HOME/Library/LaunchAgents/$LAUNCH_AGENT_PLIST" 2>/dev/null || true

echo ""
echo "✅ DNShield Menu Bar App installed successfully!"
echo ""
echo "The app will:"
echo "- Start automatically on login"
echo "- Show DNShield status in your menu bar"
echo "- Allow you to view statistics and control protection"
echo ""
echo "To start it now: Open '/Applications/$APP_NAME.app'"
echo ""
echo "To uninstall later:"
echo "  1. Quit the app from the menu bar"
echo "  2. Run: launchctl unload ~/Library/LaunchAgents/$LAUNCH_AGENT_PLIST"
echo "  3. Delete: /Applications/$APP_NAME.app"
echo "  4. Delete: ~/Library/LaunchAgents/$LAUNCH_AGENT_PLIST"