#!/bin/bash

# Test script to verify menu bar app displays network information correctly

echo "DNShield Menu Bar Network Display Test"
echo "====================================="
echo ""

# Check if DNShield is running
echo "1. Checking DNShield status..."
STATUS=$(curl -s http://127.0.0.1:5353/api/status)

if [ -z "$STATUS" ]; then
    echo "   ❌ DNShield is not running"
    echo "   Please start: sudo ./dnshield run --config test-pause.yaml"
    exit 1
fi

echo "   ✅ DNShield is running"
echo ""

# Display network information from API
echo "2. Network Information from API:"
echo "$STATUS" | jq '{
    current_network,
    network_interface,
    original_dns
}'

# Check if menu bar app is running
echo ""
echo "3. Checking Menu Bar App..."
if pgrep -f "DNShieldStatusBar" > /dev/null; then
    echo "   ✅ Menu bar app is running"
else
    echo "   ❌ Menu bar app is not running"
    echo "   To build and run:"
    echo "   cd MenuBarApp/DNShieldStatusBar"
    echo "   ./build.sh"
fi

echo ""
echo "4. Expected Menu Bar Display:"
echo "   - Header should show network name (if WiFi connected)"
echo "   - Status tab should have 'Network Status' section showing:"
echo "     • Network: [WiFi SSID or interface name]"
echo "     • Interface: [en0, en1, etc.]"
echo "     • Original DNS: [DNS servers for this network]"

echo ""
echo "5. Testing Network Changes:"
echo "   - Switch WiFi networks and verify the display updates"
echo "   - Connect/disconnect ethernet and check changes"
echo "   - Enable VPN and see if it's detected"

echo ""
echo "6. Testing Pause/Resume with Network Info:"
echo "   - Click pause in menu bar app"
echo "   - Verify it shows which DNS servers are being restored"
echo "   - Check that correct network-specific DNS is restored"

echo ""
echo "✅ Test setup complete!"
echo "   Click the DNShield icon in your menu bar to verify network display"