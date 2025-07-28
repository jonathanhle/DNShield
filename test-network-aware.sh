#!/bin/bash

# Test script for network-aware DNS management

echo "DNShield Network-Aware DNS Test"
echo "==============================="
echo ""

# Check if API is running
echo "1. Checking DNShield status..."
STATUS=$(curl -s http://127.0.0.1:5353/api/status)

if [ -z "$STATUS" ]; then
    echo "   ❌ DNShield is not running"
    echo "   Please start: sudo ./dnshield run --config test-pause.yaml"
    exit 1
fi

echo "   ✅ DNShield is running"
echo ""

# Display current network info
echo "2. Current Network Information:"
echo "$STATUS" | jq '{
    running,
    protected,
    current_network,
    network_interface,
    original_dns,
    current_dns
}'

# Show saved network configurations
echo ""
echo "3. Saved Network Configurations:"
NETWORK_DIR="$HOME/.dnshield/network-dns"
if [ -d "$NETWORK_DIR" ]; then
    COUNT=$(ls -1 "$NETWORK_DIR"/network-*.json 2>/dev/null | wc -l)
    echo "   Found $COUNT saved network(s)"
    
    for config in "$NETWORK_DIR"/network-*.json; do
        if [ -f "$config" ]; then
            echo ""
            echo "   Network: $(basename "$config")"
            jq '{
                network: .network_identity.ssid // .network_identity.interface,
                dns_servers,
                is_dhcp,
                times_connected,
                last_updated
            }' "$config" 2>/dev/null || echo "   Error reading config"
        fi
    done
else
    echo "   No network configurations found"
fi

# Test pause functionality
echo ""
echo "4. Testing Pause/Resume with Network Info:"

# Get current network
CURRENT_NET=$(echo "$STATUS" | jq -r '.current_network // "Unknown"')
echo "   Current network: $CURRENT_NET"

# Pause for 10 seconds
echo "   Pausing protection for 10 seconds..."
curl -X POST http://127.0.0.1:5353/api/pause \
    -H "Content-Type: application/json" \
    -d '{"duration": "10s"}' \
    -s | jq

# Check status during pause
sleep 2
echo ""
echo "   Status during pause:"
curl -s http://127.0.0.1:5353/api/status | jq '{
    protected,
    current_network,
    original_dns
}'

# Wait for auto-resume
echo ""
echo "   Waiting for auto-resume..."
sleep 10

# Check status after resume
echo ""
echo "   Status after auto-resume:"
curl -s http://127.0.0.1:5353/api/status | jq '{
    protected,
    current_network
}'

# Network change simulation info
echo ""
echo "5. Network Change Simulation:"
echo "   To test network changes:"
echo "   - Switch WiFi networks"
echo "   - Connect/disconnect ethernet"
echo "   - Enable/disable VPN"
echo "   - DNShield will automatically:"
echo "     • Detect the change"
echo "     • Capture DNS for new networks"
echo "     • Maintain protection"
echo ""
echo "   Monitor logs with: tail -f /var/log/dnshield.log"

echo ""
echo "✅ Network-aware DNS test complete!"