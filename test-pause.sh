#!/bin/bash

# Test script for DNShield pause functionality

echo "DNShield Pause Functionality Test"
echo "================================"
echo ""

# Check if API is running
echo "1. Checking if DNShield API is running..."
if curl -s http://127.0.0.1:5353/api/health | grep -q "healthy"; then
    echo "   ✅ API is running"
else
    echo "   ❌ API is not running. Please start DNShield first:"
    echo "      sudo ./dnshield run --config test-pause.yaml"
    exit 1
fi

# Get current status
echo ""
echo "2. Current status:"
curl -s http://127.0.0.1:5353/api/status | jq '{running, protected, dns_configured}'

# Test DNS resolution before pause
echo ""
echo "3. Testing DNS resolution (should be blocked):"
echo "   Testing doubleclick.net..."
nslookup doubleclick.net 127.0.0.1 2>&1 | grep -A2 "Address"

# Pause for 30 seconds
echo ""
echo "4. Pausing protection for 30 seconds..."
curl -X POST http://127.0.0.1:5353/api/pause \
    -H "Content-Type: application/json" \
    -d '{"duration": "30s"}' \
    -s | jq

# Check status again
echo ""
echo "5. Status after pause:"
curl -s http://127.0.0.1:5353/api/status | jq '{running, protected, dns_configured}'

# Test DNS resolution during pause
echo ""
echo "6. Testing DNS resolution during pause (should NOT be blocked):"
echo "   Testing doubleclick.net..."
nslookup doubleclick.net 2>&1 | grep -A2 "Address"

# Wait for auto-resume
echo ""
echo "7. Waiting 35 seconds for auto-resume..."
sleep 35

# Check final status
echo ""
echo "8. Status after auto-resume:"
curl -s http://127.0.0.1:5353/api/status | jq '{running, protected, dns_configured}'

# Test DNS resolution after resume
echo ""
echo "9. Testing DNS resolution after resume (should be blocked again):"
echo "   Testing doubleclick.net..."
nslookup doubleclick.net 127.0.0.1 2>&1 | grep -A2 "Address"

echo ""
echo "✅ Test complete!"