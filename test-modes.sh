#!/bin/bash

# Test script to verify both DNS and Extension modes work correctly

set -e

echo "DNShield Mode Testing Script"
echo "============================"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root (use sudo)${NC}"
   exit 1
fi

echo "1. Testing standard build (DNS mode only)..."
echo "-------------------------------------------"

# Clean and build standard version
make clean
make build

# Check that extension commands fail gracefully
echo -e "${YELLOW}Testing extension command without support...${NC}"
if ./dnshield extension status 2>&1 | grep -q "Network Extension support"; then
    echo -e "${GREEN}✓ Extension commands properly indicate missing support${NC}"
else
    echo -e "${RED}✗ Extension commands not failing gracefully${NC}"
    exit 1
fi

# Test DNS mode
echo -e "${YELLOW}Testing DNS mode functionality...${NC}"
if ./dnshield status | grep -q "DNShield Status"; then
    echo -e "${GREEN}✓ DNS mode status command works${NC}"
else
    echo -e "${RED}✗ DNS mode status command failed${NC}"
    exit 1
fi

echo ""
echo "2. Testing extension build..."
echo "-----------------------------"

# Build with extension support
make build-with-extension

# Check that extension commands are available
echo -e "${YELLOW}Testing extension command availability...${NC}"
if ./dnshield extension status | grep -q "DNShield Network Extension Status"; then
    echo -e "${GREEN}✓ Extension commands available${NC}"
else
    echo -e "${RED}✗ Extension commands not available${NC}"
    exit 1
fi

# Test that DNS mode still works
echo -e "${YELLOW}Testing DNS mode still works with extension build...${NC}"
if ./dnshield status | grep -q "DNShield Status"; then
    echo -e "${GREEN}✓ DNS mode still functional${NC}"
else
    echo -e "${RED}✗ DNS mode broken in extension build${NC}"
    exit 1
fi

echo ""
echo "3. Testing configuration..."
echo "---------------------------"

# Test config loading
echo -e "${YELLOW}Testing configuration loading...${NC}"
if ./dnshield status 2>&1 | grep -q "error"; then
    echo -e "${RED}✗ Configuration loading failed${NC}"
    exit 1
else
    echo -e "${GREEN}✓ Configuration loads successfully${NC}"
fi

echo ""
echo -e "${GREEN}All tests passed! Both DNS and Extension modes are working.${NC}"
echo ""
echo "Next steps:"
echo "1. For DNS mode: make run"
echo "2. For Extension mode: ./dnshield extension install && ./dnshield run --mode=extension"