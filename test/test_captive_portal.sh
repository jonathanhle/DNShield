#!/bin/bash

# Test script for DNShield captive portal functionality

set -e

echo "DNShield Captive Portal Test Suite"
echo "=================================="
echo

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to run tests with colored output
run_test() {
    local test_name=$1
    local test_cmd=$2
    
    echo -e "${YELLOW}Running: ${test_name}${NC}"
    if eval "$test_cmd"; then
        echo -e "${GREEN}✓ ${test_name} passed${NC}\n"
    else
        echo -e "${RED}✗ ${test_name} failed${NC}\n"
        exit 1
    fi
}

# Check if we're in the right directory
if [ ! -f "go.mod" ]; then
    echo "Error: Please run this script from the project root directory"
    exit 1
fi

echo "1. Running Unit Tests"
echo "--------------------"

# Run basic captive portal tests
run_test "Basic captive portal tests" \
    "go test -v ./internal/dns -run TestCaptivePortal"

# Run enhanced captive portal tests
run_test "Enhanced captive portal tests" \
    "go test -v ./internal/dns -run TestCaptivePortalRealWorldScenarios"

# Run time-based tests
run_test "Time-based behavior tests" \
    "go test -v ./internal/dns -run TestCaptivePortalTimeBasedBehavior"

# Run concurrency tests
run_test "Concurrency tests" \
    "go test -v ./internal/dns -run TestCaptivePortalConcurrency"

# Run integration tests
run_test "Integration tests" \
    "go test -v ./internal/dns -run TestHandlerCaptivePortalIntegration"

# Run security domain tests
run_test "Security domain tests" \
    "go test -v ./internal/security -run TestIsCaptivePortalDomain"

echo "2. Running Benchmarks"
echo "--------------------"

# Run performance benchmarks
echo -e "${YELLOW}Running performance benchmarks...${NC}"
go test -bench=BenchmarkCaptivePortal -benchmem ./internal/dns | grep -E "Benchmark|ns/op|allocs/op"
echo

echo "3. Test Coverage"
echo "---------------"

# Generate coverage report
echo -e "${YELLOW}Generating coverage report...${NC}"
go test -coverprofile=coverage.out ./internal/dns ./internal/security
coverage=$(go tool cover -func=coverage.out | grep total | awk '{print $3}')
echo -e "Total coverage: ${GREEN}${coverage}${NC}"
rm coverage.out
echo

echo "4. Race Condition Detection"
echo "--------------------------"

# Run with race detector
run_test "Race condition detection" \
    "go test -race ./internal/dns -run TestCaptivePortalConcurrency"

echo "5. Manual Testing Instructions"
echo "-----------------------------"

cat << EOF
To manually test captive portal functionality:

A. Using the Captive Portal Simulator:
   1. Build the simulator:
      go build -o captive-portal-simulator test/captive_portal_simulator.go
   
   2. Run the simulator:
      ./captive-portal-simulator
   
   3. In another terminal, configure DNShield to use the simulator's DNS:
      - Edit config.yaml and set upstream DNS to: 127.0.0.1:8053
   
   4. Run DNShield:
      sudo ./dnshield run
   
   5. Test captive portal detection:
      curl -I http://captive.apple.com
      curl -I http://connectivitycheck.gstatic.com
      curl -I http://detectportal.firefox.com
   
   6. Check DNShield logs for bypass activation

B. Testing with real networks:
   1. Connect to a public WiFi that has a captive portal
   2. Run DNShield with auto DNS configuration:
      sudo ./dnshield run --auto-configure-dns
   3. Try to browse - captive portal should be detected
   4. Check bypass status:
      ./dnshield bypass status

C. Testing specific scenarios:
   1. Test manual bypass:
      ./dnshield bypass enable
      ./dnshield bypass status
      ./dnshield bypass disable
   
   2. Test with additional domains in config.yaml:
      captivePortal:
        additionalDomains:
          - "custom-portal.company.com"
          - "wifi.hotel-chain.com"
   
   3. Test with detection disabled:
      captivePortal:
        enabled: false

EOF

echo -e "\n${GREEN}All automated tests passed!${NC}"
echo "See manual testing instructions above for comprehensive testing."