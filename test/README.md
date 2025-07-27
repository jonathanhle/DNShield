# DNShield Captive Portal Testing

This directory contains comprehensive testing tools for DNShield's captive portal functionality.

## Test Files

### 1. `captive_portal_simulator.go`
A local captive portal simulator that mimics real-world captive portal behavior without requiring access to public WiFi networks.

**Features:**
- Simulates common captive portal detection endpoints
- Provides a realistic login page
- Tracks authenticated clients
- Includes a DNS server for testing DNS interception
- Supports multiple OS detection patterns (Apple, Android, Windows)

**Usage:**
```bash
# Build the simulator
go build -o captive-portal-simulator captive_portal_simulator.go

# Run the simulator
./captive-portal-simulator

# For help
./captive-portal-simulator help
```

### 2. `test_captive_portal.sh`
Automated test runner that executes all captive portal-related tests.

**What it tests:**
- Unit tests for captive portal detection logic
- Real-world scenario simulations
- Time-based behavior (detection windows, bypass expiration)
- Concurrent request handling
- Integration tests with DNS handler
- Performance benchmarks
- Race condition detection

**Usage:**
```bash
# Run all tests
./test_captive_portal.sh

# Run specific test categories
go test -v ./internal/dns -run TestCaptivePortalRealWorldScenarios
go test -v ./internal/dns -run TestCaptivePortalTimeBasedBehavior
go test -bench=BenchmarkCaptivePortal ./internal/dns
```

## Test Scenarios Covered

### 1. Real-World Patterns
- **Apple devices**: Multi-domain checks (captive.apple.com, gsp1.apple.com)
- **Android devices**: Google connectivity checks
- **Windows 10/11**: Microsoft connectivity test with retries
- **Coffee shop WiFi**: Starbucks-style multi-stage portals
- **Airline WiFi**: Gogo inflight with satellite delays
- **Hotel WiFi**: Multi-redirect authentication flows

### 2. Edge Cases
- False positive prevention (manual visits to captive domains)
- Mixed traffic patterns
- Rapid repeated requests
- Empty domain handling
- Case sensitivity
- Detection window expiration
- Bypass mode expiration

### 3. Performance & Concurrency
- Concurrent DNS requests from multiple goroutines
- Benchmark tests for detection performance
- Race condition detection
- Thread safety verification

## Manual Testing Guide

### Using the Simulator

1. **Setup DNShield with simulator DNS:**
   ```yaml
   # config.yaml
   dns:
     upstreams: ["127.0.0.1:8053"]
   ```

2. **Run both DNShield and the simulator:**
   ```bash
   # Terminal 1
   ./captive-portal-simulator
   
   # Terminal 2
   sudo ./dnshield run
   ```

3. **Trigger captive portal detection:**
   ```bash
   # These should trigger bypass mode
   curl -I http://captive.apple.com
   curl -I http://connectivitycheck.gstatic.com
   curl -I http://detectportal.firefox.com
   ```

4. **Access the simulated portal:**
   Open http://captive.test.local:8080 in your browser

### Testing on Real Networks

1. **Coffee Shop/Public WiFi:**
   - Connect to network
   - Run: `sudo ./dnshield run --auto-configure-dns`
   - Portal should be detected automatically
   - Check: `./dnshield bypass status`

2. **Airplane WiFi:**
   - Similar process, but expect longer delays
   - Monitor logs for Gogo/airline-specific domains

3. **Hotel WiFi:**
   - Often requires room number/name
   - May have multiple redirect stages

## Monitoring & Debugging

### Check Logs
```bash
# Watch for captive portal detection
sudo ./dnshield run 2>&1 | grep -i "captive"

# Check bypass status
./dnshield bypass status
```

### Common Issues

1. **Detection not triggering:**
   - Ensure threshold is appropriate (default: 3 domains in 5 seconds)
   - Check if domains are in the allow list
   - Verify detection is enabled in config

2. **False positives:**
   - Increase detection threshold
   - Decrease detection window
   - Check for unusual browsing patterns

3. **Bypass expires too quickly:**
   - Increase bypass duration in config
   - Consider manual bypass for extended sessions

## Configuration Options

```yaml
captivePortal:
  enabled: true
  detectionThreshold: 3        # Domains needed to trigger
  detectionWindow: "5s"        # Time window for detection
  bypassDuration: "5m"         # How long bypass lasts
  additionalDomains:           # Custom domains
    - "custom-portal.company.com"
```

## Contributing New Tests

When adding new captive portal domains or test cases:

1. Add domains to `internal/security/captive_portals.go`
2. Add test cases to verify the domains
3. Update documentation in `docs/CAPTIVE_PORTALS.md`
4. Run the full test suite to ensure no regressions