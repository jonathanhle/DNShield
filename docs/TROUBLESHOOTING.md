# Troubleshooting Guide

This guide covers common issues and their solutions when running DNShield.

## Quick Diagnostics

Run the status command to check system health:
```bash
./dnshield status
```

## Common Issues

### 1. Certificate Warnings Still Appear

**Symptoms:**
- Browser shows "Your connection is not private"
- NET::ERR_CERT_AUTHORITY_INVALID errors

**Solutions:**

1. **Verify CA is installed:**
   ```bash
   # Check if CA is in keychain
   security find-certificate -c "DNShield Root CA" /Library/Keychains/System.keychain
   
   # If not found, reinstall
   ./dnshield install-ca
   
   # For v2 mode (System Keychain)
   sudo DNSHIELD_SECURITY_MODE=v2 DNSHIELD_USE_KEYCHAIN=true ./dnshield install-ca
   ```

2. **Clear browser cache:**
   - Chrome: Settings → Privacy → Clear browsing data → Cached images and files
   - Safari: Develop → Empty Caches
   - Firefox: Settings → Privacy → Clear Data

3. **Check certificate generation:**
   ```bash
   # Enable debug logging
   sudo ./dnshield run --config config.yaml
   
   # Look for certificate generation logs
   # For v1 mode
   tail -f /var/log/dnshield.log | grep "Generated certificate"
   
   # For v2 mode (audit logs)
   tail -f ~/.dnshield/audit/*.log | grep "CERT_GENERATED"
   ```

4. **Trust the CA manually:**
   - Open Keychain Access
   - Find "DNShield Root CA" certificate
   - Double-click and set to "Always Trust"

### 2. DNS Not Resolving

**Symptoms:**
- Cannot access any websites
- "Server not found" errors

**Solutions:**

1. **Verify DNShield is running:**
   ```bash
   # Check if process is running
   ps aux | grep dnshield
   
   # Check if port 53 is listening
   sudo lsof -i :53
   ```

2. **Test DNS resolution:**
   ```bash
   # Test using DNShield
   dig @127.0.0.1 google.com
   
   # Test upstream DNS
   dig @1.1.1.1 google.com
   ```

3. **Check DNS configuration:**
   ```bash
   # View current DNS servers
   networksetup -getdnsservers Wi-Fi
   
   # Should show: 127.0.0.1
   
   # If not, configure DNS automatically
   sudo ./dnshield configure-dns
   
   # Or run with auto-configuration
   sudo ./dnshield run --auto-configure-dns
   ```

4. **Review logs for errors:**
   ```bash
   sudo ./dnshield run --config config.yaml
   # Look for connection errors or timeouts
   ```

### 3. Cannot Bind to Port 53

**Symptoms:**
- Error: "bind: permission denied"
- Error: "bind: address already in use"

**Solutions:**

1. **Run with sudo:**
   ```bash
   sudo ./dnshield run
   ```

2. **Check for conflicting services:**
   ```bash
   # Find what's using port 53
   sudo lsof -i :53
   
   # Common conflicts:
   # - mDNSResponder (normal, ignore)
   # - dnsmasq (stop it)
   # - systemd-resolved (stop it)
   ```

3. **Stop conflicting services:**
   ```bash
   # Stop dnsmasq
   brew services stop dnsmasq
   
   # Stop local DNS servers
   sudo killall -9 named
   ```

### 4. S3 Rules Not Updating

**Symptoms:**
- Old rules still active
- "Failed to fetch rules" errors

**Solutions:**

1. **Check AWS credentials:**
   ```bash
   # Test AWS access
   aws s3 ls s3://your-bucket/
   
   # Set credentials
   export AWS_ACCESS_KEY_ID="your-key"
   export AWS_SECRET_ACCESS_KEY="your-secret"
   ```

2. **Verify S3 bucket configuration:**
   ```yaml
   # config.yaml
   s3:
     bucket: "correct-bucket-name"
     region: "correct-region"
     rulesPath: "path/to/rules.yaml"
   ```

3. **Force rule update:**
   ```bash
   ./dnshield update-rules
   ```

4. **Check S3 permissions:**
   - Ensure IAM user/role has s3:GetObject permission
   - Check bucket policy allows access

### 5. Block Page Not Showing

**Symptoms:**
- Connection refused instead of block page
- Timeout when accessing blocked sites

**Solutions:**

1. **Verify domain is blocked:**
   ```bash
   # Check DNS resolution
   dig @127.0.0.1 blocked-domain.com
   # Should return 127.0.0.1
   ```

2. **Check HTTPS proxy:**
   ```bash
   # Verify port 443 is listening
   sudo lsof -i :443
   
   # Test direct connection
   curl -k https://127.0.0.1
   ```

3. **Review certificate generation:**
   - Enable debug logging
   - Look for certificate errors
   - Check certificate cache is working

### 6. DNS Configuration Keeps Reverting

**Symptoms:**
- DNS settings change back to previous values
- Network reconnects reset DNS
- VPN connections override DNS

**Solutions:**

1. **Use auto-configuration mode:**
   ```bash
   # Run with automatic DNS monitoring
   sudo ./dnshield run --auto-configure-dns
   
   # This checks DNS every minute and auto-corrects changes
   ```

2. **Check for conflicting software:**
   ```bash
   # Look for VPN clients, network managers
   ps aux | grep -i "vpn\|dns"
   ```

3. **Check MDM profiles:**
   ```bash
   # List configuration profiles
   profiles show
   
   # Look for DNS-related settings
   ```

4. **Verify all interfaces are configured:**
   ```bash
   # Check all interfaces
   networksetup -listallnetworkservices
   
   # Configure each manually if needed
   sudo networksetup -setdnsservers "Wi-Fi" 127.0.0.1
   sudo networksetup -setdnsservers "Ethernet" 127.0.0.1
   ```

5. **Monitor DNS changes:**
   ```bash
   # Watch for DNS changes in real-time
   while true; do
     echo "$(date): $(networksetup -getdnsservers Wi-Fi)"
     sleep 10
   done
   ```

### 7. High CPU/Memory Usage

**Symptoms:**
- dns-guardian using excessive resources
- System slowdown

**Solutions:**

1. **Check cache size:**
   ```yaml
   # Reduce cache size in config.yaml
   dns:
     cacheSize: 5000  # Lower from 10000
   ```

2. **Review blocklist size:**
   ```bash
   # Check number of blocked domains
   ./dnshield status
   ```

3. **Enable rate limiting (future feature)**

4. **Check for DNS loops:**
   - Ensure DNShield isn't querying itself
   - Verify upstream DNS servers are correct

### 8. Pause/Resume Not Working

**Symptoms:**
- Pause doesn't restore original DNS
- Resume doesn't re-enable filtering
- Network-specific DNS not remembered

**Solutions:**

1. **Check pause is enabled:**
   ```yaml
   # config.yaml
   agent:
     allowPause: true
   ```

2. **Verify network DNS storage:**
   ```bash
   # Check stored network configurations
   ls -la ~/.dnshield/network-dns/
   
   # View current network config
   cat ~/.dnshield/network-dns/network-*.json
   ```

3. **Test pause/resume:**
   ```bash
   # Check current status
   curl http://localhost:5353/api/status
   
   # Pause for 5 minutes
   curl -X POST http://localhost:5353/api/pause -d '{"duration":"5m"}'
   
   # Verify DNS restored
   networksetup -getdnsservers Wi-Fi
   ```

### 9. Network Changes Not Detected

**Symptoms:**
- Wrong DNS restored when pausing
- DNS settings from previous network used
- Network transitions not handled

**Solutions:**

1. **Check network monitoring:**
   ```bash
   # Enable debug logging
   sudo ./dnshield run --log-level debug
   
   # Look for network change logs
   grep "Network change detected" /var/log/dnshield.log
   ```

2. **Manually trigger network detection:**
   ```bash
   # Switch WiFi networks or toggle WiFi off/on
   # DNShield should detect within 5-10 seconds
   ```

3. **Verify network storage:**
   ```bash
   # List all stored networks
   for f in ~/.dnshield/network-dns/*.json; do
     echo "=== $f ==="
     cat "$f" | jq .
   done
   ```

## Debug Mode

Enable verbose logging for troubleshooting:

```yaml
# config.yaml
agent:
  logLevel: "debug"
```

Or via command line:
```bash
sudo ./dnshield run --log-level debug
```

## Log Analysis

### Important log patterns:

```bash
# Certificate generation issues
grep "Failed to generate certificate" /var/log/dnshield.log

# DNS resolution failures  
grep "Failed to query upstream" /var/log/dnshield.log

# S3 sync problems
grep "Failed to fetch rules" /var/log/dnshield.log

# Memory/performance issues
grep "Cache full" /var/log/dnshield.log
```

## v2.0 Mode Specific Issues

### System Keychain Access Denied

**Symptoms:**
- Error: "Write permissions error" when installing CA
- Cannot access System keychain

**Solutions:**

1. **Ensure running with sudo:**
   ```bash
   sudo DNSHIELD_SECURITY_MODE=v2 DNSHIELD_USE_KEYCHAIN=true ./dnshield install-ca
   ```

2. **Check System keychain permissions:**
   ```bash
   ls -la /Library/Keychains/System.keychain
   ```

3. **Verify v2 mode is enabled:**
   ```bash
   echo $DNSHIELD_SECURITY_MODE  # Should show "v2"
   echo $DNSHIELD_USE_KEYCHAIN   # Should show "true"
   ```

### Certificate Generation Fails in v2 Mode

**Symptoms:**
- "Failed to load key from System keychain" errors
- Certificate generation timeout

**Solutions:**

1. **Verify key exists in System keychain:**
   ```bash
   sudo security find-generic-password -s "com.dnshield.ca" /Library/Keychains/System.keychain
   ```

2. **Check audit logs:**
   ```bash
   tail -f ~/.dnshield/audit/audit-*.log
   ```

3. **Reinstall CA in v2 mode:**
   ```bash
   # Clean up first
   sudo security delete-generic-password -s "com.dnshield.ca" /Library/Keychains/System.keychain 2>/dev/null
   sudo security delete-certificate -c "DNShield Root CA" /Library/Keychains/System.keychain 2>/dev/null
   
   # Reinstall
   sudo DNSHIELD_SECURITY_MODE=v2 DNSHIELD_USE_KEYCHAIN=true ./dnshield install-ca
   ```

## Getting Help

If problems persist:

1. **Collect diagnostic information:**
   ```bash
   ./dnshield status > diagnostic.txt
   ./dnshield version >> diagnostic.txt
   sw_vers >> diagnostic.txt  # macOS version
   ```

2. **Enable debug logging and capture:**
   ```bash
   sudo ./dnshield run --log-level debug 2>&1 | tee debug.log
   ```

3. **Check known issues:**
   - Review GitHub issues
   - Check release notes

4. **Contact support with:**
   - Diagnostic output
   - Debug logs
   - Configuration (sanitized)
   - Steps to reproduce

## Performance Tuning

### DNS Performance

```yaml
# Optimize for speed
dns:
  upstreams:
    - "1.1.1.1"  # Fastest first
    - "8.8.8.8"  # Fallback
  timeout: "2s"  # Quick failover
  cacheSize: 50000  # Large cache
```

### Memory Usage

```yaml
# Optimize for low memory
dns:
  cacheSize: 1000
  cacheTTL: "30m"
  
# Disable debug logging
agent:
  logLevel: "warn"
```

### Network Issues

For unreliable networks:
```yaml
dns:
  timeout: "10s"  # Longer timeout
  upstreams:
    - "8.8.8.8"     # Multiple upstreams
    - "8.8.4.4"
    - "1.1.1.1"
    - "1.0.0.1"
```