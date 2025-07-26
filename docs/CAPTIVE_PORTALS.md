# Captive Portal Support

DNShield includes automatic captive portal detection and bypass functionality to ensure you can connect to public WiFi networks that require authentication (airports, hotels, coffee shops, etc.).

## How It Works

### Automatic Detection
DNShield automatically detects when your device is trying to connect through a captive portal by monitoring requests to known captive portal detection domains used by various operating systems:

- **Apple**: captive.apple.com, mask.icloud.com
- **Windows**: www.msftconnecttest.com, msftncsi.com  
- **Android**: connectivitycheck.gstatic.com
- **Firefox**: detectportal.firefox.com
- And many others

When DNShield detects multiple requests to these domains within a short time window (indicating a captive portal login attempt), it automatically enters **bypass mode**.

### Bypass Mode
In bypass mode:
- DNS filtering is temporarily disabled for 5 minutes
- All domains are resolved normally without blocking
- You can authenticate with the captive portal
- After 5 minutes, normal filtering resumes automatically

### Always-Allowed Domains
Captive portal detection domains are **never blocked**, even if they appear in your blocklists. This ensures your device can always detect captive portals.

## Manual Controls

While captive portal support works automatically, you can also manually control bypass mode:

```bash
# Enable bypass mode for 5 minutes (default)
sudo ./dnshield bypass enable

# Enable bypass for a custom duration
sudo ./dnshield bypass enable --duration 10m

# Disable bypass mode immediately
sudo ./dnshield bypass disable

# Check bypass mode status
sudo ./dnshield bypass status
```

## Troubleshooting

### Captive Portal Not Showing
If a captive portal isn't appearing:

1. **Wait a moment** - Detection requires multiple requests (usually 3) to captive portal domains
2. **Try refreshing** - Open a new browser tab and navigate to any website
3. **Manual bypass** - Use `sudo ./dnshield bypass enable` to temporarily disable filtering
4. **Check logs** - Look for "Captive portal detected" messages in the DNShield logs

### Bypass Mode Expires Too Soon
The default 5-minute bypass window should be sufficient for most captive portals. If you need more time:

```bash
# Enable bypass for 15 minutes
sudo ./dnshield bypass enable --duration 15m
```

## Technical Details

### Detection Algorithm
- Monitors DNS requests for known captive portal domains
- Triggers bypass when 3+ different captive portal domains are queried within 10 seconds
- Automatically clears counters after bypass is enabled

### Security Considerations
- Bypass mode only affects DNS filtering - your HTTPS connections remain secure
- The CA certificate and HTTPS proxy continue to function normally
- Only DNS blocking is temporarily disabled

### Comparison with Other Solutions

| Solution | Method | User Action Required |
|----------|--------|---------------------|
| **DNShield** | Automatic detection + manual override | None (automatic) |
| **NextDNS** | App toggle or excluded domains | Manual toggle |
| **Pi-hole** | Manual disable | Full manual |
| **AdGuard** | Manual disable or allowlist | Manual configuration |

DNShield's automatic detection provides the best user experience while maintaining security.