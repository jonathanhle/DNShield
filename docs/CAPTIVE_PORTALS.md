# Captive Portal Support

DNShield includes automatic captive portal detection and bypass functionality to ensure you can connect to public WiFi networks that require authentication (airports, hotels, coffee shops, etc.).

## How It Works

### Automatic Detection
DNShield automatically detects when your device is trying to connect through a captive portal by monitoring requests to known captive portal detection domains used by various operating systems:

#### Operating System Detection Domains
- **Apple**: captive.apple.com, mask.icloud.com
- **Windows**: www.msftconnecttest.com, msftncsi.com  
- **Android**: connectivitycheck.gstatic.com, android.clients.google.com
- **Firefox**: detectportal.firefox.com

#### Airline WiFi Providers
- **Gogo**: *.gogoinflight.com, *.gogoinair.com
- **Viasat**: *.viasat.com, inflight.viasat.com
- **WiFi Onboard**: *.inflightinternet.com, *.wifionboard.com
- **Panasonic Avionics**: *.panasonic.aero
- **Others**: *.wifilauncher.com, *.flyfi.com, *.inflight-wifi.com

#### Airline-Specific Domains
- **US Airlines**: *.deltawifi.com, *.unitedwifi.com, *.aainflight.com, *.southwestwifi.com, *.alaskawifi.com
- **International**: *.lufthansa-flynet.com, *.airfrance.com, shop.ba.com
- **Ground Transportation**: amtrakconnect.com (Amtrak)
- **Airport WiFi**: *.boingohotspot.net (Boingo - multiple airlines), *.yyc.com (Calgary Airport)

#### Coffee Shops & Restaurants
- **Starbucks**: sbux-portal.globalreachtech.com, secure.datavalet.io, sbux-portal.appspot.com, aruba.odyssys.net
- **Panera Bread**: wifi.panerabread.com, iportal.panerabread.com
- **Tim Hortons**: timhortonswifi.com
- **McDonald's (McCafé)**: captive.o2wifi.co.uk (UK/Europe)
- **Gloria Jean's**: customer.hotspotsystem.com (Australia)

#### Hotels & Public WiFi
- **Hilton**: secure.guestinternet.com, *.selectnetworx.com
- **Hyatt**: globalsuite.net, *.opennetworkexchange.net
- **Marriott**: marriott.com, cloud5.com
- **Montage**: *.skyadmin.io
- **Generic Hotel WiFi**: hotelwifi.com, registerforhsia.com, danmagi.com, redwoodsystemsgroup.com
- **AT&T WiFi**: *.attwifi.com (common in hotels/airports)
- **Aruba Networks**: securelogin.arubanetworks.com
- **Public WiFi Providers**: *.selectwifi.xfinity.com (Xfinity WiFi)
- **Generic**: neverssl.com, example.com

And many others (140+ domains total)

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

## Configuration

You can customize captive portal behavior in your `config.yaml`:

```yaml
captivePortal:
  enabled: true                    # Enable/disable automatic detection
  detectionThreshold: 3            # Number of unique captive portal domains to trigger bypass
  detectionWindow: "10s"           # Time window for detection
  bypassDuration: "5m"             # How long to disable filtering
  additionalDomains:               # Add custom captive portal domains
    - "custom-portal.company.com"
    - "wifi.hotel-chain.com"
```

## Technical Details

### Detection Algorithm
- Monitors DNS requests for known captive portal domains
- Triggers bypass when configured threshold of different captive portal domains are queried within the detection window
- Automatically clears counters after bypass is enabled
- Includes comprehensive domain list covering all major operating systems and browsers

### Known Limitations

#### Multi-Stage Captive Portals
Some captive portals use a multi-stage authentication process where users are redirected through multiple networks during login. DNShield may not automatically detect all stages of these complex portals. 

**Workaround**: Use manual bypass mode (`sudo ./dnshield bypass enable`) when encountering multi-stage portals.

#### DNS-Intercepting Portals
Some captive portals intercept ALL DNS traffic, which can interfere with DNShield's operation entirely. These portals may require manual intervention.

#### HTTPS-Only Networks
Networks that only allow HTTPS traffic may block DNShield's standard DNS queries on port 53.

### Security Considerations
- Bypass mode only affects DNS filtering - your HTTPS connections remain secure
- The CA certificate and HTTPS proxy continue to function normally
- Only DNS blocking is temporarily disabled
- Each captive portal access is logged for security auditing

### Comparison with Other Solutions

| Solution | Method | User Action Required |
|----------|--------|---------------------|
| **DNShield** | Automatic detection + manual override | None (automatic) |
| **NextDNS** | App toggle or excluded domains | Manual toggle |
| **Pi-hole** | Manual disable | Full manual |
| **AdGuard** | Manual disable or allowlist | Manual configuration |

DNShield's automatic detection provides the best user experience while maintaining security.