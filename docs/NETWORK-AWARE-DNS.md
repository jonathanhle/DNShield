# Network-Aware DNS Management

## Overview

DNShield now features intelligent network-aware DNS management that automatically adapts to different network environments. This ensures the pause/resume functionality works correctly regardless of network changes.

## Key Features

### 1. **Automatic Network Detection**
- Detects when you switch WiFi networks
- Recognizes ethernet connections
- Identifies VPN connections
- Monitors for network changes every 5 seconds

### 2. **Per-Network DNS Storage**
- Remembers original DNS settings for each network
- Stores configurations in `~/.dnshield/network-dns/`
- Each network has a unique identifier based on:
  - WiFi SSID
  - Gateway MAC address (stable across reconnects)
  - Network interface
  - Subnet information

### 3. **Smart DNS Capture**
- Only captures DNS when it's not already set to 127.0.0.1
- Preserves both DHCP and static DNS configurations
- Tracks how many times you've connected to each network

### 4. **Seamless Network Transitions**
When you switch networks:
- Automatically detects the change
- Captures DNS for new networks if needed
- Maintains protection across transitions
- Restores correct DNS when paused

## Network Identity

Each network is uniquely identified by:
```json
{
  "id": "a1b2c3d4e5f67890",  // Unique hash
  "ssid": "Home WiFi",       // WiFi network name
  "interface": "en0",         // Network interface
  "interface_type": "wifi",   // Type of connection
  "gateway_ip": "192.168.1.1",
  "gateway_mac": "aa:bb:cc:dd:ee:ff",
  "subnet": "192.168.1.0/24",
  "is_vpn": false,
  "last_seen": "2024-01-15T10:30:00Z"
}
```

## How It Works

### Initial Setup
1. Run `dnshield install-ca` - initializes network manager
2. Network manager creates config directory
3. Ready to track DNS across networks

### When DNShield Starts
1. Detects current network
2. Starts monitoring for changes
3. If DNS filtering is enabled:
   - Captures original DNS if not already saved
   - Sets DNS to 127.0.0.1

### During Normal Operation
```
Network A (Home)          Network B (Coffee Shop)
DNS: 192.168.1.1    →    DNS: 10.0.0.1
      ↓                         ↓
   Captured                  Captured
      ↓                         ↓
DNS: 127.0.0.1           DNS: 127.0.0.1
(DNShield Active)        (DNShield Active)
```

### When Paused
```
Network A (Home)          Network B (Coffee Shop)
   Paused                    Paused
      ↓                         ↓
DNS: 192.168.1.1         DNS: 10.0.0.1
(Original Restored)      (Original Restored)
```

## Configuration Files

### Network DNS Configurations
Location: `~/.dnshield/network-dns/network-<id>.json`

Example:
```json
{
  "network_id": "a1b2c3d4e5f67890",
  "network_identity": {
    "id": "a1b2c3d4e5f67890",
    "ssid": "Home WiFi",
    "interface": "en0",
    "interface_type": "wifi",
    "gateway_ip": "192.168.1.1",
    "gateway_mac": "aa:bb:cc:dd:ee:ff",
    "subnet": "192.168.1.0/24",
    "last_seen": "2024-01-15T10:30:00Z",
    "is_vpn": false
  },
  "dns_servers": ["192.168.1.1", "8.8.8.8"],
  "is_dhcp": false,
  "captured_at": "2024-01-15T10:30:00Z",
  "last_updated": "2024-01-15T14:00:00Z",
  "times_connected": 5,
  "notes": ""
}
```

## VPN Handling

DNShield detects VPN connections:
- Identifies VPN interfaces (utun*, ppp*)
- Preserves VPN DNS settings
- Handles VPN connect/disconnect gracefully

## Edge Cases Handled

### 1. **New Network Without Saved DNS**
- Temporarily captures current DNS
- Enables filtering
- Saves configuration for future use

### 2. **Network Change While Paused**
- Detects network change
- Checks if new network has saved DNS
- If yes: Restores that network's DNS
- If no: Resumes protection (safer default)

### 3. **Multiple Active Interfaces**
- Uses default route to determine primary interface
- Handles failover between WiFi and Ethernet

### 4. **DHCP vs Static DNS**
- DHCP: Saves as "Empty" (system default)
- Static: Saves actual DNS server IPs

## API Integration

The status endpoint now includes network information:
```json
{
  "running": true,
  "protected": true,
  "current_network": "Home WiFi",
  "network_interface": "en0",
  "original_dns": ["192.168.1.1", "8.8.8.8"],
  ...
}
```

## Menu Bar App Display

The menu bar app can now show:
- Current network name (WiFi SSID or interface)
- Original DNS servers for the network
- Network-specific statistics

## Troubleshooting

### DNS Not Captured for Network
- Check `~/.dnshield/network-dns/` for saved configs
- Ensure DNShield has permission to run `networksetup`
- Check logs for capture errors

### Wrong DNS Restored
- Verify network identity in logs
- Check if gateway MAC changed (new router)
- Clear saved config for that network

### Network Changes Not Detected
- Check if monitoring is running
- Verify polling interval (5 seconds default)
- Check system logs for errors

## Benefits

1. **Zero Configuration**: Works automatically
2. **Network Memory**: Remembers each network's DNS
3. **Seamless Roaming**: Works across network changes
4. **VPN Compatible**: Handles VPN connections
5. **Enterprise Ready**: Supports complex network environments

## Future Enhancements

- macOS SystemConfiguration framework integration
- Instant network change notifications
- Network-specific blocking rules
- Corporate network detection
- Network trust levels