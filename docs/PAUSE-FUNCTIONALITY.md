# DNShield Pause Functionality

## Overview

DNShield now supports temporary pausing of DNS filtering, which restores the system's original DNS resolvers for a specified duration. This feature is useful for:

- Troubleshooting connectivity issues
- Temporarily accessing blocked sites for legitimate business needs
- Testing without DNS filtering

## How It Works

### DNS Configuration Capture
1. **During Installation**: When you run `dnshield install-ca`, the system automatically captures your current DNS configuration
2. **Stored Securely**: Original DNS settings are saved in `~/.dnshield/dns-config.json`
3. **Preserved Settings**: Both static DNS servers and DHCP configurations are preserved

### Pause Operation
When protection is paused:
1. Original DNS servers are restored on all network interfaces
2. DNS queries bypass DNShield completely
3. All domains become accessible (no blocking)
4. A timer is set to automatically resume protection

### Resume Operation
When the pause expires or is manually resumed:
1. DNS is reconfigured to use DNShield (127.0.0.1)
2. Filtering resumes immediately
3. All configured blocking rules are enforced again

## Usage

### Via Menu Bar App
1. Click the pause button in the header
2. Select duration:
   - 5 minutes
   - 30 minutes
   - 1 hour
3. Protection status changes to "Not Protected"
4. Original DNS servers are active

### Via API
```bash
# Pause for 30 minutes
curl -X POST http://127.0.0.1:5353/api/pause \
  -H "Content-Type: application/json" \
  -d '{"duration": "30m"}'

# Resume immediately
curl -X POST http://127.0.0.1:5353/api/resume
```

## Configuration

### Enable/Disable Pause Functionality
In your `config.yaml`:
```yaml
agent:
  allowDisable: true  # Set to false to prevent pausing
```

When `allowDisable: false`:
- Pause button is hidden in menu bar app
- API returns 403 Forbidden for pause requests
- Enterprise policy enforcement

## Technical Details

### DNS Configuration Format
```json
{
  "version": 1,
  "captured_at": "2024-01-15T10:30:00Z",
  "captured_by": "DNShield",
  "interfaces": {
    "Wi-Fi": {
      "name": "Wi-Fi",
      "type": "wifi",
      "dns_servers": ["192.168.1.1", "8.8.8.8"],
      "is_dhcp": false,
      "is_active": true
    },
    "Ethernet": {
      "name": "Ethernet",
      "type": "ethernet",
      "dns_servers": [],
      "is_dhcp": true,
      "is_active": false
    }
  },
  "metadata": {
    "os": "darwin",
    "hostname": "MacBook-Pro.local"
  }
}
```

### Implementation Details
- Uses macOS `networksetup` command for DNS configuration
- Supports both DHCP and static DNS configurations
- Thread-safe implementation with mutex locks
- Automatic timer management for pause duration
- Graceful error handling and logging

## Security Considerations

1. **Permission Control**: Pause functionality can be disabled via configuration
2. **Local Only**: API only accepts connections from localhost
3. **Audit Logging**: All pause/resume actions are logged
4. **No Permanent Changes**: Original DNS is always preserved

## Troubleshooting

### Pause Not Working
1. Check if `allowDisable: true` in config
2. Verify original DNS was captured during installation
3. Check logs for DNS restoration errors

### DNS Not Restored After Pause
1. The pause timer ensures automatic restoration
2. Manual resume via API or menu bar app
3. Restart DNShield service as last resort

### Original DNS Not Captured
Run installation again:
```bash
./dnshield install-ca
```

This will capture current DNS settings without reinstalling the CA certificate.