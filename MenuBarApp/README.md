# DNShield Menu Bar App

A native macOS menu bar application that provides real-time status monitoring and control for DNShield.

## Features

### User Features
- **Real-time Status Monitoring**: Visual indicator shows protection status at a glance
  - 🟢 Green shield: Fully protected
  - 🟡 Yellow shield: Partial protection
  - 🔴 Red shield: Not protected
  - ⚫ Gray shield: Service offline

- **Quick Actions**:
  - Pause protection temporarily (5 min, 30 min, 1 hour)
  - View recently blocked domains
  - Clear DNS cache
  - Refresh blocking rules

- **Comprehensive Statistics**:
  - Total queries and blocked count
  - Cache hit rate
  - Performance metrics (CPU, memory)
  - Today's activity summary

- **Activity Monitoring**:
  - Real-time list of blocked domains
  - Search and filter capabilities
  - Detailed domain information

### Enterprise Features
- **Policy Enforcement**: Respects enterprise policies that prevent disabling protection
- **Compliance Indicators**: Shows when protection is mandated by policy
- **Audit Trail**: All actions are logged for compliance
- **Remote Management Ready**: Designed for MDM integration

## Installation

### Quick Install
```bash
make install-menubar
```

### Manual Installation
1. Build the app:
   ```bash
   cd MenuBarApp
   ./build.sh
   ```

2. Install:
   ```bash
   ./install-menubar.sh
   ```

The app will be installed to `/Applications/DNShield Status.app` and configured to start automatically on login.

## Architecture

### Technology Stack
- **Language**: Swift 5.9+
- **UI Framework**: SwiftUI
- **Platform**: macOS 13.0+
- **Communication**: REST API + WebSocket

### API Communication
The menu bar app communicates with DNShield service via:
- REST API on `http://127.0.0.1:5353/api`
- WebSocket for real-time updates
- Polling for status updates every 5 seconds
- Statistics refresh every 10 seconds

### Security
- Only accepts connections from localhost
- No external network access required
- Respects macOS privacy settings
- Sandboxed execution where possible

## Development

### Building from Source
```bash
cd MenuBarApp/DNShieldStatusBar
swift build
```

### Running in Development
```bash
swift run
```

### Project Structure
```
DNShieldStatusBar/
├── Sources/
│   ├── DNShieldApp.swift      # Main app entry point
│   ├── AppState.swift         # State management
│   ├── Models/
│   │   └── Models.swift       # Data models
│   ├── Services/
│   │   └── DNShieldAPI.swift  # API client
│   └── Views/
│       ├── ContentView.swift  # Main view
│       ├── StatusView.swift   # Status tab
│       ├── ActivityView.swift # Activity tab
│       └── StatisticsView.swift # Stats tab
└── Package.swift              # Swift package manifest
```

## Uninstallation

To completely remove the menu bar app:

1. Quit the app from the menu bar
2. Remove auto-start:
   ```bash
   launchctl unload ~/Library/LaunchAgents/com.dnshield.statusbar.plist
   rm ~/Library/LaunchAgents/com.dnshield.statusbar.plist
   ```
3. Delete the app:
   ```bash
   rm -rf "/Applications/DNShield Status.app"
   ```

## Troubleshooting

### App doesn't appear in menu bar
- Check if DNShield service is running: `make status`
- Verify API is accessible: `curl http://127.0.0.1:5353/api/health`
- Check logs: `/tmp/dnshield-statusbar.err`

### Can't connect to service
- Ensure DNShield is running with API server enabled
- Check if port 5353 is available
- Verify no firewall is blocking local connections

### Statistics not updating
- Check WebSocket connection in logs
- Verify DNShield service is processing queries
- Try restarting both service and menu bar app

## License

Same as DNShield - see main LICENSE.md file.