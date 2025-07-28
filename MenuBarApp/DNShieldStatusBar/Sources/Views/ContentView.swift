import SwiftUI

struct ContentView: View {
    @EnvironmentObject var appState: AppState
    @State private var selectedTab = 0
    
    var body: some View {
        VStack(spacing: 0) {
            // Header
            HeaderView()
                .padding()
                .background(Color(NSColor.controlBackgroundColor))
            
            Divider()
            
            // Tab Selection
            Picker("", selection: $selectedTab) {
                Text("Status").tag(0)
                Text("Activity").tag(1)
                Text("Statistics").tag(2)
            }
            .pickerStyle(SegmentedPickerStyle())
            .padding(.horizontal)
            .padding(.vertical, 8)
            
            // Tab Content
            TabView(selection: $selectedTab) {
                StatusView()
                    .tag(0)
                
                ActivityView()
                    .tag(1)
                
                StatisticsView()
                    .tag(2)
            }
            .tabViewStyle(PageTabViewStyle(indexDisplayMode: .never))
            
            Divider()
            
            // Footer Actions
            FooterView()
                .padding()
                .background(Color(NSColor.controlBackgroundColor))
        }
        .frame(width: 320, height: 480)
    }
}

// MARK: - Header View
struct HeaderView: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        HStack {
            // Status Icon
            Image(systemName: statusIcon)
                .font(.title)
                .foregroundColor(statusColor)
            
            VStack(alignment: .leading, spacing: 4) {
                Text(statusText)
                    .font(.headline)
                if let network = appState.status.currentNetwork {
                    Text(network)
                        .font(.caption)
                        .foregroundColor(.secondary)
                } else {
                    Text(appState.status.mode)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            
            Spacer()
            
            // Protection Toggle (if allowed)
            if appState.configuration.allowPause {
                Button(action: toggleProtection) {
                    Image(systemName: appState.isPaused ? "play.fill" : "pause.fill")
                        .font(.title2)
                }
                .buttonStyle(PlainButtonStyle())
                .help(appState.isPaused ? "Resume Protection" : "Pause Protection")
            }
        }
    }
    
    private var statusIcon: String {
        switch appState.status.protectionLevel {
        case .protected:
            return "shield.fill"
        case .partial:
            return "shield.fill"
        case .notProtected:
            return "exclamationmark.shield.fill"
        case .offline:
            return "shield.slash.fill"
        }
    }
    
    private var statusColor: Color {
        switch appState.status.protectionLevel {
        case .protected:
            return .green
        case .partial:
            return .yellow
        case .notProtected:
            return .red
        case .offline:
            return .gray
        }
    }
    
    private var statusText: String {
        switch appState.status.protectionLevel {
        case .protected:
            return "Protected"
        case .partial:
            return "Partial Protection"
        case .notProtected:
            return "Not Protected"
        case .offline:
            return "Service Offline"
        }
    }
    
    private func toggleProtection() {
        if appState.isPaused {
            appState.resumeProtection()
        } else {
            // Show pause duration options
            showPauseMenu()
        }
    }
    
    private func showPauseMenu() {
        let menu = NSMenu()
        
        menu.addItem(withTitle: "Pause for 5 minutes", action: #selector(pause5Min), keyEquivalent: "")
        menu.addItem(withTitle: "Pause for 30 minutes", action: #selector(pause30Min), keyEquivalent: "")
        menu.addItem(withTitle: "Pause for 1 hour", action: #selector(pause1Hour), keyEquivalent: "")
        
        menu.popUp(positioning: nil, at: NSEvent.mouseLocation, in: nil)
    }
    
    @objc private func pause5Min() {
        appState.pauseProtection(duration: "5m")
    }
    
    @objc private func pause30Min() {
        appState.pauseProtection(duration: "30m")
    }
    
    @objc private func pause1Hour() {
        appState.pauseProtection(duration: "1h")
    }
}

// MARK: - Footer View
struct FooterView: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        HStack {
            Menu {
                Button("Open Logs") {
                    appState.openLogs()
                }
                
                Button("Refresh Rules") {
                    appState.refreshRules()
                }
                
                Button("Clear DNS Cache") {
                    appState.clearCache()
                }
                
                Divider()
                
                Button("About DNShield") {
                    showAbout()
                }
                
                if appState.configuration.allowQuit {
                    Divider()
                    
                    Button("Quit") {
                        appState.quitApp()
                    }
                }
            } label: {
                Image(systemName: "gearshape.fill")
                    .font(.title3)
            }
            .menuStyle(BorderlessButtonMenuStyle())
            .frame(width: 30)
            
            Spacer()
            
            // Connection Status
            HStack(spacing: 4) {
                Circle()
                    .fill(appState.isConnected ? Color.green : Color.red)
                    .frame(width: 8, height: 8)
                Text(appState.isConnected ? "Connected" : "Disconnected")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }
    
    private func showAbout() {
        let alert = NSAlert()
        alert.messageText = "DNShield"
        alert.informativeText = "Version \(appState.status.version)\n\nEnterprise DNS filtering and protection for macOS."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}

// Preview
struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
            .environmentObject(AppState())
    }
}