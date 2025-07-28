import SwiftUI

struct StatusView: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Service Status
                StatusSection(title: "Service Status") {
                    StatusRow(label: "DNS Service", value: appState.status.running ? "Running" : "Stopped", isGood: appState.status.running)
                    StatusRow(label: "Protection", value: appState.status.protected ? "Active" : "Inactive", isGood: appState.status.protected)
                    StatusRow(label: "Certificate", value: appState.status.certificateValid ? "Valid" : "Invalid", isGood: appState.status.certificateValid)
                }
                
                // Network Status
                if appState.status.currentNetwork != nil || appState.status.networkInterface != nil {
                    StatusSection(title: "Network Status") {
                        if let network = appState.status.currentNetwork {
                            StatusRow(label: "Network", value: network)
                        }
                        
                        if let interface = appState.status.networkInterface {
                            StatusRow(label: "Interface", value: interface)
                        }
                        
                        if let originalDNS = appState.status.originalDNS, !originalDNS.isEmpty {
                            StatusRow(label: "Original DNS", value: originalDNS.joined(separator: ", "))
                        }
                    }
                }
                
                // DNS Configuration
                StatusSection(title: "DNS Configuration") {
                    StatusRow(label: "System DNS", value: appState.status.dnsConfigured ? "Configured" : "Not Configured", isGood: appState.status.dnsConfigured)
                    
                    if !appState.status.currentDNS.isEmpty {
                        StatusRow(label: "Current DNS", value: appState.status.currentDNS.joined(separator: ", "))
                    }
                    
                    if !appState.status.upstreamDNS.isEmpty {
                        StatusRow(label: "Upstream DNS", value: appState.status.upstreamDNS.joined(separator: ", "))
                    }
                }
                
                // Policy Status (if enforced)
                if appState.status.policyEnforced {
                    StatusSection(title: "Policy") {
                        StatusRow(label: "Status", value: "Enforced", isGood: true)
                        StatusRow(label: "Source", value: appState.status.policySource)
                        StatusRow(label: "Can Disable", value: appState.configuration.allowPause ? "Yes" : "No", isGood: appState.configuration.allowPause)
                    }
                }
                
                // System Info
                StatusSection(title: "System") {
                    StatusRow(label: "Uptime", value: appState.statistics.uptime)
                    StatusRow(label: "Memory Usage", value: String(format: "%.1f MB", appState.statistics.memoryUsageMB))
                    StatusRow(label: "Last Health Check", value: RelativeDateTimeFormatter().localizedString(for: appState.status.lastHealthCheck, relativeTo: Date()))
                }
            }
            .padding()
        }
    }
}

struct StatusSection<Content: View>: View {
    let title: String
    let content: Content
    
    init(title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.headline)
                .foregroundColor(.secondary)
            
            VStack(alignment: .leading, spacing: 4) {
                content
            }
            .padding(12)
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(8)
        }
    }
}

struct StatusRow: View {
    let label: String
    let value: String
    var isGood: Bool? = nil
    
    var body: some View {
        HStack {
            Text(label)
                .foregroundColor(.secondary)
                .frame(width: 120, alignment: .leading)
            
            if let isGood = isGood {
                HStack(spacing: 4) {
                    Image(systemName: isGood ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundColor(isGood ? .green : .red)
                        .font(.caption)
                    Text(value)
                        .fontWeight(.medium)
                }
            } else {
                Text(value)
                    .fontWeight(.medium)
            }
            
            Spacer()
        }
        .font(.system(size: 12))
    }
}

struct StatusView_Previews: PreviewProvider {
    static var previews: some View {
        StatusView()
            .environmentObject(AppState())
            .frame(width: 320)
    }
}