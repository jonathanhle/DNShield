import SwiftUI

struct ActivityView: View {
    @EnvironmentObject var appState: AppState
    @State private var searchText = ""
    @State private var selectedDomain: BlockedDomain?
    
    var filteredDomains: [BlockedDomain] {
        if searchText.isEmpty {
            return appState.recentBlocked
        } else {
            return appState.recentBlocked.filter { 
                $0.domain.localizedCaseInsensitiveContains(searchText) ||
                $0.clientIP.contains(searchText)
            }
        }
    }
    
    var body: some View {
        VStack(spacing: 0) {
            // Search bar
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.secondary)
                
                TextField("Search domains...", text: $searchText)
                    .textFieldStyle(PlainTextFieldStyle())
                
                if !searchText.isEmpty {
                    Button(action: { searchText = "" }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(PlainButtonStyle())
                }
            }
            .padding(8)
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(8)
            .padding()
            
            // Activity list
            if filteredDomains.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "shield.checkmark")
                        .font(.largeTitle)
                        .foregroundColor(.secondary)
                    
                    Text(searchText.isEmpty ? "No blocked domains yet" : "No matching domains")
                        .foregroundColor(.secondary)
                    
                    Text("Blocked domains will appear here")
                        .font(.caption)
                        .foregroundColor(.tertiary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .padding()
            } else {
                List(filteredDomains.reversed()) { blocked in
                    BlockedDomainRow(blocked: blocked) {
                        selectedDomain = blocked
                    }
                    .padding(.vertical, 2)
                }
                .listStyle(PlainListStyle())
            }
        }
        .sheet(item: $selectedDomain) { domain in
            DomainDetailSheet(domain: domain)
        }
    }
}

struct BlockedDomainRow: View {
    let blocked: BlockedDomain
    let onTap: () -> Void
    @State private var isHovering = false
    
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(blocked.domain)
                    .font(.system(size: 13, weight: .medium))
                    .lineLimit(1)
                
                HStack(spacing: 8) {
                    Text(timeAgo(from: blocked.timestamp))
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    Text("•")
                        .foregroundColor(.tertiary)
                    
                    Text(blocked.clientIP)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            
            Spacer()
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(isHovering ? Color(NSColor.selectedControlColor).opacity(0.1) : Color.clear)
        .cornerRadius(4)
        .onHover { hovering in
            isHovering = hovering
        }
        .onTapGesture {
            onTap()
        }
    }
    
    private func timeAgo(from date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter.localizedString(for: date, relativeTo: Date())
    }
    
}

struct DomainDetailSheet: View {
    let domain: BlockedDomain
    @Environment(\.dismiss) var dismiss
    
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Header
            HStack {
                Text("Domain Details")
                    .font(.headline)
                
                Spacer()
                
                Button("Close") {
                    dismiss()
                }
            }
            
            Divider()
            
            // Domain info
            VStack(alignment: .leading, spacing: 8) {
                DetailRow(label: "Domain", value: domain.domain)
                DetailRow(label: "Blocked at", value: DateFormatter.localizedString(from: domain.timestamp, dateStyle: .medium, timeStyle: .medium))
                DetailRow(label: "Client IP", value: domain.clientIP)
                DetailRow(label: "Rule", value: domain.rule)
            }
            
            Spacer()
            
            // Actions
            HStack {
                Spacer()
                
                Button("Close") {
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding()
        .frame(width: 400)
    }
    
}

struct DetailRow: View {
    let label: String
    let value: String
    
    var body: some View {
        HStack(alignment: .top) {
            Text(label + ":")
                .foregroundColor(.secondary)
                .frame(width: 80, alignment: .leading)
            
            Text(value)
                .textSelection(.enabled)
                .lineLimit(nil)
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(.system(size: 12))
    }
}

struct ActivityView_Previews: PreviewProvider {
    static var previews: some View {
        ActivityView()
            .environmentObject(AppState())
            .frame(width: 320, height: 400)
    }
}