import SwiftUI
import Charts

struct StatisticsView: View {
    @EnvironmentObject var appState: AppState
    @State private var selectedTimeRange = TimeRange.today
    
    enum TimeRange: String, CaseIterable {
        case today = "Today"
        case week = "Week"
        case month = "Month"
        case allTime = "All Time"
    }
    
    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                // Time range selector
                Picker("Time Range", selection: $selectedTimeRange) {
                    ForEach(TimeRange.allCases, id: \.self) { range in
                        Text(range.rawValue).tag(range)
                    }
                }
                .pickerStyle(SegmentedPickerStyle())
                .padding(.horizontal)
                
                // Summary Cards
                HStack(spacing: 12) {
                    StatCard(
                        title: "Queries",
                        value: formatNumber(queriesForRange),
                        icon: "network",
                        color: .blue
                    )
                    
                    StatCard(
                        title: "Blocked",
                        value: formatNumber(blockedForRange),
                        subtitle: String(format: "%.1f%%", blockPercentageForRange),
                        icon: "shield.fill",
                        color: .red
                    )
                }
                .padding(.horizontal)
                
                HStack(spacing: 12) {
                    StatCard(
                        title: "Cache Hit Rate",
                        value: String(format: "%.1f%%", appState.statistics.cacheHitRate),
                        icon: "speedometer",
                        color: .green
                    )
                    
                    StatCard(
                        title: "Certificates",
                        value: formatNumber(appState.statistics.certificatesGenerated),
                        icon: "lock.shield.fill",
                        color: .orange
                    )
                }
                .padding(.horizontal)
                
                // Performance Metrics
                VStack(alignment: .leading, spacing: 8) {
                    Text("Performance")
                        .font(.headline)
                        .foregroundColor(.secondary)
                    
                    VStack(spacing: 12) {
                        PerformanceRow(
                            label: "Memory Usage",
                            value: String(format: "%.1f MB", appState.statistics.memoryUsageMB),
                            percentage: min(appState.statistics.memoryUsageMB / 500.0, 1.0) // Assume 500MB max
                        )
                        
                        PerformanceRow(
                            label: "CPU Usage",
                            value: String(format: "%.1f%%", appState.statistics.cpuUsagePercent),
                            percentage: appState.statistics.cpuUsagePercent / 100.0
                        )
                        
                        PerformanceRow(
                            label: "Cache Efficiency",
                            value: String(format: "%.1f%%", appState.statistics.cacheHitRate),
                            percentage: appState.statistics.cacheHitRate / 100.0,
                            isGood: true
                        )
                    }
                    .padding(12)
                    .background(Color(NSColor.controlBackgroundColor))
                    .cornerRadius(8)
                }
                .padding(.horizontal)
                
                // Rule Update Info
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Rule Updates")
                            .font(.headline)
                            .foregroundColor(.secondary)
                        
                        Spacer()
                        
                        Button("Update Now") {
                            appState.refreshRules()
                        }
                        .buttonStyle(LinkButtonStyle())
                        .font(.caption)
                    }
                    
                    HStack {
                        Image(systemName: "clock")
                            .foregroundColor(.secondary)
                        
                        Text("Last updated: \(RelativeDateTimeFormatter().localizedString(for: appState.statistics.lastRuleUpdate, relativeTo: Date()))")
                            .font(.system(size: 12))
                            .foregroundColor(.secondary)
                    }
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(NSColor.controlBackgroundColor))
                    .cornerRadius(8)
                }
                .padding(.horizontal)
            }
            .padding(.vertical)
        }
    }
    
    // Computed properties for selected time range
    private var queriesForRange: Int64 {
        switch selectedTimeRange {
        case .today:
            return appState.statistics.queriesToday
        case .week, .month, .allTime:
            return appState.statistics.queriesTotal
        }
    }
    
    private var blockedForRange: Int64 {
        switch selectedTimeRange {
        case .today:
            return appState.statistics.blockedToday
        case .week, .month, .allTime:
            return appState.statistics.queriesBlocked
        }
    }
    
    private var blockPercentageForRange: Double {
        switch selectedTimeRange {
        case .today:
            return appState.statistics.todayBlockPercentage
        case .week, .month, .allTime:
            return appState.statistics.blockPercentage
        }
    }
    
    private func formatNumber(_ number: Int64) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.maximumFractionDigits = 0
        return formatter.string(from: NSNumber(value: number)) ?? "0"
    }
}

struct StatCard: View {
    let title: String
    let value: String
    var subtitle: String? = nil
    let icon: String
    let color: Color
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Image(systemName: icon)
                    .foregroundColor(color)
                    .font(.caption)
                
                Text(title)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            Text(value)
                .font(.system(size: 20, weight: .semibold, design: .rounded))
            
            if let subtitle = subtitle {
                Text(subtitle)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }
}

struct PerformanceRow: View {
    let label: String
    let value: String
    let percentage: Double
    var isGood: Bool = false
    
    var barColor: Color {
        if isGood {
            return .green
        } else if percentage > 0.8 {
            return .red
        } else if percentage > 0.6 {
            return .yellow
        } else {
            return .blue
        }
    }
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(label)
                    .font(.system(size: 12))
                    .foregroundColor(.secondary)
                
                Spacer()
                
                Text(value)
                    .font(.system(size: 12, weight: .medium))
            }
            
            GeometryReader { geometry in
                ZStack(alignment: .leading) {
                    Rectangle()
                        .fill(Color(NSColor.separatorColor).opacity(0.3))
                        .frame(height: 4)
                        .cornerRadius(2)
                    
                    Rectangle()
                        .fill(barColor)
                        .frame(width: geometry.size.width * percentage, height: 4)
                        .cornerRadius(2)
                        .animation(.easeInOut(duration: 0.3), value: percentage)
                }
            }
            .frame(height: 4)
        }
    }
}

struct StatisticsView_Previews: PreviewProvider {
    static var previews: some View {
        StatisticsView()
            .environmentObject(AppState())
            .frame(width: 320, height: 480)
    }
}