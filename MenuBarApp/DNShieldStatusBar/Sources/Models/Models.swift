import Foundation

// MARK: - Protection Level
enum ProtectionLevel {
    case protected
    case partial
    case notProtected
    case offline
}

// MARK: - Service Status
struct ServiceStatus: Codable {
    let running: Bool
    let protected: Bool
    let dnsConfigured: Bool
    let currentDNS: [String]
    let upstreamDNS: [String]
    let mode: String
    let policyEnforced: Bool
    let policySource: String
    let lastHealthCheck: Date
    let version: String
    let certificateValid: Bool
    let currentNetwork: String?
    let networkInterface: String?
    let originalDNS: [String]?
    
    var protectionLevel: ProtectionLevel {
        if !running {
            return .offline
        } else if protected && dnsConfigured && certificateValid {
            return .protected
        } else if protected || dnsConfigured {
            return .partial
        } else {
            return .notProtected
        }
    }
    
    private enum CodingKeys: String, CodingKey {
        case running, protected
        case dnsConfigured = "dns_configured"
        case currentDNS = "current_dns"
        case upstreamDNS = "upstream_dns"
        case mode
        case policyEnforced = "policy_enforced"
        case policySource = "policy_source"
        case lastHealthCheck = "last_health_check"
        case version
        case certificateValid = "certificate_valid"
        case currentNetwork = "current_network"
        case networkInterface = "network_interface"
        case originalDNS = "original_dns"
    }
}

// MARK: - Statistics
struct Statistics: Codable {
    let queriesTotal: Int64
    let queriesBlocked: Int64
    let cacheHits: Int64
    let cacheMisses: Int64
    let certificatesGenerated: Int64
    let uptime: String
    let lastRuleUpdate: Date
    let blockedToday: Int64
    let queriesToday: Int64
    let cacheHitRate: Double
    let memoryUsageMB: Double
    let cpuUsagePercent: Double
    
    var blockPercentage: Double {
        guard queriesTotal > 0 else { return 0 }
        return Double(queriesBlocked) / Double(queriesTotal) * 100
    }
    
    var todayBlockPercentage: Double {
        guard queriesToday > 0 else { return 0 }
        return Double(blockedToday) / Double(queriesToday) * 100
    }
    
    private enum CodingKeys: String, CodingKey {
        case queriesTotal = "queries_total"
        case queriesBlocked = "queries_blocked"
        case cacheHits = "cache_hits"
        case cacheMisses = "cache_misses"
        case certificatesGenerated = "certificates_generated"
        case uptime
        case lastRuleUpdate = "last_rule_update"
        case blockedToday = "blocked_today"
        case queriesToday = "queries_today"
        case cacheHitRate = "cache_hit_rate"
        case memoryUsageMB = "memory_usage_mb"
        case cpuUsagePercent = "cpu_usage_percent"
    }
}

// MARK: - Blocked Domain
struct BlockedDomain: Codable, Identifiable {
    let id = UUID()
    let domain: String
    let timestamp: Date
    let rule: String
    let clientIP: String
    
    private enum CodingKeys: String, CodingKey {
        case domain, timestamp, rule
        case clientIP = "client_ip"
    }
}

// MARK: - Configuration
struct Configuration: Codable {
    let allowPause: Bool
    let allowQuit: Bool
    let policyURL: String?
    let reportingURL: String?
    let updateInterval: Int
    
    private enum CodingKeys: String, CodingKey {
        case allowPause = "allow_pause"
        case allowQuit = "allow_quit"
        case policyURL = "policy_url"
        case reportingURL = "reporting_url"
        case updateInterval = "update_interval"
    }
}

// MARK: - API Responses
struct PauseRequest: Codable {
    let duration: String
}