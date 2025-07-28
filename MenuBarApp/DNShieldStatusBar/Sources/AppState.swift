import Foundation
import Combine
import SwiftUI

class AppState: ObservableObject {
    @Published var status = ServiceStatus(
        running: false,
        protected: false,
        dnsConfigured: false,
        currentDNS: [],
        upstreamDNS: [],
        mode: "unknown",
        policyEnforced: false,
        policySource: "none",
        lastHealthCheck: Date(),
        version: "0.0.0",
        certificateValid: false,
        currentNetwork: nil,
        networkInterface: nil,
        originalDNS: nil
    )
    
    @Published var statistics = Statistics(
        queriesTotal: 0,
        queriesBlocked: 0,
        cacheHits: 0,
        cacheMisses: 0,
        certificatesGenerated: 0,
        uptime: "0s",
        lastRuleUpdate: Date(),
        blockedToday: 0,
        queriesToday: 0,
        cacheHitRate: 0,
        memoryUsageMB: 0,
        cpuUsagePercent: 0
    )
    
    @Published var recentBlocked: [BlockedDomain] = []
    @Published var configuration = Configuration(
        allowPause: true,
        allowQuit: true,
        policyURL: nil,
        reportingURL: nil,
        updateInterval: 60
    )
    
    @Published var isConnected = false
    @Published var isPaused = false
    @Published var lastError: String?
    
    var cancellables = Set<AnyCancellable>()
    private var statusTimer: Timer?
    private var statsTimer: Timer?
    private var webSocketTask: URLSessionWebSocketTask?
    private let api = DNShieldAPI.shared
    
    init() {
        // Start with checking if service is running
        checkServiceStatus()
    }
    
    func startMonitoring() {
        // Fetch initial data
        fetchStatus()
        fetchStatistics()
        fetchConfiguration()
        fetchRecentBlocked()
        
        // Set up periodic updates
        statusTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { _ in
            self.fetchStatus()
        }
        
        statsTimer = Timer.scheduledTimer(withTimeInterval: 10.0, repeats: true) { _ in
            self.fetchStatistics()
            self.fetchRecentBlocked()
        }
        
        // Connect WebSocket for real-time updates
        connectWebSocket()
    }
    
    func stopMonitoring() {
        statusTimer?.invalidate()
        statsTimer?.invalidate()
        webSocketTask?.cancel()
        
        statusTimer = nil
        statsTimer = nil
        webSocketTask = nil
    }
    
    // MARK: - Service Check
    
    private func checkServiceStatus() {
        // Try to connect to the API to see if service is running
        api.fetchStatus()
            .receive(on: DispatchQueue.main)
            .sink(
                receiveCompletion: { completion in
                    if case .failure = completion {
                        self.isConnected = false
                    }
                },
                receiveValue: { status in
                    self.isConnected = true
                    self.status = status
                }
            )
            .store(in: &cancellables)
    }
    
    // MARK: - Data Fetching
    
    private func fetchStatus() {
        api.fetchStatus()
            .receive(on: DispatchQueue.main)
            .sink(
                receiveCompletion: { completion in
                    if case .failure(let error) = completion {
                        self.isConnected = false
                        self.lastError = error.localizedDescription
                    }
                },
                receiveValue: { status in
                    self.isConnected = true
                    self.status = status
                    self.lastError = nil
                }
            )
            .store(in: &cancellables)
    }
    
    private func fetchStatistics() {
        api.fetchStatistics()
            .receive(on: DispatchQueue.main)
            .sink(
                receiveCompletion: { _ in },
                receiveValue: { stats in
                    self.statistics = stats
                }
            )
            .store(in: &cancellables)
    }
    
    private func fetchRecentBlocked() {
        api.fetchRecentBlocked()
            .receive(on: DispatchQueue.main)
            .sink(
                receiveCompletion: { _ in },
                receiveValue: { blocked in
                    self.recentBlocked = blocked
                }
            )
            .store(in: &cancellables)
    }
    
    private func fetchConfiguration() {
        api.fetchConfiguration()
            .receive(on: DispatchQueue.main)
            .sink(
                receiveCompletion: { _ in },
                receiveValue: { config in
                    self.configuration = config
                }
            )
            .store(in: &cancellables)
    }
    
    // MARK: - WebSocket
    
    private func connectWebSocket() {
        webSocketTask = api.connectWebSocket { [weak self] data in
            self?.handleWebSocketMessage(data)
        }
    }
    
    private func handleWebSocketMessage(_ data: Data) {
        // Parse WebSocket messages and update state accordingly
        // This would handle real-time updates from the service
    }
    
    // MARK: - Control Actions
    
    func pauseProtection(duration: String) {
        api.pauseProtection(duration: duration)
            .receive(on: DispatchQueue.main)
            .sink(
                receiveCompletion: { completion in
                    if case .failure(let error) = completion {
                        self.lastError = error.localizedDescription
                    }
                },
                receiveValue: { _ in
                    self.isPaused = true
                    // Refresh status
                    self.fetchStatus()
                }
            )
            .store(in: &cancellables)
    }
    
    func resumeProtection() {
        api.resumeProtection()
            .receive(on: DispatchQueue.main)
            .sink(
                receiveCompletion: { completion in
                    if case .failure(let error) = completion {
                        self.lastError = error.localizedDescription
                    }
                },
                receiveValue: { _ in
                    self.isPaused = false
                    // Refresh status
                    self.fetchStatus()
                }
            )
            .store(in: &cancellables)
    }
    
    func refreshRules() {
        api.refreshRules()
            .receive(on: DispatchQueue.main)
            .sink(
                receiveCompletion: { completion in
                    if case .failure(let error) = completion {
                        self.lastError = error.localizedDescription
                    }
                },
                receiveValue: { _ in
                    // Refresh statistics to show new rule count
                    self.fetchStatistics()
                }
            )
            .store(in: &cancellables)
    }
    
    func clearCache() {
        api.clearCache()
            .receive(on: DispatchQueue.main)
            .sink(
                receiveCompletion: { completion in
                    if case .failure(let error) = completion {
                        self.lastError = error.localizedDescription
                    }
                },
                receiveValue: { _ in
                    // Refresh statistics
                    self.fetchStatistics()
                }
            )
            .store(in: &cancellables)
    }
    
    // MARK: - Helpers
    
    func openLogs() {
        // Open Console.app filtered to DNShield logs
        let process = Process()
        process.launchPath = "/usr/bin/open"
        process.arguments = ["-a", "Console"]
        process.launch()
    }
    
    func quitApp() {
        guard configuration.allowQuit else { return }
        NSApplication.shared.terminate(nil)
    }
}