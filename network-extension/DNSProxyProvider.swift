import NetworkExtension
import Foundation
import os

/// DNShield DNS Proxy Provider - Filters DNS queries at the network level
@objc(DNSProxyProvider)
class DNSProxyProvider: NEDNSProxyProvider {
    
    // Logging
    private let log = OSLog(subsystem: "com.dnshield.network-extension", category: "DNSProxy")
    
    // Domain filtering
    private var blockedDomains: Set<String> = []
    private var domainTrie: DomainTrie = DomainTrie()
    
    // Statistics
    private var blockedCount: Int = 0
    private var allowedCount: Int = 0
    
    override init() {
        super.init()
        os_log(.info, log: log, "DNShield DNS Proxy Provider initialized")
    }
    
    override func startProxy(options: [String : Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        os_log(.info, log: log, "Starting DNShield DNS Proxy...")
        
        // Load blocked domains from provider configuration
        // Note: providerConfiguration is not available in NEDNSProxyProvider
        // We'll need to load domains from a different source or hardcode for testing
        let testDomains = ["doubleclick.net", "googleadservices.com", "googlesyndication.com"]
        loadBlockedDomains(testDomains)
        os_log(.info, log: log, "Loaded %d blocked domains", testDomains.count)
        
        // DNS settings are configured through the NEDNSProxyProviderProtocol
        // not directly in the provider
        
        completionHandler(nil)
        os_log(.info, log: log, "DNShield DNS Proxy started successfully")
    }
    
    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log(.info, log: log, "Stopping DNShield DNS Proxy (reason: %d)", reason.rawValue)
        os_log(.info, log: log, "Statistics - Blocked: %d, Allowed: %d", blockedCount, allowedCount)
        
        completionHandler()
    }
    
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // NEDNSProxyProvider handles flows differently
        // We need to use handleNewUDPFlow instead
        return false
    }
    
    override func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow, initialRemoteEndpoint remoteEndpoint: NWEndpoint) -> Bool {
        // Handle DNS queries on UDP port 53
        handleDNSFlow(flow)
        return true
    }
    
    private func handleDNSFlow(_ flow: NEAppProxyUDPFlow) {
        // For DNS proxy, we don't need to open the flow to a specific endpoint
        // Just start reading queries
        readDNSQueries(from: flow)
    }
    
    private func readDNSQueries(from flow: NEAppProxyUDPFlow) {
        flow.readDatagrams { [weak self] datagrams, endpoints, error in
            guard let self = self,
                  let datagrams = datagrams,
                  let endpoints = endpoints,
                  error == nil else {
                os_log(.error, log: self?.log ?? OSLog.default, "Failed to read datagrams: %{public}@", error?.localizedDescription ?? "unknown error")
                return
            }
            
            // Process each DNS query
            for (index, datagram) in datagrams.enumerated() {
                if index < endpoints.count {
                    let endpoint = endpoints[index]
                    self.processDNSQuery(datagram: datagram, endpoint: endpoint, flow: flow)
                }
            }
            
            // Continue reading
            self.readDNSQueries(from: flow)
        }
    }
    
    private func processDNSQuery(datagram: Data, endpoint: NWEndpoint, flow: NEAppProxyUDPFlow) {
        // Parse DNS query
        guard let query = DNSMessage(data: datagram),
              let domain = query.questionDomain else {
            // Forward malformed queries
            forwardQuery(datagram: datagram, endpoint: endpoint, flow: flow)
            return
        }
        
        let domainLower = domain.lowercased()
        
        // Check if domain should be blocked
        if shouldBlockDomain(domainLower) {
            os_log(.info, log: log, "BLOCKED: %{public}@", domain)
            blockedCount += 1
            
            // Send blocked response
            let blockedResponse = createBlockedResponse(for: query, domain: domain)
            flow.writeDatagrams([blockedResponse], sentBy: [endpoint]) { error in
                if let error = error {
                    os_log(.error, log: self.log, "Failed to send blocked response: %{public}@", error.localizedDescription)
                }
            }
        } else {
            os_log(.debug, log: log, "ALLOWED: %{public}@", domain)
            allowedCount += 1
            
            // Forward to upstream DNS
            forwardQuery(datagram: datagram, endpoint: endpoint, flow: flow)
        }
    }
    
    private func shouldBlockDomain(_ domain: String) -> Bool {
        // Use trie for efficient lookup
        return domainTrie.isBlocked(domain: domain)
    }
    
    private func forwardQuery(datagram: Data, endpoint: NWEndpoint, flow: NEAppProxyUDPFlow) {
        // For NEDNSProxyProvider, we need to handle DNS queries differently
        // Since we're blocking certain domains, we'll just forward allowed queries
        
        // Create a simple DNS response that indicates the query should be handled by system DNS
        // In a real implementation, we would forward to upstream DNS servers
        // For now, we'll return SERVFAIL to indicate the query couldn't be processed
        
        guard let query = DNSMessage(data: datagram),
              let _ = query.questionDomain else {
            return
        }
        
        // Create a SERVFAIL response
        var response = datagram
        if response.count > 3 {
            response[2] = 0x81  // QR=1, OPCODE=0, AA=0, TC=0, RD=1
            response[3] = 0x82  // RA=1, Z=0, RCODE=2 (SERVFAIL)
        }
        
        // Send response back to client
        flow.writeDatagrams([response], sentBy: [endpoint]) { error in
            if let error = error {
                os_log(.error, log: self.log, "Failed to send SERVFAIL response: %{public}@", error.localizedDescription)
            }
        }
    }
    
    private func createBlockedResponse(for query: DNSMessage, domain: String) -> Data {
        var response = query.data
        
        // Set response flags
        if response.count > 3 {
            response[2] = 0x81  // QR=1, OPCODE=0, AA=0, TC=0, RD=1
            response[3] = 0x80  // RA=1, Z=0, RCODE=0 (NOERROR)
        }
        
        // Set answer count to 1
        if response.count > 7 {
            response[6] = 0x00
            response[7] = 0x01
        }
        
        // Add A record answer pointing to 127.0.0.1
        // This allows the HTTPS proxy to show block page
        let answer = createARecord(for: domain)
        response.append(answer)
        
        return response
    }
    
    private func createARecord(for domain: String) -> Data {
        var record = Data()
        
        // Domain name (compressed pointer to question)
        record.append(contentsOf: [0xC0, 0x0C])
        
        // Type A (1)
        record.append(contentsOf: [0x00, 0x01])
        
        // Class IN (1)
        record.append(contentsOf: [0x00, 0x01])
        
        // TTL (10 seconds)
        record.append(contentsOf: [0x00, 0x00, 0x00, 0x0A])
        
        // Data length (4 bytes for IPv4)
        record.append(contentsOf: [0x00, 0x04])
        
        // IP address (127.0.0.1)
        record.append(contentsOf: [0x7F, 0x00, 0x00, 0x01])
        
        return record
    }
    
    private func loadBlockedDomains(_ domains: [String]) {
        os_log(.info, log: log, "Loading %d domains into filter...", domains.count)
        
        blockedDomains = Set(domains.map { $0.lowercased() })
        
        // Build trie for efficient lookups
        domainTrie = DomainTrie()
        for domain in blockedDomains {
            domainTrie.insert(domain: domain)
        }
        
        os_log(.info, log: log, "Domain filter ready with %d entries", blockedDomains.count)
    }
}

// MARK: - DNS Message Parsing

struct DNSMessage {
    let data: Data
    let questionDomain: String?
    
    init?(data: Data) {
        guard data.count >= 12 else { return nil }
        
        self.data = data
        
        // Parse question section
        var offset = 12
        var domain = ""
        
        while offset < data.count {
            let length = Int(data[offset])
            offset += 1
            
            if length == 0 {
                break
            }
            
            if length > 63 || offset + length > data.count {
                return nil
            }
            
            if !domain.isEmpty {
                domain += "."
            }
            
            let labelData = data[offset..<(offset + length)]
            if let label = String(data: labelData, encoding: .utf8) {
                domain += label
            }
            
            offset += length
        }
        
        self.questionDomain = domain.isEmpty ? nil : domain
    }
}

// MARK: - Domain Trie

class DomainTrie {
    private class TrieNode {
        var children: [String: TrieNode] = [:]
        var isEnd = false
        var isBlocked = false
    }
    
    private let root = TrieNode()
    private let queue = DispatchQueue(label: "com.dnshield.trie", attributes: .concurrent)
    
    func insert(domain: String) {
        queue.async(flags: .barrier) {
            let parts = domain.split(separator: ".").map(String.init).reversed()
            var current = self.root
            
            for part in parts {
                if current.children[part] == nil {
                    current.children[part] = TrieNode()
                }
                current = current.children[part]!
            }
            current.isEnd = true
            current.isBlocked = true
        }
    }
    
    func isBlocked(domain: String) -> Bool {
        return queue.sync {
            let parts = domain.split(separator: ".").map(String.init).reversed()
            var current = root
            
            for part in parts {
                guard let next = current.children[part] else {
                    return false
                }
                current = next
                // If we find a blocked parent domain, block this subdomain too
                if current.isEnd && current.isBlocked {
                    return true
                }
            }
            return false
        }
    }
}