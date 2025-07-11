import NetworkExtension
import Foundation
import os.log

/// DNShield DNS Proxy Provider - Filters DNS queries at the network level
class DNSProxyProvider: NEDNSProxyProvider {
    
    // Logging
    private let logger = Logger(subsystem: "com.dnshield.network-extension", category: "DNSProxy")
    
    // Domain filtering
    private var blockedDomains: Set<String> = []
    private var domainTrie: DomainTrie = DomainTrie()
    
    // Statistics
    private var blockedCount: Int = 0
    private var allowedCount: Int = 0
    
    override init() {
        super.init()
        logger.info("DNShield DNS Proxy Provider initialized")
    }
    
    override func startProxy(options: [String : Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        logger.info("Starting DNShield DNS Proxy...")
        
        // Load blocked domains from provider configuration
        if let config = self.providerConfiguration as? [String: Any],
           let domains = config["blockedDomains"] as? [String] {
            loadBlockedDomains(domains)
            logger.info("Loaded \(domains.count) blocked domains")
        } else {
            logger.warning("No blocked domains found in configuration")
        }
        
        // Configure system DNS settings
        let dnsSettings = NEDNSSettings(servers: ["127.0.0.1"])
        dnsSettings.matchDomains = [""] // Match all domains
        dnsSettings.matchDomainsNoSearch = true
        
        self.systemDNSSettings = dnsSettings
        
        completionHandler(nil)
        logger.info("DNShield DNS Proxy started successfully")
    }
    
    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("Stopping DNShield DNS Proxy (reason: \(String(describing: reason)))")
        logger.info("Statistics - Blocked: \(blockedCount), Allowed: \(allowedCount)")
        
        completionHandler()
    }
    
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let udpFlow = flow as? NEAppProxyUDPFlow else {
            // We only handle UDP flows for DNS
            return false
        }
        
        // Handle DNS queries
        handleDNSFlow(udpFlow)
        return true
    }
    
    private func handleDNSFlow(_ flow: NEAppProxyUDPFlow) {
        flow.open { [weak self] error in
            guard error == nil else {
                self?.logger.error("Failed to open UDP flow: \(error!.localizedDescription)")
                return
            }
            
            self?.readDNSQueries(from: flow)
        }
    }
    
    private func readDNSQueries(from flow: NEAppProxyUDPFlow) {
        flow.readDatagrams { [weak self] datagrams, endpoints, error in
            guard let self = self,
                  let datagrams = datagrams,
                  let endpoints = endpoints,
                  error == nil else {
                self?.logger.error("Failed to read datagrams: \(error?.localizedDescription ?? "unknown error")")
                return
            }
            
            // Process each DNS query
            for (index, datagram) in datagrams.enumerated() {
                if let endpoint = endpoints[index] as? NWEndpoint {
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
            logger.info("BLOCKED: \(domain)")
            blockedCount += 1
            
            // Send blocked response
            let blockedResponse = createBlockedResponse(for: query, domain: domain)
            flow.writeDatagrams([blockedResponse], sentBy: [endpoint]) { error in
                if let error = error {
                    self.logger.error("Failed to send blocked response: \(error.localizedDescription)")
                }
            }
        } else {
            logger.debug("ALLOWED: \(domain)")
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
        // Forward to upstream DNS servers (CloudFlare)
        let upstreamEndpoint = NWHostEndpoint(hostname: "1.1.1.1", port: "53")
        
        let connection = flow.createNewConnection(to: upstreamEndpoint, parameters: .udp)
        
        connection.start { error in
            if let error = error {
                self.logger.error("Failed to connect to upstream DNS: \(error.localizedDescription)")
                return
            }
            
            // Send query to upstream
            connection.send(datagram) { sendError in
                if let sendError = sendError {
                    self.logger.error("Failed to send query to upstream: \(sendError.localizedDescription)")
                    return
                }
                
                // Read response
                connection.receiveData { responseData, receiveError in
                    if let responseData = responseData {
                        // Forward response back to client
                        flow.writeDatagrams([responseData], sentBy: [endpoint]) { writeError in
                            if let writeError = writeError {
                                self.logger.error("Failed to forward response: \(writeError.localizedDescription)")
                            }
                        }
                    }
                }
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
        logger.info("Loading \(domains.count) domains into filter...")
        
        blockedDomains = Set(domains.map { $0.lowercased() })
        
        // Build trie for efficient lookups
        domainTrie = DomainTrie()
        for domain in blockedDomains {
            domainTrie.insert(domain: domain)
        }
        
        logger.info("Domain filter ready with \(blockedDomains.count) entries")
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