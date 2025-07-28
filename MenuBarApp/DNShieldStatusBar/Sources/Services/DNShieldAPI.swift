import Foundation
import Combine

class DNShieldAPI {
    static let shared = DNShieldAPI()
    
    private let baseURL = "http://127.0.0.1:5353/api"
    private let session: URLSession
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder
    
    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 5
        config.timeoutIntervalForResource = 10
        self.session = URLSession(configuration: config)
        
        self.decoder = JSONDecoder()
        self.decoder.dateDecodingStrategy = .iso8601
        
        self.encoder = JSONEncoder()
        self.encoder.dateEncodingStrategy = .iso8601
    }
    
    // MARK: - Status & Statistics
    
    func fetchStatus() -> AnyPublisher<ServiceStatus, Error> {
        guard let url = URL(string: "\(baseURL)/status") else {
            return Fail(error: URLError(.badURL))
                .eraseToAnyPublisher()
        }
        
        return session.dataTaskPublisher(for: url)
            .map(\.data)
            .decode(type: ServiceStatus.self, decoder: decoder)
            .eraseToAnyPublisher()
    }
    
    func fetchStatistics() -> AnyPublisher<Statistics, Error> {
        guard let url = URL(string: "\(baseURL)/statistics") else {
            return Fail(error: URLError(.badURL))
                .eraseToAnyPublisher()
        }
        
        return session.dataTaskPublisher(for: url)
            .map(\.data)
            .decode(type: Statistics.self, decoder: decoder)
            .eraseToAnyPublisher()
    }
    
    func fetchRecentBlocked() -> AnyPublisher<[BlockedDomain], Error> {
        guard let url = URL(string: "\(baseURL)/recent-blocked") else {
            return Fail(error: URLError(.badURL))
                .eraseToAnyPublisher()
        }
        
        return session.dataTaskPublisher(for: url)
            .map(\.data)
            .decode(type: [BlockedDomain].self, decoder: decoder)
            .eraseToAnyPublisher()
    }
    
    func fetchConfiguration() -> AnyPublisher<Configuration, Error> {
        guard let url = URL(string: "\(baseURL)/config") else {
            return Fail(error: URLError(.badURL))
                .eraseToAnyPublisher()
        }
        
        return session.dataTaskPublisher(for: url)
            .map(\.data)
            .decode(type: Configuration.self, decoder: decoder)
            .eraseToAnyPublisher()
    }
    
    // MARK: - Control Actions
    
    func pauseProtection(duration: String) -> AnyPublisher<Void, Error> {
        guard let url = URL(string: "\(baseURL)/pause") else {
            return Fail(error: URLError(.badURL))
                .eraseToAnyPublisher()
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let pauseRequest = PauseRequest(duration: duration)
        do {
            request.httpBody = try encoder.encode(pauseRequest)
        } catch {
            return Fail(error: error)
                .eraseToAnyPublisher()
        }
        
        return session.dataTaskPublisher(for: request)
            .map { _ in () }
            .mapError { $0 as Error }
            .eraseToAnyPublisher()
    }
    
    func resumeProtection() -> AnyPublisher<Void, Error> {
        guard let url = URL(string: "\(baseURL)/resume") else {
            return Fail(error: URLError(.badURL))
                .eraseToAnyPublisher()
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        
        return session.dataTaskPublisher(for: request)
            .map { _ in () }
            .mapError { $0 as Error }
            .eraseToAnyPublisher()
    }
    
    func refreshRules() -> AnyPublisher<Void, Error> {
        guard let url = URL(string: "\(baseURL)/refresh-rules") else {
            return Fail(error: URLError(.badURL))
                .eraseToAnyPublisher()
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        
        return session.dataTaskPublisher(for: request)
            .map { _ in () }
            .mapError { $0 as Error }
            .eraseToAnyPublisher()
    }
    
    func clearCache() -> AnyPublisher<Void, Error> {
        guard let url = URL(string: "\(baseURL)/clear-cache") else {
            return Fail(error: URLError(.badURL))
                .eraseToAnyPublisher()
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        
        return session.dataTaskPublisher(for: request)
            .map { _ in () }
            .mapError { $0 as Error }
            .eraseToAnyPublisher()
    }
    
    // MARK: - WebSocket Connection
    
    func connectWebSocket(onMessage: @escaping (Data) -> Void) -> URLSessionWebSocketTask? {
        guard let url = URL(string: "ws://127.0.0.1:5353/api/ws") else {
            return nil
        }
        
        let task = session.webSocketTask(with: url)
        task.resume()
        
        // Start receiving messages
        receiveWebSocketMessage(task: task, onMessage: onMessage)
        
        return task
    }
    
    private func receiveWebSocketMessage(task: URLSessionWebSocketTask, onMessage: @escaping (Data) -> Void) {
        task.receive { result in
            switch result {
            case .success(let message):
                switch message {
                case .data(let data):
                    onMessage(data)
                case .string(let text):
                    if let data = text.data(using: .utf8) {
                        onMessage(data)
                    }
                @unknown default:
                    break
                }
                
                // Continue receiving messages
                self.receiveWebSocketMessage(task: task, onMessage: onMessage)
                
            case .failure(let error):
                print("WebSocket error: \(error)")
            }
        }
    }
}