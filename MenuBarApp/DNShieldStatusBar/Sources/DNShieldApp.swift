import SwiftUI
import AppKit

@main
struct DNShieldApp: App {
    @StateObject private var appState = AppState()
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    
    var body: some Scene {
        Settings {
            EmptyView()
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var popover: NSPopover!
    var appState: AppState!
    var eventMonitor: EventMonitor?
    
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Create the status bar item
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "shield.fill", accessibilityDescription: "DNShield")
            button.action = #selector(togglePopover)
            button.target = self
        }
        
        // Create the app state
        appState = AppState()
        
        // Create the popover
        popover = NSPopover()
        popover.contentSize = NSSize(width: 320, height: 480)
        popover.behavior = .transient
        popover.contentViewController = NSHostingController(rootView: ContentView().environmentObject(appState))
        
        // Create event monitor to close popover when clicking outside
        eventMonitor = EventMonitor(mask: [.leftMouseDown, .rightMouseDown]) { [weak self] event in
            if let strongSelf = self, strongSelf.popover.isShown {
                strongSelf.closePopover(nil)
            }
        }
        
        // Start monitoring the service
        appState.startMonitoring()
        
        // Update status icon based on protection status
        appState.$status
            .receive(on: DispatchQueue.main)
            .sink { [weak self] status in
                self?.updateStatusIcon(status: status)
            }
            .store(in: &appState.cancellables)
    }
    
    @objc func togglePopover(_ sender: AnyObject?) {
        if popover.isShown {
            closePopover(sender)
        } else {
            showPopover(sender)
        }
    }
    
    func showPopover(_ sender: AnyObject?) {
        if let button = statusItem.button {
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: NSRectEdge.minY)
            eventMonitor?.start()
        }
    }
    
    func closePopover(_ sender: AnyObject?) {
        popover.performClose(sender)
        eventMonitor?.stop()
    }
    
    func updateStatusIcon(status: ServiceStatus) {
        guard let button = statusItem.button else { return }
        
        let symbolName: String
        let color: NSColor
        
        switch status.protectionLevel {
        case .protected:
            symbolName = "shield.fill"
            color = .systemGreen
        case .partial:
            symbolName = "shield.fill"
            color = .systemYellow
        case .notProtected:
            symbolName = "exclamationmark.shield.fill"
            color = .systemRed
        case .offline:
            symbolName = "shield.slash.fill"
            color = .systemGray
        }
        
        if let image = NSImage(systemSymbolName: symbolName, accessibilityDescription: "DNShield") {
            image.isTemplate = true
            button.image = image
            button.contentTintColor = color
        }
    }
}

// Event monitor for detecting clicks outside the popover
class EventMonitor {
    private var monitor: Any?
    private let mask: NSEvent.EventTypeMask
    private let handler: (NSEvent?) -> Void
    
    init(mask: NSEvent.EventTypeMask, handler: @escaping (NSEvent?) -> Void) {
        self.mask = mask
        self.handler = handler
    }
    
    deinit {
        stop()
    }
    
    func start() {
        monitor = NSEvent.addGlobalMonitorForEvents(matching: mask, handler: handler)
    }
    
    func stop() {
        if monitor != nil {
            NSEvent.removeMonitor(monitor!)
            monitor = nil
        }
    }
}