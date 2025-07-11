import Foundation
import NetworkExtension

// Main entry point for the System Extension
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

// This will never return
dispatchMain()