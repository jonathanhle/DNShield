// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "DNShieldStatusBar",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(
            name: "DNShieldStatusBar",
            targets: ["DNShieldStatusBar"]
        )
    ],
    dependencies: [],
    targets: [
        .executableTarget(
            name: "DNShieldStatusBar",
            dependencies: [],
            path: "Sources"
        )
    ]
)