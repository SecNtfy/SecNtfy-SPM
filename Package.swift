// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SecNtfy",
    platforms: [.iOS(.v15), .macOS(.v13), .watchOS(.v9)],
    products: [
        .library(name: "SecNtfy", targets: ["SecNtfy"]),
    ],
    dependencies: [
        .package(url: "https://github.com/SwiftyBeaver/SwiftyBeaver.git", .upToNextMajor(from: "2.0.0")),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.10.0"),
    ],
    targets: [
        .target(
            name: "SecNtfy",
            dependencies: [
                .product(name: "CryptoSwift", package: "CryptoSwift"),
                .product(name: "SwiftyBeaver", package: "SwiftyBeaver"),
            ]
        ),
        .testTarget(
            name: "SecNtfyTests",
            dependencies: ["SecNtfy"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
