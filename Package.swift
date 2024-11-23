// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SecNtfy",
    platforms: [.iOS(.v15), .macOS(.v13), .watchOS(.v9)],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SecNtfy",
            targets: ["SecNtfy"]),
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.3"),
        .package(url: "https://github.com/SwiftyBeaver/SwiftyBeaver.git", .upToNextMajor(from: "2.0.0")),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SecNtfy",
            dependencies: ["CryptoSwift", "SwiftyBeaver"],
            swiftSettings: [
                /// Xcode 15. Remove `=targeted` to use the default `complete`.
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        .testTarget(
            name: "SecNtfyTests",
            dependencies: ["SecNtfy"]),
    ],
    swiftLanguageVersions: [.version("6")]
)
