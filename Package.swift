// swift-tools-version: 5.9
//
//  Package.swift
//  StreamShield
//
//  SwiftPM manifest. Mirrors StreamShield.podspec so the library can be
//  consumed either via CocoaPods or via SwiftPM from the same sources.
//
//  NOTE: nuSDKService is a device-only (ios-arm64) binary framework, so the
//  iOS Simulator is not supported — the same limitation the podspec expresses
//  with EXCLUDED_ARCHS[sdk=iphonesimulator*] = arm64.
//

import PackageDescription

let package = Package(
    name: "StreamShield",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        .library(
            name: "StreamShield",
            targets: ["StreamShield"]
        )
    ],
    dependencies: [
        // Shared with NexilisLite so an app can depend on both without the
        // two colliding on a duplicate nuSDKService target.
        .package(url: "https://github.com/alqindiirsyam-es/nuSDKService.git", from: "5.0.2")
    ],
    targets: [
        .target(
            name: "StreamShield",
            dependencies: [
                .product(name: "nuSDKService", package: "nuSDKService")
            ],
            path: "StreamShield",
            // Umbrella header for the Xcode framework target; SwiftPM builds a
            // pure Swift module and does not need it.
            exclude: ["StreamShield.h"],
            sources: ["Source"]
        )
    ]
)
