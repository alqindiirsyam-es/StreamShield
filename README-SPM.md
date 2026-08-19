# StreamShield — Swift Package Manager

StreamShield ships through **both** CocoaPods (`StreamShield.podspec`) and
SwiftPM (`Package.swift`), built from the same source — `StreamShield/Source`.

## Consuming the package

```swift
.package(path: "../NexilisLibraryiOS/StreamShield")   // local
.package(url: "https://github.com/alqindiirsyam-es/StreamShield.git", from: "1.0.0")
```

```swift
.target(name: "YourApp", dependencies: [
    .product(name: "StreamShield", package: "StreamShield")
])
```

In Xcode: **File → Add Package Dependencies… → Add Local…** and pick the
`StreamShield` folder (the one containing `Package.swift`).

## ⚠️ Device-only — the Simulator is not supported

`nuSDKService`, the only dependency, is an **arm64 device-only** binary with no
simulator slice, so builds must target real hardware
(`-destination 'generic/platform=iOS'`). Same limitation the podspec expresses
via `EXCLUDED_ARCHS[sdk=iphonesimulator*]`.

## Layout

```
StreamShield/
├── Package.swift              SPM manifest
├── StreamShield.podspec       CocoaPods spec (unchanged)
└── StreamShield/
    ├── Source/                SecurityShield.swift — shared by both
    └── StreamShield.h         umbrella header, Xcode framework target only
```

Only `nuSDKService` is needed, and it comes from the shared package at
`../nuSDKService` rather than a binary target of its own — see that package's
`README.md` for why that matters.

### No resources

Unlike NexilisLite, StreamShield has no resource bundle. The podspec declares

```ruby
spec.resource_bundles = { 'StreamShield' => ['StreamShield/Resource/**/*'] }
```

but no `Resource/` directory exists, so that line matches nothing and the
manifest deliberately mirrors it by declaring no resources. The source only ever
reads `Bundle.main` (the host app's Info.plist and bundle identifier), which
behaves identically under both build systems — so no `Bundle.module` handling
is required here.

## Publishing

This package is published at
**https://github.com/alqindiirsyam-es/StreamShield** and already depends on the
published `nuSDKService` by URL. To cut a new release:

```bash
cd /path/to/NexilisLibraryiOS
git subtree split --prefix=StreamShield -b spm-streamshield
git push https://github.com/alqindiirsyam-es/StreamShield.git spm-streamshield:main

git clone https://github.com/alqindiirsyam-es/StreamShield.git /tmp/StreamShield
cd /tmp/StreamShield && git tag 1.0.0 && git push origin 1.0.0
```

Keep the tag in step with `spec.version` in the podspec.
