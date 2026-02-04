# Swift BCrypt

Swift BCrypt implementation for securely hashing and verifying passwords using
adaptive cost factors, random salts, and constant-time comparison.

[![Release: 2.0.1](https://img.shields.io/badge/Release-2.0.1-F05138)]( https://github.com/binarybirds/swift-bcrypt/releases/tag/2.0.1)

## Requirements

![Swift 6.1+](https://img.shields.io/badge/Swift-6%2E1%2B-F05138)
![Platforms: macOS, iOS, tvOS, watchOS, visionOS](https://img.shields.io/badge/Platforms-macOS_%7C_iOS_%7C_tvOS_%7C_watchOS_%7C_visionOS-F05138)

- Swift 6.1+
- Platforms:
  - macOS 15+
  - iOS 18+
  - tvOS 18+
  - watchOS 11+
  - visionOS 2+

## Installation

Use Swift Package Manager; add the dependency to your `Package.swift` file:

```swift
.package(url: "https://github.com/binarybirds/swift-bcrypt", exact: "2.0.1"),
```

Then add `Bcrypt` to your target dependencies:

```swift
.product(name: "Bcrypt", package: "swift-bcrypt"),
```

Update the packages and you are ready.

## Usage

[![DocC API documentation](https://img.shields.io/badge/DocC-API_documentation-F05138)](https://binarybirds.github.io/swift-bcrypt)

API documentation is available at the following link. Refer to the mock objects in the Tests directory if you want to build a custom database driver implementation.

## Usage example

```swift
import Bcrypt

let digest = try Bcrypt.hash("binary-birds", cost: 6)
let res = try Bcrypt.verify("binary-birds", created: digest)
```

## Development

- Build: `swift build`
- Test:
  - local: `swift test`
  - using Docker: `make docker-test`
- Format: `make format`
- Check: `make check`

## Contributing

[Pull requests](https://github.com/binarybirds/swift-bcrypt/pulls) are welcome. Please keep changes focused and include tests for new logic.

## Credits

This code is derived from the Vapor web framework:

- [Vapor](https://github.com/vapor/vapor)
