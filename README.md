# Swift BCrypt

## Install

Add the repository as a dependency:

```swift
.package(url: "https://github.com/binarybirds/swift-bcrypt", from: "1.0.0"),
```

Add `Bcrypt` to the target dependencies:

```swift
.product(name: "Bcrypt", package: "swift-bcrypt"),
```

Update the packages and you are ready.

## Usage example

Basic example

```swift
import Bcrypt

let digest = try Bcrypt.hash("binary-birds", cost: 6)
let res = try Bcrypt.verify("binary-birds", created: digest)
```

## Credits

This code is derived from the Vapor web framework:

- [Vapor](https://github.com/vapor/vapor)
