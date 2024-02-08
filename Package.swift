// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "bcrypt",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "Bcrypt", targets: ["Bcrypt"]),
    ],
    dependencies: [
    ],
    targets: [
        .target(name: "CBcrypt"),
        .target(name: "Bcrypt", dependencies: [
            .target(name: "CBcrypt"),
        ]),
        .testTarget(
            name: "BcryptTests",
            dependencies: [
                .target(name: "Bcrypt"),
            ]
        ),
    ]
)
