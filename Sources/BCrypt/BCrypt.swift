//
//  BCrypt.swift
//  swift-bcrypt
//
//  Created by Kitti Bodecs on 2026. 01. 21..
//
// MARK: - BCrypt

import CBCrypt

/// A convenience accessor for hashing and verifying BCrypt hashes.
///
/// Use this global variable to create and verify BCrypt hashes without manually instantiating
/// ``BCrypt``.
///
/// ```swift
/// let hash = try BCrypt().hash("password", cost: 12)
/// let ok = try BCrypt().verify("password", created: hash)
/// ```
///

/// A BCrypt hasher/verifier.
///
/// ``BCrypt`` provides methods for creating BCrypt hashes and verifying plaintext values
/// against existing BCrypt hashes. It delegates the core cryptographic work to the underlying
/// C implementation (`CBCrypt`).
///
/// The hashed output includes:
/// - Algorithm revision (e.g. `$2b$`)
/// - Cost factor (log rounds)
/// - Salt (OpenBSD Radix-64 encoding)
/// - Checksum
///
/// Prefer using the global ``BCrypt`` convenience value rather than constructing this directly.
///
/// ```swift
/// let digest = BCrypt()
/// let hash = try digest.hash("password")
/// let ok = try digest.verify("password", created: hash)
/// ```
public final class BCrypt {
    /// Creates a new ``BCrypt`` instance.
    ///
    /// Prefer ``BCrypt`` unless you need explicit ownership or dependency injection.
    public init() {}

    /// Creates a new BCrypt hash using a randomly generated salt.
    ///
    /// The output string is self-contained: it includes algorithm revision, cost, salt, and checksum.
    ///
    /// - Parameters:
    ///   - plaintext: The plaintext value to hash (typically a password).
    ///   - cost: The BCrypt cost factor (log rounds). Higher values are more secure but slower.
    /// - Throws: ``BCryptError/invalidCost`` if `cost` is outside the allowed range,
    ///           or ``BCryptError/hashFailure`` if hashing fails.
    /// - Returns: A BCrypt hash string suitable for storage (e.g. in a database).
    public func hash(
        _ plaintext: String, 
        cost: Int = 12
    ) throws(BCryptError) -> String {
        guard cost >= BCRYPT_MINLOGROUNDS && cost <= 31 else {
            throw .invalidCost
        }
        return try self.hash(plaintext, salt: self.generateSalt(cost: cost))
    }

    /// Creates a new BCrypt hash using the provided salt.
    ///
    /// This is primarily useful for tests or when interoperating with systems that provide
    /// a fixed salt string.
    ///
    /// The `salt` parameter may be:
    /// - A full salt including revision and cost information (e.g. `$2b$12$...`)
    /// - A user-provided salt body (22 chars) without revision/cost
    ///
    /// - Parameters:
    ///   - plaintext: The plaintext value to hash.
    ///   - salt: The salt to use, either a full salt string or a 22-character salt body.
    /// - Throws: ``BCryptError/invalidSalt`` if the salt has an invalid format,
    ///           or ``BCryptError/hashFailure`` if hashing fails.
    /// - Returns: A BCrypt hash string.
    public func hash(_ plaintext: String, salt: String) throws(BCryptError)
        -> String
    {
        guard isSaltValid(salt) else {
            throw .invalidSalt
        }

        let originalAlgorithm: Algorithm
        if salt.count == Algorithm.saltCount {
            // user provided salt
            originalAlgorithm = .b
        }
        else {
            // full salt, not user provided
            let revisionString = String(salt.prefix(4))
            guard let parsedRevision = Algorithm(rawValue: revisionString)
            else {
                throw .invalidSalt
            }
            originalAlgorithm = parsedRevision
        }

        // OpenBSD doesn't support 2y revision.
        let normalizedSalt: String
        if originalAlgorithm == Algorithm.y {
            // Replace with 2b.
            normalizedSalt =
                Algorithm.b.rawValue
                + salt.dropFirst(originalAlgorithm.revisionCount)
        }
        else {
            normalizedSalt = salt
        }

        let hashedBytes = UnsafeMutablePointer<Int8>.allocate(capacity: 128)
        defer { hashedBytes.deallocate() }
        let hashingResult = bb_bcrypt_hashpass(
            plaintext,
            normalizedSalt,
            hashedBytes,
            128
        )

        guard hashingResult == 0 else {
            throw .hashFailure
        }
        return originalAlgorithm.rawValue
            + String(cString: hashedBytes)
            .dropFirst(originalAlgorithm.revisionCount)
    }

    /// Verifies that a plaintext value matches a previously created BCrypt hash.
    ///
    /// Verification works by parsing the algorithm revision and salt from the stored hash,
    /// hashing the supplied plaintext using the same parameters, and comparing checksums
    /// in a way that avoids early exit.
    ///
    /// ```swift
    /// let hash = try Bcrypt.hash("password", cost: 12)
    /// let ok = try Bcrypt.verify("password", created: hash)   // true
    /// let bad = try Bcrypt.verify("wrong", created: hash)     // false
    /// ```
    ///
    /// - Parameters:
    ///   - plaintext: The plaintext value to verify.
    ///   - hash: A BCrypt hash string previously produced by ``hash(_:cost:)`` or compatible implementations.
    /// - Throws: ``BcryptError/invalidHash`` if the provided hash is malformed,
    ///           or ``BcryptError/hashFailure`` if hashing fails during verification.
    /// - Returns: `true` if `plaintext` matches the hash; otherwise `false`.
    public func verify(
        _ plaintext: String, 
        created hash: String
    ) throws(BCryptError) -> Bool {
        guard let hashVersion = Algorithm(rawValue: String(hash.prefix(4)))
        else {
            throw .invalidHash
        }

        let hashSalt = String(hash.prefix(hashVersion.fullSaltCount))
        guard !hashSalt.isEmpty, hashSalt.count == hashVersion.fullSaltCount
        else {
            throw .invalidHash
        }

        let hashChecksum = String(hash.suffix(hashVersion.checksumCount))
        guard !hashChecksum.isEmpty,
            hashChecksum.count == hashVersion.checksumCount
        else {
            throw .invalidHash
        }

        let messageHash = try self.hash(plaintext, salt: hashSalt)
        let messageHashChecksum = String(
            messageHash.suffix(hashVersion.checksumCount)
        )
        return messageHashChecksum.secureCompare(to: hashChecksum)
    }

    // MARK: Private

    /// Generates a full BCrypt salt string including algorithm revision, cost, and encoded random salt.
    ///
    /// Format:
    /// - Revision: `$2b$` (or other revision)
    /// - Cost: two digits
    /// - Separator: `$`
    /// - Salt: 22 characters in OpenBSD Radix-64
    ///
    /// Example:
    /// `$2b$12$J/dtt5ybYUTCJ/dtt5ybYO`
    ///
    /// - Parameters:
    ///   - cost: The cost factor to encode into the salt string.
    ///   - algorithm: The BCrypt revision to use (defaults to `$2b$`).
    ///   - seed: Optional raw salt bytes. If `nil`, random bytes are generated. Must be 16 bytes when provided.
    /// - Returns: A full salt string suitable to pass to ``hash(_:salt:)``.
    private func generateSalt(
        cost: Int,
        algorithm: Algorithm = .b,
        seed: [UInt8]? = nil
    )
        -> String
    {
        let randomData: [UInt8]
        if let seed = seed {
            randomData = seed
        }
        else {
            randomData = [UInt8].random(count: 16)
        }
        let encodedSalt = base64Encode(randomData)

        return
            algorithm.rawValue + (cost < 10 ? "0\(cost)" : "\(cost)")
            // 0 padded
            + "$" + encodedSalt
    }

    /// Validates a salt string.
    ///
    /// A salt is considered valid if it is either:
    /// - A 22-character salt body (no revision/cost), or
    /// - A full salt string matching one of the supported algorithm revisions and the expected full length.
    ///
    /// - Parameter salt: The salt string to validate.
    /// - Returns: `true` if the salt is valid; otherwise `false`.
    private func isSaltValid(_ salt: String) -> Bool {
        // Includes revision and cost info (count should be 29)
        let revisionString = String(salt.prefix(4))
        guard let algorithm = Algorithm(rawValue: revisionString) else {
            // Does not include revision and cost info (count should be 22)
            return salt.count == Algorithm.saltCount
        }
        return salt.count == algorithm.fullSaltCount
    }

    /// Encodes bytes using OpenBSD's custom base-64 encoding (Radix-64) as used by BCrypt.
    ///
    /// BCrypt uses a non-standard base-64 alphabet and encoding rules; this function delegates
    /// to the underlying C implementation.
    ///
    /// - Parameter data: The raw bytes to encode (commonly 16 bytes for a salt).
    /// - Returns: A Radix-64 encoded string.
    ///
    /// - Important: This method currently asserts if the underlying C call fails.
    ///   Consider converting it to `throws(BcryptError)` and throwing
    ///   ``BcryptError/base64EncodingFailure`` instead of asserting.
    private func base64Encode(_ data: [UInt8]) -> String {
        let encodedBytes = UnsafeMutablePointer<Int8>.allocate(capacity: 25)
        defer { encodedBytes.deallocate() }
        let res = data.withUnsafeBytes { bytes in
            bb_encode_base64(
                encodedBytes,
                bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                bytes.count
            )
        }
        assert(res == 0, "base64 convert failed")
        return String(cString: encodedBytes)
    }

    /// Supported BCrypt algorithm revisions.
    ///
    /// BCrypt hashes are prefixed with a revision string that encodes the variant used.
    /// This implementation supports the most commonly encountered revisions and normalizes
    /// `$2y$` where required for compatibility.
    private enum Algorithm: String, RawRepresentable {
        /// Older revision used by some legacy implementations.
        case a = "$2a$"
        /// Revision used by `crypt_blowfish` (identical to `2b` in all but name).
        case y = "$2y$"
        /// Latest revision of the official BCrypt algorithm and the default used by this library.
        case b = "$2b$"

        /// The length of the revision string, including `$` symbols (always 4).
        var revisionCount: Int {
            4
        }

        /// The length of a full salt string including revision and cost (always 29).
        var fullSaltCount: Int {
            29
        }

        /// The length of the BCrypt checksum suffix (always 31).
        var checksumCount: Int {
            31
        }

        /// The length of the salt body without revision and cost (always 22).
        static var saltCount: Int {
            22
        }
    }
}
