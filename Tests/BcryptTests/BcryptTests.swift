//
//  BcryptTests.swift
//  swift-bcrypt
//
//  Created by Kitti Bodecs on 2026. 01. 21..
//

import Bcrypt
import Testing

@testable import Bcrypt

@Suite
struct BcryptTests {

    struct ConstantRNG: RandomNumberGenerator {
        var value: UInt64
        mutating func next() -> UInt64 { value }
    }

    @Test
    func verify() throws {
        for (desired, message) in tests {
            let result = try BCrypt().verify(message, created: desired)
            #expect(result, "\(message): did not match \(desired)")
        }
    }

    @Test
    func fail() throws {
        let digest = try BCrypt().hash("foo", cost: 6)
        let res = try BCrypt().verify("bar", created: digest)
        #expect(res == false)
    }

    @Test
    func invalidMinCost() throws {
        #expect(throws: BcryptError.invalidCost) {
            try BCrypt().hash("foo", cost: 1)
        }
    }
    @Test
    func invalidMaxCost() throws {
        #expect(throws: BcryptError.invalidCost) {
            try BCrypt().hash("foo", cost: 32)
        }
    }

    @Test
    func invalidSalt() throws {
        #expect(throws: BcryptError.invalidHash) {
            try BCrypt().verify("", created: "foo")
        }
    }

    @Test
    func randomArrayHasCorrectCount() {
        let count = 32
        let array: [UInt8] = .random(count: count)

        #expect(array.count == count)
    }

    @Test
    func randomArrayIsNotAllZeros() {
        let array: [UInt8] = .random(count: 32)

        // Very weak sanity check: extremely unlikely to be all zeros
        let allZero = array.allSatisfy { $0 == 0 }
        #expect(!allZero)
    }

    @Test
    func randomArrayAllowsZeroCount() {
        let array: [UInt8] = .random(count: 0)

        #expect(array.isEmpty)
    }

    @Test
    func fixedWidthIntegerRandomUsingGeneratorIsDeterministic() {
        var rng = ConstantRNG(value: 0x0123_4567_89AB_CDEF)

        let a: UInt64 = .random(using: &rng)
        let b: UInt64 = .random(using: &rng)

        // Since our RNG always returns the same value, random(using:) should too.
        #expect(a == 0x0123_4567_89AB_CDEF)
        #expect(b == 0x0123_4567_89AB_CDEF)
    }

    @Test
    func randomArrayUsingGeneratorIsDeterministic() {
        var rng = ConstantRNG(value: 42)

        let array: [UInt64] = .random(count: 3, using: &rng)

        #expect(array == [42, 42, 42])
    }

    @Test
    func secureCompareEqualCollections() {
        let a = [1, 2, 3]
        let b = [1, 2, 3]

        #expect(a.secureCompare(to: b))
    }

    @Test
    func hashWithInvalidSaltThrows() {
        #expect(throws: BcryptError.invalidSalt) {
            _ = try BCrypt().hash("password", salt: "nope")
        }
    }

    @Test
    func hashWithFullSaltProducesExpectedHash() throws {
        let desired = tests[0].0
        let message = tests[0].1

        let fullSalt = String(desired.prefix(29))  // "$2b$06$<22 salt chars>"
        #expect(fullSalt.count == 29)

        let hash = try BCrypt().hash(message, salt: fullSalt)
        #expect(hash == desired)
    }

    @Test
    func hashWithFullSaltMatchesFixture() throws {
        let desired = tests[0].0
        let message = tests[0].1

        let fullSalt = String(desired.prefix(29))  // "$2b$06$<22 chars>"
        #expect(fullSalt.count == 29)

        let hash = try BCrypt().hash(message, salt: fullSalt)
        #expect(hash == desired)
    }

    @Test
    func hashWithFullSalt2yPreserves2yPrefix() throws {
        let fullSalt = "$2y$06$......................"
        #expect(fullSalt.count == 29)

        let hash = try BCrypt().hash("password", salt: fullSalt)

        // Internally normalized to 2b for hashing, but your code prefixes output with originalAlgorithm (2y)
        #expect(hash.hasPrefix("$2y$"))
    }

    @Test
    func hashWithFullSaltUnknownRevisionThrows() {
        let fullSalt = "$2x$06$......................"
        // 29 chars but invalid revision
        #expect(fullSalt.count == 29)

        #expect(throws: BcryptError.invalidSalt) {
            _ = try BCrypt().hash("password", salt: fullSalt)
        }
    }
}

let tests: [(String, String)] = [
    (
        "$2b$06$xETUbh.9MrhmYsSTXqg5tOJ/Az0WZuVfpYqvcDhYsuqBt3N1qQ7Bm",
        "binary-birds"
    )
]
