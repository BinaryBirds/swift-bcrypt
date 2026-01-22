//
//  Extensions.swift
//  swift-bcrypt
//
//  Created by Kitti Bodecs on 2026. 01. 21..
//
import CBCrypt

extension FixedWidthInteger {
    /// Generates a random value in the full range of the integer type.
    ///
    /// This uses Swift's standard library random number generation.
    ///
    /// - Returns: A random value between `.min` and `.max` (inclusive).
    public static func random() -> Self {
        Self.random(in: .min ... .max)
    }

    /// Generates a random value in the full range of the integer type using a custom random number generator.
    ///
    /// - Parameter generator: The random number generator to use.
    /// - Returns: A random value between `.min` and `.max` (inclusive).
    public static func random<T>(using generator: inout T) -> Self
    where T: RandomNumberGenerator {
        Self.random(in: .min ... .max, using: &generator)
    }
}

extension Array where Element: FixedWidthInteger {
    /// Generates an array of random integers of the given count using the system random number generator.
    ///
    /// - Parameter count: The number of elements to generate.
    /// - Returns: An array containing `count` random elements.
    public static func random(count: Int) -> [Element] {
        var array: [Element] = .init(repeating: 0, count: count)
        for i in (0..<count) { array[i] = Element.random() }
        return array
    }

    /// Generates an array of random integers of the given count using a custom random number generator.
    ///
    /// - Parameters:
    ///   - count: The number of elements to generate.
    ///   - generator: The random number generator to use.
    /// - Returns: An array containing `count` random elements.
    public static func random<T>(count: Int, using generator: inout T)
        -> [Element]
    where T: RandomNumberGenerator {
        var array: [Element] = .init(repeating: 0, count: count)
        for i in (0..<count) { array[i] = Element.random(using: &generator) }
        return array
    }
}

// MARK: - Secure Comparison

extension Collection where Element: Equatable {
    /// Performs a full comparison of two collections without early exit.
    ///
    /// This method is intended for comparing security-sensitive values (such as hash digests)
    /// where early-exit comparisons may leak timing information.
    ///
    /// The function compares elements up to the length of the smaller collection, then finally
    /// checks the counts match.
    ///
    /// ```swift
    /// let a: Data = ...
    /// let b: Data = ...
    /// let equal = a.secureCompare(to: b)
    /// ```
    ///
    /// - Parameter other: The collection to compare against.
    /// - Returns: `true` if the collections have equal length and all elements match; otherwise `false`.
    public func secureCompare<C>(to other: C) -> Bool
    where C: Collection, C.Element == Element {
        let chk = self
        let sig = other

        // byte-by-byte comparison to avoid timing attacks
        var match = true
        for i in 0..<Swift.min(chk.count, sig.count)
        where chk[chk.index(chk.startIndex, offsetBy: i)]
            != sig[sig.index(sig.startIndex, offsetBy: i)]
        {
            match = false
        }

        // finally, if the counts match then we can accept the result
        guard chk.count == sig.count else {
            return false
        }
        return match
    }
}
