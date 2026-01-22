//
//  Errors.swift
//  swift-bcrypt
//
//  Created by Kitti Bodecs on 2026. 01. 21..
//
import CBCrypt

// MARK: - Errors

/// Errors thrown by ``BCrypt`` operations.
///
/// These errors cover invalid input formatting (cost, salt, hash) and failures returned by the
/// underlying C implementation.
public enum BCryptError: Swift.Error, CustomStringConvertible {
    /// The supplied cost factor is outside the allowed range.
    case invalidCost

    /// The supplied salt is malformed or has an unexpected length/revision.
    case invalidSalt

    /// The underlying hashing function failed.
    case hashFailure

    /// The supplied hash string is malformed (unknown version, missing salt, missing checksum, etc.).
    case invalidHash

    /// The underlying Radix-64 encoding routine failed.
    case base64EncodingFailure

    /// A human-readable description of the error.
    public var errorDescription: String? { self.description }

    /// A formatted description suitable for logging.
    public var description: String { "Bcrypt error: \(self.reason)" }

    /// A short reason string describing the failure.
    var reason: String {
        switch self {
        case .invalidCost:
            return "Cost should be between 4 and 31"
        case .invalidSalt:
            return "Provided salt has incorrect format"
        case .hashFailure:
            return "Unable to compute hash"
        case .invalidHash:
            return "Invalid hash formatting"
        case .base64EncodingFailure:
            return "Unable to base64-encode salt"
        }
    }
}
