import Bcrypt
import XCTest

final class BcryptTests: XCTestCase {
    func testVerify() throws {
        for (desired, message) in tests {
            let result = try Bcrypt.verify(message, created: desired)
            XCTAssert(result, "\(message): did not match \(desired)")
        }
    }

    func testFail() throws {
        let digest = try Bcrypt.hash("foo", cost: 6)
        let res = try Bcrypt.verify("bar", created: digest)
        XCTAssertEqual(res, false)
    }

    func testInvalidMinCost() throws {
        XCTAssertThrowsError(try Bcrypt.hash("foo", cost: 1))
    }

    func testInvalidMaxCost() throws {
        XCTAssertThrowsError(try Bcrypt.hash("foo", cost: 32))
    }

    func testInvalidSalt() throws {
        XCTAssertThrowsError(try Bcrypt.verify("", created: "foo")) {
            XCTAssert($0 is BcryptError)
        }
    }
}

let tests: [(String, String)] = [
    (
        "$2b$06$xETUbh.9MrhmYsSTXqg5tOJ/Az0WZuVfpYqvcDhYsuqBt3N1qQ7Bm",
        "binary-birds"
    )
]
