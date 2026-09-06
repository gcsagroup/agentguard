import XCTest
@testable import WebShieldCore

final class URLMinimizerTests: XCTestCase {
    func testKeepsOnlyHTTPSOrigin() {
        XCTAssertEqual(
            URLMinimizer.origin(from: "https://Example.com/account/profile?token=secret#private"),
            "https://example.com"
        )
    }

    func testKeepsNonDefaultPort() {
        XCTAssertEqual(
            URLMinimizer.origin(from: "http://example.com:8080/private"),
            "http://example.com:8080"
        )
    }

    func testRejectsNonWebSchemes() {
        XCTAssertNil(URLMinimizer.origin(from: "file:///private/secret"))
        XCTAssertNil(URLMinimizer.origin(from: "javascript:alert(1)"))
    }
}
