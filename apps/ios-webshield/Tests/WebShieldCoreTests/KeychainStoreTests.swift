import XCTest
@testable import WebShieldCore

final class KeychainStoreTests: XCTestCase {
    func testSetUpdateReadAndDeleteOrReportsUnsignedEntitlementBoundary() throws {
        let store = KeychainStore(service: "WebShieldKeychainTests.\(UUID().uuidString)")
        let account = UUID().uuidString
        defer { try? store.delete(account: account) }

        do {
            try store.set(Data("first".utf8), for: account)
        } catch let error as KeychainStoreError {
            XCTAssertEqual(error, .unexpectedStatus(errSecMissingEntitlement))
            return
        }
        XCTAssertEqual(try store.data(for: account), Data("first".utf8))
        try store.set(Data("second".utf8), for: account)
        XCTAssertEqual(try store.data(for: account), Data("second".utf8))
        try store.delete(account: account)
        XCTAssertNil(try store.data(for: account))
    }
}
