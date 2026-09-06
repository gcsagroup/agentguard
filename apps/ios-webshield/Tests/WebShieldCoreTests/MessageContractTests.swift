import XCTest
@testable import WebShieldCore

final class MessageContractTests: XCTestCase {
    func testRejectsNonDictionaryContainer() {
        XCTAssertThrowsError(try NativeMessageDecoder.decode("not a dictionary")) { error in
            XCTAssertEqual(error as? MessageValidationError, .notDictionary)
        }
    }

    func testDecodesVersionedStatusRequest() throws {
        let requestID = UUID()
        let request = try NativeMessageDecoder.decode([
            "version": 1,
            "requestId": requestID.uuidString,
            "type": "get_status"
        ])
        XCTAssertEqual(request, .status(requestID: requestID))
    }

    func testRejectsUnknownTopLevelField() {
        XCTAssertThrowsError(try NativeMessageDecoder.decode([
            "version": 1,
            "requestId": UUID().uuidString,
            "type": "get_status",
            "rawPageText": "must not cross the boundary"
        ])) { error in
            XCTAssertEqual(error as? MessageValidationError, .unknownField)
        }
    }

    func testDecodesAndMinimizesEventURL() throws {
        let requestID = UUID()
        let request = try NativeMessageDecoder.decode([
            "version": 1,
            "requestId": requestID.uuidString,
            "type": "record_events",
            "events": [[
                "ruleId": "CRIT-001",
                "kind": "payment",
                "action": "cancelled",
                "timestampMs": 1_700_000_000_000,
                "url": "https://user:secret@Example.COM:443/checkout?id=42#card"
            ]]
        ])
        guard case let .recordEvents(_, events) = request else {
            return XCTFail("Expected a record-events request")
        }
        XCTAssertEqual(events.single?.origin, "https://example.com")
    }

    func testRejectsUnsupportedEventValues() {
        XCTAssertThrowsError(try NativeMessageDecoder.decode([
            "version": 1,
            "requestId": UUID().uuidString,
            "type": "record_events",
            "events": [[
                "ruleId": "CRIT-001",
                "kind": "arbitrary_kind",
                "action": "cancelled",
                "timestampMs": 1_700_000_000_000,
                "url": "https://example.com/"
            ]]
        ]))
    }

    func testRejectsMoreThanFiftyEvents() {
        let event: [String: Any] = [
            "ruleId": "CRIT-001",
            "kind": "payment",
            "action": "cancelled",
            "timestampMs": 1_700_000_000_000,
            "url": "https://example.com/"
        ]
        XCTAssertThrowsError(try NativeMessageDecoder.decode([
            "version": 1,
            "requestId": UUID().uuidString,
            "type": "record_events",
            "events": Array(repeating: event, count: 51)
        ])) { error in
            XCTAssertEqual(error as? MessageValidationError, .tooManyEvents)
        }
    }
}

private extension Array {
    var single: Element? { count == 1 ? first : nil }
}
