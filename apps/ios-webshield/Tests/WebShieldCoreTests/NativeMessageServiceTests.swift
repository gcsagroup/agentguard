import XCTest
@testable import WebShieldCore

final class NativeMessageServiceTests: XCTestCase {
    func testDisabledServiceRejectsAuditWrite() async throws {
        let fixture = try ServiceFixture()
        defer { fixture.cleanup() }
        let response = await fixture.service.handle(fixture.recordMessage(), profileID: nil)

        XCTAssertEqual(response["ok"] as? Bool, false)
        XCTAssertEqual(response["error"] as? String, "protection_disabled")
        let records = try await fixture.auditStore.load(now: fixture.now)
        XCTAssertTrue(records.isEmpty)
    }

    func testEnabledServiceWritesMinimizedAuditRecord() async throws {
        let fixture = try ServiceFixture()
        defer { fixture.cleanup() }
        fixture.settings.setPrivacyAccepted(true)
        fixture.settings.setEnabled(true)

        let missingProfile = await fixture.service.handle(fixture.recordMessage(), profileID: nil)
        XCTAssertEqual(missingProfile["ok"] as? Bool, false)
        XCTAssertEqual(missingProfile["error"] as? String, "profile_unavailable")

        let response = await fixture.service.handle(fixture.recordMessage(), profileID: fixture.profileID)
        XCTAssertEqual(response["ok"] as? Bool, true)
        XCTAssertEqual(response["storedCount"] as? Int, 1)

        let records = try await fixture.auditStore.load(now: fixture.now)
        XCTAssertEqual(records.single?.origin, "https://example.com")
        XCTAssertEqual(records.single?.profileID, fixture.profileID.uuidString.lowercased())
    }
}

private final class ServiceFixture {
    let suite = "WebShieldServiceTests.\(UUID().uuidString)"
    let directory: URL
    let settings: WebShieldSettingsStore
    let auditStore: AuditStore
    let service: NativeMessageService
    let profileID = UUID()
    let now = Date()

    init() throws {
        let defaults = UserDefaults(suiteName: suite)!
        settings = WebShieldSettingsStore(defaults: defaults)
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("WebShieldServiceTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        auditStore = AuditStore(fileURL: directory.appendingPathComponent("audit.json"))
        service = NativeMessageService(settings: settings, auditStore: auditStore)
    }

    func recordMessage() -> [String: Any] {
        [
            "version": 1,
            "requestId": UUID().uuidString,
            "type": "record_events",
            "events": [[
                "ruleId": "CRIT-001",
                "kind": "payment",
                "action": "cancelled",
                "timestampMs": now.timeIntervalSince1970 * 1_000,
                "url": "https://example.com/checkout?card=secret#details"
            ]]
        ]
    }

    func cleanup() {
        UserDefaults(suiteName: suite)?.removePersistentDomain(forName: suite)
        try? FileManager.default.removeItem(at: directory)
    }
}

private extension Array {
    var single: Element? { count == 1 ? first : nil }
}
