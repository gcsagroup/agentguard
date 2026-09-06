import XCTest
@testable import WebShieldCore

final class AuditStoreTests: XCTestCase {
    func testAppendIsIdempotentAndClearRemovesRecords() async throws {
        let fixture = try AuditFixture()
        defer { fixture.cleanup() }
        let store = AuditStore(fileURL: fixture.fileURL)
        let requestID = UUID()
        let event = fixture.event(at: fixture.now)

        let first = try await store.append(
            requestID: requestID,
            profileID: UUID(),
            events: [event],
            retention: .default,
            now: fixture.now
        )
        let duplicate = try await store.append(
            requestID: requestID,
            profileID: UUID(),
            events: [event],
            retention: .default,
            now: fixture.now
        )

        XCTAssertEqual(first, 1)
        XCTAssertEqual(duplicate, 0)
        let recordsBeforeClear = try await store.load(now: fixture.now)
        XCTAssertEqual(recordsBeforeClear.count, 1)
        try await store.clear()
        let recordsAfterClear = try await store.load(now: fixture.now)
        XCTAssertTrue(recordsAfterClear.isEmpty)

        try Data("corrupt".utf8).write(to: fixture.fileURL, options: .atomic)
        do {
            _ = try await store.load(now: fixture.now)
            XCTFail("A corrupt audit must not be silently replaced")
        } catch {
            // The user-visible clear action remains able to recover this file.
        }
        try await store.clear()
        let recovered = try await store.load(now: fixture.now)
        XCTAssertTrue(recovered.isEmpty)
    }

    func testRetentionDropsExpiredAndFutureRecords() async throws {
        let fixture = try AuditFixture()
        defer { fixture.cleanup() }
        let store = AuditStore(fileURL: fixture.fileURL)
        let old = fixture.event(at: fixture.now.addingTimeInterval(-8 * 86_400))
        let current = fixture.event(at: fixture.now)
        let future = fixture.event(at: fixture.now.addingTimeInterval(600))

        _ = try await store.append(
            requestID: UUID(),
            profileID: nil,
            events: [old, current, future],
            retention: .default,
            now: fixture.now
        )

        let records = try await store.load(now: fixture.now)
        XCTAssertEqual(records.map(\.occurredAt), [fixture.now])
    }

    func testLoadPhysicallyPurgesExpiredRecordsFromDisk() async throws {
        let fixture = try AuditFixture()
        defer { fixture.cleanup() }
        let store = AuditStore(fileURL: fixture.fileURL)
        try fixture.writeRecords([
            fixture.record(id: "expired", at: fixture.now.addingTimeInterval(-8 * 86_400)),
            fixture.record(id: "current", at: fixture.now)
        ])

        let records = try await store.load(now: fixture.now)

        XCTAssertEqual(records.map(\.id), ["current"])
        XCTAssertEqual(try fixture.diskRecords().map(\.id), ["current"])
        XCTAssertEqual(try fixture.diskLineCount(), 1)
    }

    func testLoadReplacesAnAllExpiredFileWithAnEmptyFile() async throws {
        let fixture = try AuditFixture()
        defer { fixture.cleanup() }
        let store = AuditStore(fileURL: fixture.fileURL)
        try fixture.writeRecords([
            fixture.record(id: "expired-1", at: fixture.now.addingTimeInterval(-8 * 86_400)),
            fixture.record(id: "expired-2", at: fixture.now.addingTimeInterval(-30 * 86_400))
        ])

        let loaded = try await store.load(now: fixture.now)
        XCTAssertTrue(loaded.isEmpty)
        XCTAssertEqual(try Data(contentsOf: fixture.fileURL).count, 0)
        XCTAssertEqual(try fixture.diskLineCount(), 0)
    }

    func testConcurrentCallersAreSerializedWithoutLostRecords() async throws {
        let fixture = try AuditFixture()
        defer { fixture.cleanup() }
        let store = AuditStore(fileURL: fixture.fileURL)
        let now = fixture.now

        try await withThrowingTaskGroup(of: Void.self) { group in
            for offset in 0 ..< 12 {
                group.addTask {
                    _ = try await store.append(
                        requestID: UUID(),
                        profileID: nil,
                        events: [fixture.event(at: now.addingTimeInterval(Double(offset)))],
                        retention: AuditRetentionPolicy(days: 7, maximumRecords: 20),
                        now: now.addingTimeInterval(20)
                    )
                }
            }
            try await group.waitForAll()
        }

        let records = try await store.load(
            retention: AuditRetentionPolicy(days: 7, maximumRecords: 20),
            now: now.addingTimeInterval(20)
        )
        XCTAssertEqual(records.count, 12)
        let lines = try String(contentsOf: fixture.fileURL, encoding: .utf8)
            .split(separator: "\n")
        XCTAssertEqual(lines.count, 12)
    }

    func testConcurrentStoreInstancesCoordinateWithoutLostOrPartialRecords() async throws {
        let fixture = try AuditFixture()
        defer { fixture.cleanup() }
        let fileURL = fixture.fileURL
        let now = fixture.now
        try fixture.writeRecords([
            fixture.record(id: "expired", at: now.addingTimeInterval(-8 * 86_400))
        ])

        try await withThrowingTaskGroup(of: Void.self) { group in
            for offset in 0 ..< 32 {
                group.addTask {
                    let store = AuditStore(fileURL: fileURL)
                    let event = IncomingWebShieldEvent(
                        ruleID: "CRIT-001",
                        kind: "payment",
                        action: "cancelled",
                        occurredAt: now.addingTimeInterval(Double(offset)),
                        origin: "https://example.com"
                    )
                    _ = try await store.append(
                        requestID: UUID(),
                        profileID: nil,
                        events: [event],
                        retention: AuditRetentionPolicy(days: 7, maximumRecords: 64),
                        now: now.addingTimeInterval(60)
                    )
                    _ = try await store.load(
                        retention: AuditRetentionPolicy(days: 7, maximumRecords: 64),
                        now: now.addingTimeInterval(60)
                    )
                }
            }
            try await group.waitForAll()
        }

        let records = try await AuditStore(fileURL: fileURL).load(
            retention: AuditRetentionPolicy(days: 7, maximumRecords: 64),
            now: now.addingTimeInterval(60)
        )
        XCTAssertEqual(records.count, 32)
        XCTAssertEqual(Set(records.map(\.occurredAt)).count, 32)
        XCTAssertEqual(try fixture.diskRecords().count, 32)
        XCTAssertEqual(try fixture.diskLineCount(), 32)
    }
}

// XCTest closures use this fixture concurrently, but its URLs and reference time are immutable;
// each test owns a unique directory and performs I/O through AuditStore's actor/coordinator.
private final class AuditFixture: @unchecked Sendable {
    let directory: URL
    let fileURL: URL
    let now = Date(timeIntervalSince1970: 1_700_000_000)

    init() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("WebShieldAuditTests-\(UUID().uuidString)", isDirectory: true)
        fileURL = directory.appendingPathComponent("audit.json")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    func event(at date: Date) -> IncomingWebShieldEvent {
        IncomingWebShieldEvent(
            ruleID: "CRIT-001",
            kind: "payment",
            action: "cancelled",
            occurredAt: date,
            origin: "https://example.com"
        )
    }

    func record(id: String, at date: Date) -> AuditRecord {
        AuditRecord(
            id: id,
            requestID: "request-\(id)",
            profileID: "profile",
            ruleID: "CRIT-001",
            kind: "payment",
            action: "cancelled",
            occurredAt: date,
            origin: "https://example.com"
        )
    }

    func writeRecords(_ records: [AuditRecord]) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        let lines = try records.map { record in
            String(decoding: try encoder.encode(record), as: UTF8.self)
        }
        try Data((lines.joined(separator: "\n") + "\n").utf8)
            .write(to: fileURL, options: .atomic)
    }

    func diskRecords() throws -> [AuditRecord] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return try Data(contentsOf: fileURL)
            .split(separator: 0x0A)
            .map { try decoder.decode(AuditRecord.self, from: Data($0)) }
    }

    func diskLineCount() throws -> Int {
        try Data(contentsOf: fileURL).split(separator: 0x0A).count
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: directory)
    }
}
