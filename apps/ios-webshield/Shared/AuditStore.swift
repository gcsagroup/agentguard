import Foundation

public struct AuditRecord: Codable, Equatable, Identifiable, Sendable {
    public let id: String
    public let requestID: String
    public let profileID: String
    public let ruleID: String
    public let kind: String
    public let action: String
    public let occurredAt: Date
    public let origin: String

    public init(
        id: String,
        requestID: String,
        profileID: String,
        ruleID: String,
        kind: String,
        action: String,
        occurredAt: Date,
        origin: String
    ) {
        self.id = id
        self.requestID = requestID
        self.profileID = profileID
        self.ruleID = ruleID
        self.kind = kind
        self.action = action
        self.occurredAt = occurredAt
        self.origin = origin
    }
}

public struct AuditRetentionPolicy: Equatable, Sendable {
    public let days: Int
    public let maximumRecords: Int

    public init(days: Int, maximumRecords: Int) {
        self.days = min(max(days, 1), 30)
        self.maximumRecords = min(max(maximumRecords, 10), 2_000)
    }

    public static let `default` = AuditRetentionPolicy(
        days: WebShieldConstants.defaultRetentionDays,
        maximumRecords: WebShieldConstants.defaultMaximumAuditEvents
    )
}

public actor AuditStore {
    private let fileURL: URL

    public init(fileURL: URL) {
        self.fileURL = fileURL
    }

    @discardableResult
    public func append(
        requestID: UUID,
        profileID: UUID?,
        events: [IncomingWebShieldEvent],
        retention: AuditRetentionPolicy,
        now: Date = Date()
    ) throws -> Int {
        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        return try coordinateWrite { coordinatedURL in
            var records = retained(
                try decodeRecords(at: coordinatedURL),
                policy: retention,
                now: now
            )
            let requestIDString = requestID.uuidString.lowercased()
            guard !records.contains(where: { $0.requestID == requestIDString }) else {
                try encodeRecords(records, to: coordinatedURL)
                return 0
            }

            let profile = profileID?.uuidString.lowercased() ?? "default"
            let incoming = events.enumerated().map { index, event in
                AuditRecord(
                    id: "\(requestIDString)#\(index)",
                    requestID: requestIDString,
                    profileID: profile,
                    ruleID: event.ruleID,
                    kind: event.kind,
                    action: event.action,
                    occurredAt: event.occurredAt,
                    origin: event.origin
                )
            }
            records.append(contentsOf: incoming)
            records = retained(records, policy: retention, now: now)
            try encodeRecords(records, to: coordinatedURL)
            let incomingIDs = Set(incoming.map(\.id))
            return records.count { incomingIDs.contains($0.id) }
        }
    }

    public func load(
        retention: AuditRetentionPolicy = .default,
        now: Date = Date()
    ) throws -> [AuditRecord] {
        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        return try coordinateWrite { coordinatedURL in
            let records = try decodeRecords(at: coordinatedURL)
            let maintained = retained(records, policy: retention, now: now)
            if maintained != records {
                try encodeRecords(maintained, to: coordinatedURL)
            }
            return maintained.sorted { $0.occurredAt > $1.occurredAt }
        }
    }

    public func clear() throws {
        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try coordinateWrite { coordinatedURL in
            try encodeRecords([], to: coordinatedURL)
        }
    }

    private func retained(
        _ records: [AuditRecord],
        policy: AuditRetentionPolicy,
        now: Date
    ) -> [AuditRecord] {
        let cutoff = now.addingTimeInterval(-Double(policy.days) * 86_400)
        let inWindow = records
            .filter { $0.occurredAt >= cutoff && $0.occurredAt <= now.addingTimeInterval(300) }
            .sorted { $0.occurredAt < $1.occurredAt }
        return Array(inWindow.suffix(policy.maximumRecords))
    }

    private func decodeRecords(at url: URL) throws -> [AuditRecord] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        guard !data.isEmpty else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return try data.split(separator: 0x0A).map { line in
            try decoder.decode(AuditRecord.self, from: Data(line))
        }
    }

    private func encodeRecords(_ records: [AuditRecord], to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        let lines = try records.map { record -> String in
            let data = try encoder.encode(record)
            guard let line = String(data: data, encoding: .utf8) else {
                throw CocoaError(.fileWriteInapplicableStringEncoding)
            }
            return line
        }
        let text = lines.isEmpty ? "" : lines.joined(separator: "\n") + "\n"
        let data = Data(text.utf8)
        try data.write(to: url, options: [.atomic])
#if os(iOS)
        try? FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: url.path
        )
#endif
    }

    private func coordinateWrite<T>(_ body: (URL) throws -> T) throws -> T {
        var coordinationError: NSError?
        var operationResult: Result<T, Error>?
        NSFileCoordinator(filePresenter: nil).coordinate(
            writingItemAt: fileURL,
            options: .forReplacing,
            error: &coordinationError
        ) { coordinatedURL in
            operationResult = Result { try body(coordinatedURL) }
        }
        if let coordinationError { throw coordinationError }
        guard let operationResult else {
            throw CocoaError(.fileWriteUnknown)
        }
        return try operationResult.get()
    }
}
