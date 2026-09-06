import Foundation

public final class NativeMessageService {
    private let settings: WebShieldSettingsStore
    private let auditStore: AuditStore

    public init(settings: WebShieldSettingsStore, auditStore: AuditStore) {
        self.settings = settings
        self.auditStore = auditStore
    }

    public func handle(_ rawMessage: Any, profileID: UUID?) async -> [String: Any] {
        do {
            let request = try NativeMessageDecoder.decode(rawMessage)
            let status = settings.snapshot()
            switch request {
            case let .status(requestID):
                return successResponse(requestID: requestID, status: status)

            case let .recordEvents(requestID, events):
                guard status.hasAcceptedPrivacy, status.isEnabled else {
                    return errorResponse(
                        requestID: requestID,
                        code: "protection_disabled"
                    )
                }
                guard let profileID else {
                    return errorResponse(
                        requestID: requestID,
                        code: "profile_unavailable"
                    )
                }
                let stored = try await auditStore.append(
                    requestID: requestID,
                    profileID: profileID,
                    events: events,
                    retention: AuditRetentionPolicy(
                        days: status.retentionDays,
                        maximumRecords: status.maximumAuditEvents
                    )
                )
                var response = successResponse(requestID: requestID, status: status)
                response["storedCount"] = stored
                return response
            }
        } catch let error as MessageValidationError {
            return errorResponse(requestID: nil, code: error.code)
        } catch {
            return errorResponse(requestID: nil, code: "storage_unavailable")
        }
    }

    private func successResponse(
        requestID: UUID,
        status: WebShieldStatus
    ) -> [String: Any] {
        [
            "version": WebShieldConstants.contractVersion,
            "requestId": requestID.uuidString.lowercased(),
            "ok": true,
            "enabled": status.isEnabled,
            "privacyAccepted": status.hasAcceptedPrivacy,
            "policyRevision": status.policyRevision
        ]
    }

    private func errorResponse(requestID: UUID?, code: String) -> [String: Any] {
        var response: [String: Any] = [
            "version": WebShieldConstants.contractVersion,
            "ok": false,
            "error": code
        ]
        if let requestID {
            response["requestId"] = requestID.uuidString.lowercased()
        }
        return response
    }
}
