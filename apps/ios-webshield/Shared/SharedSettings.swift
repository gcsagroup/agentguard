import Foundation

public struct WebShieldStatus: Codable, Equatable, Sendable {
    public let isEnabled: Bool
    public let hasAcceptedPrivacy: Bool
    public let policyRevision: String
    public let retentionDays: Int
    public let maximumAuditEvents: Int
}

public final class WebShieldSettingsStore {
    private enum Key {
        static let enabled = "webshield.enabled"
        static let privacyAccepted = "webshield.privacy-accepted"
        static let policyRevision = "webshield.policy-revision"
        static let retentionDays = "webshield.retention-days"
        static let maximumAuditEvents = "webshield.maximum-audit-events"
    }

    private let defaults: UserDefaults

    public init(defaults: UserDefaults) {
        self.defaults = defaults
    }

    public static func appGroup() throws -> WebShieldSettingsStore {
        guard let defaults = UserDefaults(suiteName: WebShieldConstants.appGroupIdentifier) else {
            throw SharedContainerError.unavailable(WebShieldConstants.appGroupIdentifier)
        }
        return WebShieldSettingsStore(defaults: defaults)
    }

    public func snapshot() -> WebShieldStatus {
        let accepted = defaults.bool(forKey: Key.privacyAccepted)
        return WebShieldStatus(
            isEnabled: accepted && defaults.bool(forKey: Key.enabled),
            hasAcceptedPrivacy: accepted,
            policyRevision: defaults.string(forKey: Key.policyRevision) ?? "builtin-1",
            retentionDays: clampedInteger(
                forKey: Key.retentionDays,
                defaultValue: WebShieldConstants.defaultRetentionDays,
                range: 1 ... 30
            ),
            maximumAuditEvents: clampedInteger(
                forKey: Key.maximumAuditEvents,
                defaultValue: WebShieldConstants.defaultMaximumAuditEvents,
                range: 10 ... 2_000
            )
        )
    }

    public func setPrivacyAccepted(_ accepted: Bool) {
        defaults.set(accepted, forKey: Key.privacyAccepted)
        if !accepted {
            defaults.set(false, forKey: Key.enabled)
        }
    }

    public func setEnabled(_ enabled: Bool) {
        defaults.set(enabled && defaults.bool(forKey: Key.privacyAccepted), forKey: Key.enabled)
    }

    public func setRetentionDays(_ value: Int) {
        defaults.set(min(max(value, 1), 30), forKey: Key.retentionDays)
    }

    private func clampedInteger(
        forKey key: String,
        defaultValue: Int,
        range: ClosedRange<Int>
    ) -> Int {
        guard defaults.object(forKey: key) != nil else { return defaultValue }
        return min(max(defaults.integer(forKey: key), range.lowerBound), range.upperBound)
    }
}
