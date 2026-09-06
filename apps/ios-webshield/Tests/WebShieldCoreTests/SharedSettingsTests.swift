import XCTest
@testable import WebShieldCore

final class SharedSettingsTests: XCTestCase {
    func testConsentGatesProtectionAndRevocationDisablesIt() {
        let suite = "WebShieldSettingsTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = WebShieldSettingsStore(defaults: defaults)

        store.setEnabled(true)
        XCTAssertFalse(store.snapshot().isEnabled)

        store.setPrivacyAccepted(true)
        store.setEnabled(true)
        XCTAssertTrue(store.snapshot().isEnabled)

        store.setPrivacyAccepted(false)
        XCTAssertFalse(store.snapshot().isEnabled)
        XCTAssertFalse(store.snapshot().hasAcceptedPrivacy)
    }

    func testDefaultsUseBoundedRetention() {
        let suite = "WebShieldSettingsTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = WebShieldSettingsStore(defaults: defaults)

        XCTAssertEqual(store.snapshot().retentionDays, 7)
        XCTAssertEqual(store.snapshot().maximumAuditEvents, 500)
        store.setRetentionDays(90)
        XCTAssertEqual(store.snapshot().retentionDays, 30)
    }
}
