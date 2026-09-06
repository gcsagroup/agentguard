import Foundation
import WebShieldCore

@MainActor
final class WebShieldViewModel: ObservableObject {
    @Published private(set) var isEnabled = false
    @Published private(set) var hasAcceptedPrivacy = false
    @Published private(set) var records: [AuditRecord] = []
    @Published private(set) var storageAvailable = true

    var canClearHistory: Bool { auditStore != nil }

    private let settings: WebShieldSettingsStore?
    private let auditStore: AuditStore?

    init() {
        do {
            let settings = try WebShieldSettingsStore.appGroup()
            let container = try SharedContainer.appGroupURL()
            self.settings = settings
            auditStore = AuditStore(
                fileURL: container.appendingPathComponent(WebShieldConstants.auditFileName)
            )
        } catch {
            settings = nil
            auditStore = nil
            storageAvailable = false
        }
    }

    func reload() async {
        guard let settings, let auditStore else {
            storageAvailable = false
            return
        }
        let status = settings.snapshot()
        isEnabled = status.isEnabled
        hasAcceptedPrivacy = status.hasAcceptedPrivacy
        do {
            records = try await auditStore.load(
                retention: AuditRetentionPolicy(
                    days: status.retentionDays,
                    maximumRecords: status.maximumAuditEvents
                )
            )
            storageAvailable = true
        } catch {
            records = []
            storageAvailable = false
        }
    }

    func setPrivacyAccepted(_ accepted: Bool) async {
        settings?.setPrivacyAccepted(accepted)
        await reload()
    }

    func setEnabled(_ enabled: Bool) async {
        settings?.setEnabled(enabled)
        await reload()
    }

    func clearHistory() async {
        do {
            try await auditStore?.clear()
            await reload()
        } catch {
            storageAvailable = false
        }
    }
}
