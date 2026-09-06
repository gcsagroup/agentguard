@preconcurrency import Foundation
import OSLog
import SafariServices
import WebShieldCore

/// SafariServices is an Objective-C framework and does not annotate its request payload or
/// `NSExtensionContext` as `Sendable`. Each callback gives this handler exclusive ownership of
/// one immutable payload/context pair, and exactly one child task completes that context once.
/// Keep the unchecked boundary this small; no value escapes beyond that task.
private final class PendingExtensionRequest: @unchecked Sendable {
    let context: NSExtensionContext
    let message: Any
    let profileID: UUID?

    init(context: NSExtensionContext, message: Any, profileID: UUID?) {
        self.context = context
        self.message = message
        self.profileID = profileID
    }
}

final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling, @unchecked Sendable {
    private let logger = Logger(
        subsystem: "com.agentguard.webshield.extension",
        category: "native-message"
    )

    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let message = item?.userInfo?[SFExtensionMessageKey] ?? NSNull()
        let profileID = item?.userInfo?[SFExtensionProfileKey] as? UUID
        let request = PendingExtensionRequest(
            context: context,
            message: message,
            profileID: profileID
        )

        // Safari may call from an Objective-C executor that Swift cannot prove is isolated.
        // The handler and request wrapper are immutable; this single task exclusively handles
        // the payload and completes its request context exactly once.
        Task {
            let response = await handle(message: request.message, profileID: request.profileID)
            let responseItem = NSExtensionItem()
            responseItem.userInfo = [SFExtensionMessageKey: response]
            request.context.completeRequest(returningItems: [responseItem])
        }
    }

    private func handle(message: Any, profileID: UUID?) async -> [String: Any] {
        do {
            let settings = try WebShieldSettingsStore.appGroup()
            let container = try SharedContainer.appGroupURL()
            let store = AuditStore(
                fileURL: container.appendingPathComponent(WebShieldConstants.auditFileName)
            )
            let service = NativeMessageService(settings: settings, auditStore: store)
            let response = await service.handle(message, profileID: profileID)
            logger.info("Handled WebShield native message; success=\(response["ok"] as? Bool ?? false, privacy: .public)")
            return response
        } catch {
            logger.error("WebShield shared container unavailable")
            return [
                "version": WebShieldConstants.contractVersion,
                "ok": false,
                "error": "shared_container_unavailable"
            ]
        }
    }
}
