import Foundation

public enum WebShieldConstants {
    public static let appGroupIdentifier = "group.com.agentguard.webshield"
    public static let nativeApplicationIdentifier = "com.agentguard.webshield"
    public static let auditFileName = "webshield-audit-v1.jsonl"
    public static let contractVersion = 1
    public static let maximumMessageBytes = 64 * 1024
    public static let maximumEventsPerMessage = 50
    public static let defaultRetentionDays = 7
    public static let defaultMaximumAuditEvents = 500
}
