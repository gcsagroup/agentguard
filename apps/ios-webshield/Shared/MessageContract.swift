import CoreFoundation
import Foundation

public enum WebShieldRequest: Equatable {
    case status(requestID: UUID)
    case recordEvents(requestID: UUID, events: [IncomingWebShieldEvent])

    public var requestID: UUID {
        switch self {
        case let .status(requestID), let .recordEvents(requestID, _):
            return requestID
        }
    }
}

public struct IncomingWebShieldEvent: Codable, Equatable, Sendable {
    public let ruleID: String
    public let kind: String
    public let action: String
    public let occurredAt: Date
    public let origin: String

    public init(
        ruleID: String,
        kind: String,
        action: String,
        occurredAt: Date,
        origin: String
    ) {
        self.ruleID = ruleID
        self.kind = kind
        self.action = action
        self.occurredAt = occurredAt
        self.origin = origin
    }
}

public enum MessageValidationError: Error, Equatable {
    case notDictionary
    case messageTooLarge
    case unknownField
    case unsupportedVersion
    case invalidRequestID
    case invalidType
    case invalidEvents
    case tooManyEvents
    case invalidEvent
    case unsupportedEventValue

    public var code: String {
        switch self {
        case .notDictionary: return "invalid_container"
        case .messageTooLarge: return "message_too_large"
        case .unknownField: return "unknown_field"
        case .unsupportedVersion: return "unsupported_version"
        case .invalidRequestID: return "invalid_request_id"
        case .invalidType: return "invalid_type"
        case .invalidEvents: return "invalid_events"
        case .tooManyEvents: return "too_many_events"
        case .invalidEvent: return "invalid_event"
        case .unsupportedEventValue: return "unsupported_event_value"
        }
    }
}

public enum NativeMessageDecoder {
    private static let statusFields: Set<String> = ["version", "requestId", "type"]
    private static let recordFields: Set<String> = ["version", "requestId", "type", "events"]
    private static let eventFields: Set<String> = [
        "ruleId", "kind", "action", "timestampMs", "url"
    ]
    private static let allowedKinds: Set<String> = ["payment", "prompt_injection", "privacy_trap"]
    private static let allowedActions: Set<String> = ["cancelled", "allowed"]

    public static func decode(_ value: Any) throws -> WebShieldRequest {
        guard let dictionary = value as? [String: Any] else {
            throw MessageValidationError.notDictionary
        }
        guard JSONSerialization.isValidJSONObject(dictionary),
              let encoded = try? JSONSerialization.data(withJSONObject: dictionary),
              encoded.count <= WebShieldConstants.maximumMessageBytes else {
            throw MessageValidationError.messageTooLarge
        }
        guard integer(dictionary["version"]) == WebShieldConstants.contractVersion else {
            throw MessageValidationError.unsupportedVersion
        }
        guard let requestIDString = boundedString(dictionary["requestId"], maximumLength: 64),
              let requestID = UUID(uuidString: requestIDString) else {
            throw MessageValidationError.invalidRequestID
        }
        guard let type = boundedString(dictionary["type"], maximumLength: 32) else {
            throw MessageValidationError.invalidType
        }

        switch type {
        case "get_status":
            guard Set(dictionary.keys).isSubset(of: statusFields) else {
                throw MessageValidationError.unknownField
            }
            return .status(requestID: requestID)

        case "record_events":
            guard Set(dictionary.keys).isSubset(of: recordFields) else {
                throw MessageValidationError.unknownField
            }
            guard let eventValues = dictionary["events"] as? [Any], !eventValues.isEmpty else {
                throw MessageValidationError.invalidEvents
            }
            guard eventValues.count <= WebShieldConstants.maximumEventsPerMessage else {
                throw MessageValidationError.tooManyEvents
            }
            let events = try eventValues.map(decodeEvent)
            return .recordEvents(requestID: requestID, events: events)

        default:
            throw MessageValidationError.invalidType
        }
    }

    private static func decodeEvent(_ value: Any) throws -> IncomingWebShieldEvent {
        guard let dictionary = value as? [String: Any],
              Set(dictionary.keys).isSubset(of: eventFields),
              Set(dictionary.keys) == eventFields,
              let ruleID = boundedString(dictionary["ruleId"], maximumLength: 32),
              ruleID.range(of: #"^[A-Z][A-Z0-9-]{1,31}$"#, options: .regularExpression) != nil,
              let kind = boundedString(dictionary["kind"], maximumLength: 32),
              let action = boundedString(dictionary["action"], maximumLength: 16),
              allowedKinds.contains(kind),
              allowedActions.contains(action),
              let timestamp = finiteNumber(dictionary["timestampMs"]),
              timestamp >= 0,
              let rawURL = boundedString(dictionary["url"], maximumLength: 2_048),
              let origin = URLMinimizer.origin(from: rawURL) else {
            throw MessageValidationError.invalidEvent
        }

        return IncomingWebShieldEvent(
            ruleID: ruleID,
            kind: kind,
            action: action,
            occurredAt: Date(timeIntervalSince1970: timestamp / 1_000),
            origin: origin
        )
    }

    private static func boundedString(_ value: Any?, maximumLength: Int) -> String? {
        guard let string = value as? String,
              !string.isEmpty,
              string.utf8.count <= maximumLength,
              string.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            return nil
        }
        return string
    }

    private static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.rounded() == number.doubleValue else {
            return nil
        }
        return number.intValue
    }

    private static func finiteNumber(_ value: Any?) -> Double? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.isFinite else {
            return nil
        }
        return number.doubleValue
    }
}
