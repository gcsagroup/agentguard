import Foundation

public enum SharedContainerError: Error, Equatable {
    case unavailable(String)
}

extension SharedContainerError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case let .unavailable(identifier):
            return "Shared App Group container is unavailable: \(identifier)"
        }
    }
}

public enum SharedContainer {
    public static func appGroupURL(
        fileManager: FileManager = .default,
        identifier: String = WebShieldConstants.appGroupIdentifier
    ) throws -> URL {
        guard let url = fileManager.containerURL(
            forSecurityApplicationGroupIdentifier: identifier
        ) else {
            throw SharedContainerError.unavailable(identifier)
        }
        return url
    }
}
