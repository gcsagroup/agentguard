import Foundation

public enum URLMinimizer {
    /// Keeps only the HTTP(S) origin. User info, path, query, and fragment never enter the audit log.
    public static func origin(from rawValue: String) -> String? {
        guard !rawValue.isEmpty,
              rawValue.utf8.count <= 2_048,
              rawValue.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }),
              var components = URLComponents(string: rawValue),
              let rawScheme = components.scheme?.lowercased(),
              rawScheme == "http" || rawScheme == "https",
              let rawHost = components.host?.lowercased(),
              !rawHost.isEmpty else {
            return nil
        }

        let defaultPort = rawScheme == "https" ? 443 : 80
        let retainedPort = components.port == defaultPort ? nil : components.port
        components = URLComponents()
        components.scheme = rawScheme
        components.host = rawHost
        components.port = retainedPort
        return components.url?.absoluteString
    }
}
