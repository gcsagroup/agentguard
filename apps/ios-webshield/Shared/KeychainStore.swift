import Foundation
import Security

public enum KeychainStoreError: Error, Equatable {
    case invalidConfiguration
    case unexpectedStatus(OSStatus)
}

public struct KeychainStore {
    private let service: String
    private let accessGroup: String?

    public init(service: String = "com.agentguard.webshield", accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    public static func production(bundle: Bundle = .main) throws -> KeychainStore {
        guard let accessGroup = bundle.object(
            forInfoDictionaryKey: "AGKeychainAccessGroup"
        ) as? String,
        !accessGroup.isEmpty,
        !accessGroup.contains("$(") else {
            throw KeychainStoreError.invalidConfiguration
        }
        return KeychainStore(accessGroup: accessGroup)
    }

    public func set(_ data: Data, for account: String) throws {
        var query = baseQuery(account: account)
        let updateStatus = SecItemUpdate(
            query as CFDictionary,
            [kSecValueData as String: data] as CFDictionary
        )
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else {
            throw KeychainStoreError.unexpectedStatus(updateStatus)
        }

        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let addStatus = SecItemAdd(query as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw KeychainStoreError.unexpectedStatus(addStatus)
        }
    }

    public func data(for account: String) throws -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeychainStoreError.unexpectedStatus(status)
        }
        return data
    }

    public func delete(account: String) throws {
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainStoreError.unexpectedStatus(status)
        }
    }

    private func baseQuery(account: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }
}
