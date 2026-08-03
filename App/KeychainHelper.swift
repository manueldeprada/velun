import Security
import Foundation
import OSLog

private let keychainLog = Logger(subsystem: "com.manueldeprada.velun", category: "Keychain")

enum KeychainHelper {
    private static let service = "com.manueldeprada.velun"

    // MARK: – Per-profile secrets

    static func savePassword(_ value: String, for id: UUID) {
        set(value, account: "pwd-\(id.uuidString)")
    }
    static func loadPassword(for id: UUID) -> String? {
        get(account: "pwd-\(id.uuidString)")
    }

    static func saveTOTP(_ value: String, for id: UUID) {
        set(value, account: "totp-\(id.uuidString)")
    }
    static func loadTOTP(for id: UUID) -> String? {
        get(account: "totp-\(id.uuidString)")
    }

    static func saveWireGuardConf(_ value: String, for id: UUID) {
        set(value, account: "wgconf-\(id.uuidString)")
    }
    static func loadWireGuardConf(for id: UUID) -> String? {
        get(account: "wgconf-\(id.uuidString)")
    }

    static func saveClientCert(_ base64: String, for id: UUID) {
        set(base64, account: "cert-\(id.uuidString)")
    }
    static func loadClientCert(for id: UUID) -> String? {
        get(account: "cert-\(id.uuidString)")
    }
    static func saveClientCertPassword(_ value: String, for id: UUID) {
        set(value, account: "certpw-\(id.uuidString)")
    }
    static func loadClientCertPassword(for id: UUID) -> String? {
        get(account: "certpw-\(id.uuidString)")
    }

    static func delete(for id: UUID) {
        remove(account: "pwd-\(id.uuidString)")
        remove(account: "totp-\(id.uuidString)")
        remove(account: "wgconf-\(id.uuidString)")
        remove(account: "cert-\(id.uuidString)")
        remove(account: "certpw-\(id.uuidString)")
    }

    // MARK: – Generic named items (license, install date, ...)

    static func setItem(_ value: String, account: String) {
        set(value, account: account)
    }
    static func getItem(account: String) -> String? {
        get(account: account)
    }
    static func removeItem(account: String) {
        remove(account: account)
    }

    // MARK: – Private

    private static func baseQuery(account: String) -> [CFString: Any] {
        velunKeychainBaseQuery(service: service, account: account)
    }

    private static func set(_ value: String, account: String) {
        guard let data = value.data(using: .utf8) else { return }
        let query = baseQuery(account: account)
        let attrs: [CFString: Any] = [kSecValueData: data]
        if SecItemUpdate(query as CFDictionary, attrs as CFDictionary) == errSecItemNotFound {
            SecItemAdd(query.merging(attrs) { _, new in new } as CFDictionary, nil)
        }
    }

    private static func get(account: String) -> String? {
        var query = baseQuery(account: account)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var ref: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &ref)
        if status == errSecSuccess,
           let data = ref as? Data,
           let s = String(data: data, encoding: .utf8) {
            return s
        }
        if status != errSecItemNotFound {
            keychainLog.error("SecItemCopyMatching failed for \(account, privacy: .public): OSStatus \(status)")
        }
        var legacy: [CFString: Any] = [
            kSecClass:               kSecClassGenericPassword,
            kSecAttrService:         service,
            kSecAttrAccount:         account,
            kSecReturnData:          true,
            kSecMatchLimit:          kSecMatchLimitOne,
            kSecUseAuthenticationUI: kSecUseAuthenticationUISkip as Any,
        ]
        var legacyRef: AnyObject?
        guard SecItemCopyMatching(legacy as CFDictionary, &legacyRef) == errSecSuccess,
              let data = legacyRef as? Data,
              let s = String(data: data, encoding: .utf8) else { return nil }
        set(s, account: account)
        legacy.removeValue(forKey: kSecReturnData)
        legacy.removeValue(forKey: kSecMatchLimit)
        SecItemDelete(legacy as CFDictionary)
        return s
    }

    private static func remove(account: String) {
        SecItemDelete(baseQuery(account: account) as CFDictionary)
    }
}
