import Foundation

// MARK: – SSL VPN family config (AnyConnect / GlobalProtect / Fortinet)

struct SSLVPNFamilyConfig: Codable, Equatable {
    var host:        String = ""
    var port:        Int    = 443
    var username:    String = ""
    var password:    String = ""    // Keychain-only, never JSON
    var group:       String = ""
    var totpSecret:  String = ""    // Keychain-only, never JSON
    var splitRoutes: String = ""    // CIDRs (manual list, optional)

    var tunnelDomains: String = ""

    var clientCertName:     String = ""
    var clientCertP12:      String = ""   // Keychain-only, base64 of the .p12
    var clientCertPassword: String = ""   // Keychain-only

    var partialEnabled: Bool = true

    enum CodingKeys: String, CodingKey {
        case host, port, username, group, splitRoutes, tunnelDomains, partialEnabled, clientCertName
    }

    init() {}

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        host        = (try? c.decode(String.self, forKey: .host))        ?? ""
        port        = (try? c.decode(Int.self,    forKey: .port))        ?? 443
        username    = (try? c.decode(String.self, forKey: .username))    ?? ""
        group       = (try? c.decode(String.self, forKey: .group))       ?? ""
        splitRoutes = (try? c.decode(String.self, forKey: .splitRoutes)) ?? ""
        tunnelDomains = (try? c.decode(String.self, forKey: .tunnelDomains)) ?? ""
        clientCertName = (try? c.decode(String.self, forKey: .clientCertName)) ?? ""
        if let saved = try? c.decode(Bool.self, forKey: .partialEnabled) {
            partialEnabled = saved
        } else {
            partialEnabled = !splitRoutes.isEmpty
        }
    }
}

// MARK: – WireGuard config

struct WireGuardConfig: Codable, Equatable {
    var confText: String = ""

    var splitRoutes: String = ""

    var partialEnabled: Bool = false

    enum CodingKeys: String, CodingKey {
        case splitRoutes, partialEnabled
    }

    init() {}

    init(confText: String, splitRoutes: String, partialEnabled: Bool = false) {
        self.confText = confText
        self.splitRoutes = splitRoutes
        self.partialEnabled = partialEnabled
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        splitRoutes = (try? c.decode(String.self, forKey: .splitRoutes)) ?? ""
        if let saved = try? c.decode(Bool.self, forKey: .partialEnabled) {
            partialEnabled = saved
        } else {
            partialEnabled = !splitRoutes.isEmpty
        }
    }
}

// MARK: – Tagged enum

enum ProviderConfig: Codable, Equatable {
    case sslVPN(SSLVPNFamilyConfig)
    case wireguard  (WireGuardConfig)

    var splitRoutes: String {
        get {
            switch self {
            case .sslVPN(let c): return c.splitRoutes
            case .wireguard  (let c): return c.splitRoutes
            }
        }
        set {
            switch self {
            case .sslVPN(var c): c.splitRoutes = newValue; self = .sslVPN(c)
            case .wireguard  (var c): c.splitRoutes = newValue; self = .wireguard(c)
            }
        }
    }

    var partialEnabled: Bool {
        get {
            switch self {
            case .sslVPN(let c): return c.partialEnabled
            case .wireguard  (let c): return c.partialEnabled
            }
        }
        set {
            switch self {
            case .sslVPN(var c): c.partialEnabled = newValue; self = .sslVPN(c)
            case .wireguard  (var c): c.partialEnabled = newValue; self = .wireguard(c)
            }
        }
    }

    var tunnelDomains: String {
        get { sslVPN?.tunnelDomains ?? "" }
        set {
            if case .sslVPN(var c) = self { c.tunnelDomains = newValue; self = .sslVPN(c) }
        }
    }

    var sslVPN: SSLVPNFamilyConfig? {
        if case .sslVPN(let c) = self { return c }; return nil
    }
    var wireguard: WireGuardConfig? {
        if case .wireguard(let c) = self { return c }; return nil
    }

    private static let legacyKindTag = "openConnect"
    private static let legacyPayloadKey = "openConnect"

    enum CodingKeys: String, CodingKey { case kind, sslVPN, wireguard }
    private struct LegacyCodingKeys: CodingKey {
        var stringValue: String
        init?(stringValue: String) { self.stringValue = stringValue }
        var intValue: Int? { nil }
        init?(intValue: Int) { nil }
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = (try? c.decode(String.self, forKey: .kind)) ?? Self.legacyKindTag
        switch kind {
        case "wireguard":
            self = .wireguard(try c.decode(WireGuardConfig.self, forKey: .wireguard))
        case Self.legacyKindTag:
            let legacy = try decoder.container(keyedBy: LegacyCodingKeys.self)
            let key = LegacyCodingKeys(stringValue: Self.legacyPayloadKey)!
            self = .sslVPN(try legacy.decode(SSLVPNFamilyConfig.self, forKey: key))
        default:
            self = .sslVPN(try c.decode(SSLVPNFamilyConfig.self, forKey: .sslVPN))
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .sslVPN(let v):
            try c.encode("sslVPN", forKey: .kind)
            try c.encode(v, forKey: .sslVPN)
        case .wireguard(let v):
            try c.encode("wireguard", forKey: .kind)
            try c.encode(v, forKey: .wireguard)
        }
    }
}

// MARK: – Scripted command

struct ScriptedCommand: Codable, Equatable, Identifiable {
    var id: UUID = UUID()
    var name: String = ""             // shown in the Connect-row terminal menu
    var targetHost: String = ""       // IP literal — DNS-through-tunnel isn't supported yet
    var targetPort: Int = 0
    var commandLine: String = ""
}

// MARK: – VPNProfile

struct VPNProfile: Identifiable, Codable, Equatable {
    var id:       UUID           = UUID()
    var name:     String         = "New Connection"
    var provider: ProviderType   = .anyConnect
    var config:   ProviderConfig = .sslVPN(SSLVPNFamilyConfig())
    var scriptedCommands: [ScriptedCommand] = []

    var sslVPNFamily: SSLVPNFamilyConfig {
        get { config.sslVPN ?? SSLVPNFamilyConfig() }
        set { config = .sslVPN(newValue) }
    }

    var wireguard: WireGuardConfig {
        get { config.wireguard ?? WireGuardConfig() }
        set { config = .wireguard(newValue) }
    }

    enum CodingKeys: String, CodingKey {
        case id, name, provider, config, scriptedCommands
    }

    init() {}

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id       = (try? c.decode(UUID.self, forKey: .id))         ?? UUID()
        name     = (try? c.decode(String.self, forKey: .name))     ?? "New Connection"
        provider = (try? c.decode(ProviderType.self, forKey: .provider)) ?? .anyConnect
        config   = (try? c.decode(ProviderConfig.self, forKey: .config))
                ?? .sslVPN(SSLVPNFamilyConfig())
        scriptedCommands = (try? c.decode([ScriptedCommand].self, forKey: .scriptedCommands)) ?? []
    }

    @discardableResult
    mutating func normalizeServerAddress() -> Bool {
        guard case .sslVPN(var oc) = config else { return false }
        let parsed = ServerAddress.parse(oc.host)
        var changed = false
        if oc.host != parsed.host { oc.host = parsed.host; changed = true }
        if let p = parsed.port, oc.port != p { oc.port = p; changed = true }
        if oc.group.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !parsed.group.isEmpty {
            oc.group = parsed.group; changed = true
        }
        if changed { config = .sslVPN(oc) }
        return changed
    }

    @discardableResult
    mutating func normalizeSplitRoutes() -> Bool {
        let canonical = RouteList.normalized(from: config.splitRoutes)
        guard canonical != config.splitRoutes else { return false }
        config.splitRoutes = canonical
        return true
    }

    @discardableResult
    mutating func normalizeTunnelDomains() -> Bool {
        guard case .sslVPN(var oc) = config else { return false }
        let canonical = DomainRouteResolver.normalizedList(from: oc.tunnelDomains)
        guard canonical != oc.tunnelDomains else { return false }
        oc.tunnelDomains = canonical
        config = .sslVPN(oc)
        return true
    }
}
