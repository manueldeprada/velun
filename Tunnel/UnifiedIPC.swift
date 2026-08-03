import Foundation

enum UnifiedIPC {

    enum Action {
        static let addUpstream    = "u.addUpstream"
        static let removeUpstream = "u.removeUpstream"
        static let setRouting     = "u.setRouting"
        static let setDomainRoutes = "u.setDomainRoutes"
        static let status         = "u.status"
        static let appliedRoutes  = "u.appliedRoutes"
        static let lastError      = "u.lastError"
        static let stats          = "u.stats"
        static let mfaPrompt      = "u.mfaPrompt"
        static let submitMFA      = "u.submitMFA"
        static let ssoRequest     = "u.ssoRequest"
        static let submitSSO      = "u.submitSSO"
    }

    // MARK: – Requests (app → extension)

    struct AddUpstream: Codable, Equatable {
        var action: String = Action.addUpstream
        var config: SharedTunnelConfig
    }

    struct ByProfile: Codable, Equatable {
        var action: String
        var profileID: String
    }

    struct SubmitMFA: Codable, Equatable {
        var action: String = Action.submitMFA
        var profileID: String
        var code: String
    }

    struct SubmitSSO: Codable, Equatable {
        var action: String = Action.submitSSO
        var profileID: String
        var token: String
    }

    struct SetRouting: Codable, Equatable {
        var action: String = Action.setRouting
        var profileID: String
        var partialMode: String      // PartialTunnelMode.rawValue
        var manualRoutes: String
    }

    struct SetDomainRoutes: Codable, Equatable {
        var action: String = Action.setDomainRoutes
        var profileID: String
        var cidrs: [String]
    }

    /// Poll-all-upstream-states request (no payload beyond the action).
    struct StatusRequest: Codable, Equatable {
        var action: String = Action.status
    }

    /// Poll per-upstream byte counters (no payload beyond the action).
    struct StatsRequest: Codable, Equatable {
        var action: String = Action.stats
    }

    struct StatsReply: Codable, Equatable {
        var stats: [String: [UInt64]]
    }

    // MARK: – Replies (extension → app)

    struct StatusReply: Codable, Equatable {
        var statuses: [String: String]   // profileID → UpstreamState.rawValue
    }

    enum UpstreamState: String, Codable {
        case connecting
        case connected
        case reconnecting
        case disconnected
        case failed
        case needsMFA
        case needsSSO
    }

    // Short reply tokens for fire-and-ack actions.
    static let ok = "ok"
    static func err(_ message: String) -> String { "err:\(message)" }

    // MARK: – Helpers

    static func action(in data: Data) -> String? {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return obj["action"] as? String
    }

    static func encode<T: Encodable>(_ value: T) -> Data? {
        try? JSONEncoder().encode(value)
    }

    static func decode<T: Decodable>(_ type: T.Type, from data: Data) -> T? {
        try? JSONDecoder().decode(type, from: data)
    }

    // Convenience builders so call sites don't repeat the action string.
    static func removeUpstream(_ profileID: String) -> ByProfile {
        ByProfile(action: Action.removeUpstream, profileID: profileID)
    }
    static func appliedRoutes(_ profileID: String) -> ByProfile {
        ByProfile(action: Action.appliedRoutes, profileID: profileID)
    }
    static func lastError(_ profileID: String) -> ByProfile {
        ByProfile(action: Action.lastError, profileID: profileID)
    }
    static func mfaPrompt(_ profileID: String) -> ByProfile {
        ByProfile(action: Action.mfaPrompt, profileID: profileID)
    }
    static func ssoRequest(_ profileID: String) -> ByProfile {
        ByProfile(action: Action.ssoRequest, profileID: profileID)
    }
}
