import Foundation
import Combine
import NetworkExtension

// MARK: – Status

enum ConnectionStatus: Equatable {
    case disconnected
    case connecting
    case connected
    case disconnecting
    case reconnecting   // transitional state during full/partial tunnel switch
    case failed(String)

    static func == (lhs: Self, rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case (.disconnected,.disconnected),(.connecting,.connecting),
             (.connected,.connected),(.disconnecting,.disconnecting),
             (.reconnecting,.reconnecting): return true
        case (.failed(let a),.failed(let b)): return a == b
        default: return false
        }
    }

    static func from(_ s: NEVPNStatus) -> ConnectionStatus {
        switch s {
        case .connected:     return .connected
        case .connecting:    return .connecting
        case .disconnecting: return .disconnecting
        case .reasserting:   return .connecting
        default:             return .disconnected
        }
    }

    var isActive: Bool {
        self == .connected || self == .connecting || self == .disconnecting || self == .reconnecting
    }
    var canDisconnect: Bool {
        if case .disconnected = self { return false }; return true
    }

    var label: String {
        switch self {
        case .disconnected:   return "Disconnected"
        case .connecting:     return "Connecting…"
        case .connected:      return "Connected"
        case .disconnecting:  return "Disconnecting…"
        case .reconnecting:   return "Reconnecting…"
        case .failed(let m):  return "Failed: \(m)"
        }
    }
    var color: String {
        switch self {
        case .connected:                                      return "green"
        case .connecting,.disconnecting,.reconnecting:        return "yellow"
        case .failed:                                         return "red"
        case .disconnected:                                   return "secondary"
        }
    }
}

// Sent by backends when the VPN server requires a second authentication factor.
struct MFAChallenge {
    let prompt: String
}

// MARK: – Protocol every backend must satisfy

protocol VPNBackend: AnyObject {
    var statusPublisher:       AnyPublisher<ConnectionStatus, Never> { get }
    /// Emits a non-nil MFAChallenge when the server requires a second factor; nil when resolved.
    var mfaChallengePublisher: AnyPublisher<MFAChallenge?, Never>    { get }
    var ssoChallengePublisher: AnyPublisher<SSOLoginRequest?, Never> { get }

    func connect(profile: VPNProfile) async throws
    func disconnect()
    /// Called by the UI when the user submits an MFA code.
    func submitMFA(code: String)
    /// Called once the SSO browser flow captures a token (or nil if cancelled).
    func submitSSO(token: String?)
    /// Persist profile into backend-specific storage (NE → system prefs).
    func saveProfile(profile: VPNProfile) async throws
}
