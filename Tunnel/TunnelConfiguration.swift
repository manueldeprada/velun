import Foundation
import Security

// Shared between App and Tunnel extension targets.

// MARK: – ResumeOnce

final class ResumeOnce<T> {
    private let lock = NSLock()
    private var done = false
    private let cont: CheckedContinuation<T, Error>

    init(_ cont: CheckedContinuation<T, Error>) {
        self.cont = cont
    }

    func resume(returning value: T) {
        lock.lock(); defer { lock.unlock() }
        guard !done else { return }
        done = true
        cont.resume(returning: value)
    }

    func resume(throwing error: Error) {
        lock.lock(); defer { lock.unlock() }
        guard !done else { return }
        done = true
        cont.resume(throwing: error)
    }
}

extension ResumeOnce where T == Void {
    func resume() { resume(returning: ()) }
}

// MARK: – withTimeout

struct TimeoutError: Error, LocalizedError {
    var errorDescription: String? { "timed out" }
}

enum TimeoutBranch<T: Sendable>: Sendable {
    case completed(Result<T, Error>)
    case timeout
}

func withTimeout<T: Sendable>(seconds: TimeInterval,
                              onTimeout: @Sendable () -> Void = {},
                              operation: @escaping @Sendable () async throws -> T) async throws -> T {
    let outcome: TimeoutBranch<T> = await withTaskGroup(of: TimeoutBranch<T>.self) { group in
        group.addTask {
            do { return .completed(.success(try await operation())) }
            catch { return .completed(.failure(error)) }
        }
        group.addTask {
            try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            return .timeout
        }
        guard let first = await group.next() else { return .timeout }
        switch first {
        case .timeout:
            onTimeout()
            group.cancelAll()
            _ = await group.next()
        case .completed:
            group.cancelAll()
        }
        return first
    }
    switch outcome {
    case .completed(.success(let v)): return v
    case .completed(.failure(let e)): throw e
    case .timeout:                    throw TimeoutError()
    }
}

// MARK: – Provider type

enum ProviderType: String, CaseIterable, Identifiable, Codable {
    case anyConnect    = "anyconnect"
    case wireguard     = "wireguard"
    case globalProtect = "globalprotect"
    case fortinet      = "fortinet"

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .anyConnect:    return "AnyConnect"
        case .wireguard:     return "WireGuard"
        case .globalProtect: return "GlobalProtect"
        case .fortinet:      return "Fortinet"
        }
    }

    var userAgent: String {
        switch self {
        case .anyConnect:    return "AnyConnect"
        case .wireguard:     return "velun-WireGuard"
        case .globalProtect: return "PAN GlobalProtect"
        case .fortinet:      return "Open Fortinet Client"
        }
    }

}

let velunKeychainAccessGroup = "PAJ4L89MD3.com.manueldeprada.velun.shared"

@inline(__always)
func velunKeychainBaseQuery(service: String, account: String) -> [CFString: Any] {
    [kSecClass:                       kSecClassGenericPassword,
     kSecAttrService:                 service,
     kSecAttrAccount:                 account,
     kSecAttrAccessGroup:             velunKeychainAccessGroup,
     kSecUseDataProtectionKeychain:   true]
}

// MARK: – Partial-tunnel intent

enum PartialTunnelMode: String, Codable, Equatable {
    case full
    case partialAuto
    case partialManual
}

// MARK: – SharedTunnelConfig

struct SharedTunnelConfig: Codable, Equatable {
    var profileID:    String = ""
    var providerType: String = "anyconnect"

    // SSL VPN family
    var host:        String = ""
    var port:        Int    = 443
    var username:    String = ""
    var password:    String = ""
    var group:       String = ""
    var totpSecret:  String = ""
    var userAgent:   String = "AnyConnect"

    // WireGuard
    var wgConf:      String = ""

    var clientCertP12:      String = ""
    var clientCertPassword: String = ""

    // Routing
    var partialMode:  PartialTunnelMode = .full
    var manualRoutes: String = ""    // space-/comma-separated CIDRs

    var dtlsEnabled: Bool = true
}

struct SSOLoginRequest: Codable, Equatable {
    var loginURL: String
    var finalURL: String
    var tokenCookieName: String
    var errorCookieName: String
    var tokenFieldName: String
}

struct TunnelNetworkConfig {
    var ipAddress:     String
    var netmask:       String
    var gateway:       String
    var dnsServers:    [String]
    var searchDomains: [String]
    var mtu:           Int
    var splitIncludes: [String]
    var splitExcludes: [String]

    var ipv6Address:       String   = ""
    var ipv6PrefixLength:  Int      = 0
    var ipv6SplitIncludes: [String] = []
}

// MARK: – SSL-VPN-family tunnel abstraction

protocol SSLVPNFamilyTunnel: AnyObject {
    func connect(config: SharedTunnelConfig) async throws -> TunnelNetworkConfig
    func disconnect()
    func readDataPacket()  async throws -> Data?
    func writeDataPacket(_ data: Data) async throws

    var supportsSeamlessReconnect: Bool { get }

    func reconnectTransport() async throws

    func abortTransport()

    var secondsSinceLastInbound: TimeInterval? { get }
}

extension SSLVPNFamilyTunnel {
    var supportsSeamlessReconnect: Bool { false }
    func reconnectTransport() async throws {
        throw NSError(domain: "velun", code: 1, userInfo: [
            NSLocalizedDescriptionKey: "Seamless reconnect not supported by this protocol"
        ])
    }
    func abortTransport() {}
    var secondsSinceLastInbound: TimeInterval? { nil }
}

// MARK: – Applied-routes report

struct AppliedRoutesReport: Codable, Equatable {
    enum Source: String, Codable { case full, server, auto, manual }
    var source: Source
    var routes: [String]    // CIDR list actually installed in the tunnel
    var explanation: String // user-readable note shown in the UI
    var warning: Bool = false
    var routeConflictWarning: String? = nil
    var assignedIP: String = ""
    var dnsSuffixes: [String] = []
    var ipv6Routes: [String] = []
    var resolvedHostRoutes: [String] = []
    var dnsLearnedRoutes: [String] = []
}

