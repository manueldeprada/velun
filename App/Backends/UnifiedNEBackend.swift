import Foundation
import Combine

enum NEBackendError: LocalizedError {
    case noProfile(String)
    var errorDescription: String? {
        switch self { case .noProfile(let m): return m }
    }
}

protocol NEControllable: AnyObject {
    var isConnected: Bool { get }
    var isTrulyDisconnected: Bool { get }
    func setRoutingLive(mode: PartialTunnelMode, manualRoutes: String) async throws
    func setDomainRoutes(_ cidrs: [String]) async throws
    func fetchAppliedRoutes() async -> AppliedRoutesReport?
    /// Per-tunnel byte counters (cumulative since connect), or nil if unavailable.
    func fetchStats() async -> (sent: UInt64, rcvd: UInt64)?
}

final class UnifiedNEBackendProxy: VPNBackend, NEControllable {

    private let profileID: UUID
    private let _statusPublisher: AnyPublisher<ConnectionStatus, Never>
    private let _mfaPublisher: AnyPublisher<MFAChallenge?, Never>
    private let _ssoPublisher: AnyPublisher<SSOLoginRequest?, Never>

    @MainActor
    init(profileID: UUID) {
        self.profileID = profileID
        self._statusPublisher = UnifiedNEController.shared.statusPublisher(for: profileID)
        self._mfaPublisher = UnifiedNEController.shared.mfaChallengePublisher(for: profileID)
        self._ssoPublisher = UnifiedNEController.shared.ssoChallengePublisher(for: profileID)
    }

    // VPNBackend
    var statusPublisher: AnyPublisher<ConnectionStatus, Never> { _statusPublisher }
    var mfaChallengePublisher: AnyPublisher<MFAChallenge?, Never> { _mfaPublisher }
    var ssoChallengePublisher: AnyPublisher<SSOLoginRequest?, Never> { _ssoPublisher }

    func connect(profile: VPNProfile) async throws {
        try await UnifiedNEController.shared.activate(profile)
    }
    func disconnect() {
        let id = profileID
        Task { @MainActor in UnifiedNEController.shared.deactivate(id) }
    }
    func submitMFA(code: String) {
        let id = profileID
        Task { @MainActor in UnifiedNEController.shared.submitMFA(id, code: code) }
    }
    func submitSSO(token: String?) {
        let id = profileID
        Task { @MainActor in UnifiedNEController.shared.submitSSO(id, token: token) }
    }
    func saveProfile(profile: VPNProfile) async throws {
        try await UnifiedNEController.shared.saveProfile(profile)
    }

    // NEControllable — sync probes; callers are always on the main actor.
    var isConnected: Bool {
        MainActor.assumeIsolated { UnifiedNEController.shared.isConnected(profileID) }
    }
    var isTrulyDisconnected: Bool {
        MainActor.assumeIsolated { UnifiedNEController.shared.isTrulyDisconnected(profileID) }
    }
    func setRoutingLive(mode: PartialTunnelMode, manualRoutes: String) async throws {
        try await UnifiedNEController.shared.setRoutingLive(profileID, mode: mode, manualRoutes: manualRoutes)
    }
    func setDomainRoutes(_ cidrs: [String]) async throws {
        try await UnifiedNEController.shared.setDomainRoutes(profileID, cidrs: cidrs)
    }
    func fetchAppliedRoutes() async -> AppliedRoutesReport? {
        await UnifiedNEController.shared.fetchAppliedRoutes(profileID)
    }
    func fetchStats() async -> (sent: UInt64, rcvd: UInt64)? {
        await UnifiedNEController.shared.fetchStats(profileID)
    }
}
