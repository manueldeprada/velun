import Foundation
import NetworkExtension
import Combine
import AppKit
import OSLog

private let log = Logger(subsystem: "com.manueldeprada.velun", category: "UnifiedNEController")

@MainActor
final class UnifiedNEController {
    static let shared = UnifiedNEController()
    private init() {}

    private static let extensionBundleID = "com.manueldeprada.velun.PacketTunnel"
    private static let managerDescription = "velun"
    private static let unifiedMarker = "unified"

    private var manager: NETunnelProviderManager?

    // Per-profile published status, derived from the status poll.
    private var subjects: [UUID: CurrentValueSubject<ConnectionStatus, Never>] = [:]
    private var lastStatus: [UUID: ConnectionStatus] = [:]

    private var mfaSubjects: [UUID: CurrentValueSubject<MFAChallenge?, Never>] = [:]

    private var ssoSubjects: [UUID: CurrentValueSubject<SSOLoginRequest?, Never>] = [:]

    // Profiles we've sent addUpstream for and not yet removeUpstream'd.
    private var activeProfiles: [UUID: VPNProfile] = [:]
    private var activationsInFlight = 0
    private var pollTask: Task<Void, Never>?

    // Shared-tunnel death watch (see handleTunnelStatusChange).
    private var connectionObserver: NSObjectProtocol?
    private var lastConnStatus: NEVPNStatus = .invalid
    private var restartingForRegime = false
    private var bringUpDepth = 0

    private static var sysExtActivated = false

    // MARK: – Per-profile status publisher

    func statusPublisher(for id: UUID) -> AnyPublisher<ConnectionStatus, Never> {
        subject(for: id).removeDuplicates().eraseToAnyPublisher()
    }

    private func subject(for id: UUID) -> CurrentValueSubject<ConnectionStatus, Never> {
        if let s = subjects[id] { return s }
        let s = CurrentValueSubject<ConnectionStatus, Never>(.disconnected)
        subjects[id] = s
        return s
    }

    private func emit(_ id: UUID, _ status: ConnectionStatus) {
        if lastStatus[id] == status { return }
        lastStatus[id] = status
        subject(for: id).send(status)
    }

    // MARK: – Per-profile MFA challenge publisher

    func mfaChallengePublisher(for id: UUID) -> AnyPublisher<MFAChallenge?, Never> {
        mfaSubject(for: id).eraseToAnyPublisher()
    }

    private func mfaSubject(for id: UUID) -> CurrentValueSubject<MFAChallenge?, Never> {
        if let s = mfaSubjects[id] { return s }
        let s = CurrentValueSubject<MFAChallenge?, Never>(nil)
        mfaSubjects[id] = s
        return s
    }

    /// Send a user-typed second-factor code to the parked auth in the extension.
    func submitMFA(_ id: UUID, code: String) {
        mfaSubject(for: id).send(nil)   // clear the prompt locally right away
        Task { _ = try? await send(UnifiedIPC.SubmitMFA(profileID: id.uuidString, code: code)) }
    }

    // MARK: – Per-profile SSO challenge publisher

    func ssoChallengePublisher(for id: UUID) -> AnyPublisher<SSOLoginRequest?, Never> {
        ssoSubject(for: id).eraseToAnyPublisher()
    }

    private func ssoSubject(for id: UUID) -> CurrentValueSubject<SSOLoginRequest?, Never> {
        if let s = ssoSubjects[id] { return s }
        let s = CurrentValueSubject<SSOLoginRequest?, Never>(nil)
        ssoSubjects[id] = s
        return s
    }

    func submitSSO(_ id: UUID, token: String?) {
        ssoSubject(for: id).send(nil)   // clear the challenge locally right away
        Task { _ = try? await send(UnifiedIPC.SubmitSSO(profileID: id.uuidString, token: token ?? "")) }
    }

    func isConnected(_ id: UUID) -> Bool { lastStatus[id] == .connected }
    func isTrulyDisconnected(_ id: UUID) -> Bool { (lastStatus[id] ?? .disconnected) == .disconnected }

    // MARK: – Activate / deactivate a logical tunnel

    func activate(_ profile: VPNProfile) async throws {
        try await ensureSysext()
        try await ensureManager()
        guard manager != nil else {
            throw NEBackendError.noProfile("Failed to register VPN configuration.")
        }
        activationsInFlight += 1
        defer { activationsInFlight -= 1 }
        activeProfiles[profile.id] = profile
        liveRoutingMode[profile.id] = nil   // a fresh connect uses the profile's own mode
        emit(profile.id, .connecting)

        do {
            try await reconcileRegimeAndStartSerialized()
            let cfg = sharedConfig(from: profile)
            lastAuthAt[profile.id] = Date()
            let resp = try await send(UnifiedIPC.AddUpstream(config: cfg))
            if let s = resp.flatMap({ String(data: $0, encoding: .utf8) }), s.hasPrefix("err:") {
                throw NEBackendError.noProfile(String(s.dropFirst(4)))
            }
        } catch {
            activeProfiles.removeValue(forKey: profile.id)
            emit(profile.id, .failed(error.localizedDescription))
            stopTunnelIfIdle(ignoringInFlight: 1)   // discount this activation; it is over
            throw error
        }
        startPolling()
    }

    func deactivate(_ id: UUID) {
        activeProfiles.removeValue(forKey: id)
        liveRoutingMode[id] = nil
        mfaSubject(for: id).send(nil)   // drop any pending MFA prompt
        emit(id, .disconnecting)
        Task {
            _ = try? await send(UnifiedIPC.removeUpstream(id.uuidString))
            emit(id, .disconnected)
            stopTunnelIfIdle()
            clearKillSwitchIfStranded()
        }
    }

    // MARK: – Live routing hot-switch + applied routes

    func setRoutingLive(_ id: UUID, mode: PartialTunnelMode, manualRoutes: String) async throws {
        let req = UnifiedIPC.SetRouting(profileID: id.uuidString,
                                        partialMode: mode.rawValue, manualRoutes: manualRoutes)
        let resp = try await send(req)
        let s = resp.flatMap { String(data: $0, encoding: .utf8) } ?? "no response"
        guard s == UnifiedIPC.ok else { throw NEBackendError.noProfile("setRouting: \(s)") }
        liveRoutingMode[id] = (mode, manualRoutes)
        clearKillSwitchIfStranded()
    }

    private func clearKillSwitchIfStranded() {
        guard isTunnelRunning, appliedKillSwitch, !desiredKillSwitch(),
              !activeProfiles.isEmpty else { return }
        log.notice("kill switch applied with no full tunnel left; restarting to clear it (all traffic would otherwise be blocked)")
        Task { [weak self] in
            do { try await self?.applyKillSwitchRegimeNow() }
            catch { log.error("clearing stranded kill switch failed: \(error.localizedDescription, privacy: .public)") }
        }
    }

    func setDomainRoutes(_ id: UUID, cidrs: [String]) async throws {
        let req = UnifiedIPC.SetDomainRoutes(profileID: id.uuidString, cidrs: cidrs)
        let resp = try await send(req)
        let s = resp.flatMap { String(data: $0, encoding: .utf8) } ?? "no response"
        guard s == UnifiedIPC.ok else { throw NEBackendError.noProfile("setDomainRoutes: \(s)") }
    }

    func fetchAppliedRoutes(_ id: UUID) async -> AppliedRoutesReport? {
        // `try?` flattens the Data? result, so this binds to non-nil Data only.
        guard let data = try? await send(UnifiedIPC.appliedRoutes(id.uuidString)) else { return nil }
        return try? JSONDecoder().decode(AppliedRoutesReport.self, from: data)
    }

    func fetchStats(_ id: UUID) async -> (sent: UInt64, rcvd: UInt64)? {
        guard let data = try? await send(UnifiedIPC.StatsRequest()),
              let reply = UnifiedIPC.decode(UnifiedIPC.StatsReply.self, from: data),
              let v = reply.stats[id.uuidString], v.count == 2 else { return nil }
        return (v[0], v[1])
    }

    // MARK: – Save (System Settings entry / kill-switch regime)

    func saveProfile(_ profile: VPNProfile) async throws {
        try await ensureSysext()
        try await ensureManager()
        if activeProfiles[profile.id] != nil { activeProfiles[profile.id] = profile }
    }

    // MARK: – Manager lifecycle + stale-config cleanup

    private func ensureManager() async throws {
        if manager != nil { return }
        let all = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        var unified: NETunnelProviderManager?
        var stale: [NETunnelProviderManager] = []
        for m in all {
            guard let proto = m.protocolConfiguration as? NETunnelProviderProtocol,
                  proto.providerBundleIdentifier == Self.extensionBundleID else { continue }
            let isUnified = (proto.providerConfiguration?[Self.unifiedMarker] as? String) == "1"
            if isUnified, unified == nil { unified = m } else { stale.append(m) }
        }
        for m in stale {
            log.notice("removing stale velun VPN config: \(m.localizedDescription ?? "?", privacy: .public)")
            try? await m.removeFromPreferences()
        }

        if let unified {
            manager = unified
            installConnectionObserver()
            return
        }
        let m = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.extensionBundleID
        proto.serverAddress = "velun"
        proto.providerConfiguration = [Self.unifiedMarker: "1"]
        m.protocolConfiguration = proto
        m.localizedDescription = Self.managerDescription
        m.isEnabled = true
        NotificationCenter.default.post(name: .velunDismissPopover, object: nil)
        try await m.saveToPreferences()
        try await m.loadFromPreferences()
        manager = m
        installConnectionObserver()
    }

    // MARK: – Shared-tunnel death watch

    private func installConnectionObserver() {
        guard connectionObserver == nil else { return }
        lastConnStatus = manager?.connection.status ?? .invalid
        connectionObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: nil, queue: .main
        ) { [weak self] note in
            MainActor.assumeIsolated {
                guard let self, let conn = note.object as? NEVPNConnection,
                      conn === self.manager?.connection else { return }
                self.handleTunnelStatusChange(conn.status)
            }
        }
    }

    private func handleTunnelStatusChange(_ status: NEVPNStatus) {
        let previous = lastConnStatus
        lastConnStatus = status
        guard status == .disconnected || status == .invalid else { return }
        guard previous == .connected || previous == .reasserting || previous == .disconnecting else { return }
        guard !activeProfiles.isEmpty else { return }
        guard !restartingForRegime, bringUpDepth == 0 else { return }   // our own doing, not a death
        log.error("shared tunnel stopped with \(self.activeProfiles.count, privacy: .public) active profile(s) — marking them failed")
        for id in activeProfiles.keys {
            emit(id, .failed("The VPN tunnel stopped unexpectedly."))
        }
        activeProfiles.removeAll()
        stopPolling()
    }

    private var reconciling = false

    private func reconcileRegimeAndStartSerialized() async throws {
        let deadline = Date().addingTimeInterval(30)
        while reconciling, Date() < deadline {
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        reconciling = true
        defer { reconciling = false }
        try await reconcileRegimeAndStart()
    }

    private static func isStaleConfiguration(_ error: Error) -> Bool {
        let e = error as NSError
        return e.domain == NEVPNErrorDomain && e.code == NEVPNError.configurationStale.rawValue
    }

    private func reconcileRegimeAndStart() async throws {
        guard let manager else { return }
        bringUpDepth += 1
        defer { bringUpDepth -= 1 }
        let desired = desiredKillSwitch()

        await waitWhileDisconnecting()

        let status = manager.connection.status
        if status == .disconnected || status == .invalid {
            if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
               proto.includeAllNetworks != desired {
                proto.includeAllNetworks = desired
                proto.excludeLocalNetworks = desired
                manager.protocolConfiguration = proto
                manager.isEnabled = true
                NotificationCenter.default.post(name: .velunDismissPopover, object: nil)
                try await manager.saveToPreferences()
                try await manager.loadFromPreferences()
            }
            try await startTunnelAndWait(manager, timeout: 25)
            return
        } else if (manager.protocolConfiguration as? NETunnelProviderProtocol)?.includeAllNetworks != desired {
            log.notice("kill-switch regime change pending; needs a shared-tunnel restart to apply")
        }
        try await waitForConnected(timeout: 25)
    }

    private func startTunnelAndWait(_ manager: NETunnelProviderManager,
                                    timeout: TimeInterval) async throws {
        for attempt in 0..<2 {
            do { try manager.connection.startVPNTunnel() }
            catch {
                if Self.isStaleConfiguration(error) {
                    log.notice("stale configuration on start; reloading preferences and retrying")
                    try await manager.loadFromPreferences()
                    try manager.connection.startVPNTunnel()
                } else if manager.connection.status == .disconnected {
                    // Already starting/connected is fine; anything else propagates.
                    throw error
                }
            }

            do {
                try await waitForConnected(timeout: timeout)
                return
            } catch {
                let status = manager.connection.status
                let neverStarted = (status == .disconnected || status == .invalid)
                guard attempt == 0, neverStarted else { throw error }
                log.notice("tunnel start appears to have been dropped; reloading preferences and retrying once")
                try? await manager.loadFromPreferences()
                await waitWhileDisconnecting()
            }
        }
    }

    private func desiredKillSwitch() -> Bool {
        Self.killSwitchPreference && activeProfiles.contains { effectiveMode($0.key, $0.value) == .full }
    }

    static let killSwitchKey = "velun.killSwitch"

    static var killSwitchPreference: Bool {
        UserDefaults.standard.object(forKey: killSwitchKey) as? Bool ?? false
    }

    var appliedKillSwitch: Bool {
        guard let proto = manager?.protocolConfiguration as? NETunnelProviderProtocol else { return false }
        return proto.includeAllNetworks
    }

    var isTunnelRunning: Bool {
        guard let s = manager?.connection.status else { return false }
        return s == .connected || s == .connecting || s == .reasserting
    }

    var isKillSwitchPending: Bool {
        isTunnelRunning && !activeProfiles.isEmpty && appliedKillSwitch != desiredKillSwitch()
    }

    var isKillSwitchInForce: Bool {
        guard appliedKillSwitch, isTunnelRunning else { return false }
        return activeProfiles.contains { id, profile in
            effectiveMode(id, profile) == .full && lastStatus[id] == .connected
        }
    }

    private func stopTunnelIfIdle(ignoringInFlight: Int = 0) {
        guard activeProfiles.isEmpty else { return }
        guard activationsInFlight - ignoringInFlight <= 0 else { return }
        manager?.connection.stopVPNTunnel()
        stopPolling()
    }

    private static let totpStep: TimeInterval = 30

    /// Seconds until `lastAuth`'s TOTP step expires, or 0 if it already has.
    private static func secondsUntilFreshTOTP(after lastAuth: Date,
                                              now: Date = Date()) -> TimeInterval {
        let step = totpStep
        let lastStep = (lastAuth.timeIntervalSince1970 / step).rounded(.down)
        let nowStep = (now.timeIntervalSince1970 / step).rounded(.down)
        guard lastStep == nowStep else { return 0 }
        // +0.5 s so we land inside the next step rather than exactly on its edge.
        return ((nowStep + 1) * step) - now.timeIntervalSince1970 + 0.5
    }

    private var lastAuthAt: [UUID: Date] = [:]

    /// Does this profile authenticate with a TOTP code? Only those can replay one.
    private func usesTOTP(_ profile: VPNProfile) -> Bool {
        if case .sslVPN(let c) = profile.config { return !c.totpSecret.isEmpty }
        return false
    }

    /// Park until every profile about to re-authenticate has a fresh code.
    private func awaitFreshTOTP(for profiles: [UUID: VPNProfile]) async {
        let waits = profiles.compactMap { id, profile -> TimeInterval? in
            guard usesTOTP(profile), let last = lastAuthAt[id] else { return nil }
            let w = Self.secondsUntilFreshTOTP(after: last)
            return w > 0 ? w : nil
        }
        guard let longest = waits.max() else { return }
        log.notice("waiting \(String(format: "%.1f", longest), privacy: .public)s for the one-time code to rotate before re-auth")
        try? await Task.sleep(nanoseconds: UInt64(longest * 1_000_000_000))
    }

    func applyKillSwitchRegimeNow() async throws {
        guard let manager, isKillSwitchPending else { return }
        let toReadd = activeProfiles
        log.notice("applying kill-switch regime → restarting shared tunnel with \(toReadd.count, privacy: .public) upstream(s)")

        restartingForRegime = true
        defer { restartingForRegime = false }

        for id in toReadd.keys { emit(id, .reconnecting) }
        manager.connection.stopVPNTunnel()
        await waitForDisconnected()
        try await reconcileRegimeAndStartSerialized()

        await awaitFreshTOTP(for: toReadd)

        for (id, profile) in toReadd {
            do {
                lastAuthAt[id] = Date()
                let resp = try await send(UnifiedIPC.AddUpstream(config: sharedConfig(from: profile)))
                if let s = resp.flatMap({ String(data: $0, encoding: .utf8) }), s.hasPrefix("err:") {
                    throw NEBackendError.noProfile(String(s.dropFirst(4)))
                }
            } catch {
                activeProfiles.removeValue(forKey: id)
                emit(id, .failed(error.localizedDescription))
            }
        }
        stopTunnelIfIdle()
        startPolling()
    }

    private func waitForConnected(timeout: TimeInterval) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        var sawStarting = false
        var disconnectedTicks = 0
        while Date() < deadline {
            switch manager?.connection.status {
            case .connected:
                return
            case .connecting, .reasserting:
                sawStarting = true
                disconnectedTicks = 0
            case .disconnected, .invalid, .none:
                disconnectedTicks += 1
                if sawStarting || disconnectedTicks >= 15 {
                    throw NEBackendError.noProfile("The VPN tunnel failed to start.")
                }
            default:
                break   // .disconnecting — a previous stop still settling
            }
            try? await Task.sleep(nanoseconds: 200_000_000)
        }
        guard manager?.connection.status == .connected else {
            throw NEBackendError.noProfile("Tunnel did not come up in time")
        }
    }

    private func waitWhileDisconnecting() async {
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline, manager?.connection.status == .disconnecting {
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
    }

    private func waitForDisconnected(timeout: TimeInterval = 12) async {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            switch manager?.connection.status {
            case .disconnected, .invalid, .none: return
            default: try? await Task.sleep(nanoseconds: 100_000_000)
            }
        }
        log.error("tunnel did not reach .disconnected within \(Int(timeout), privacy: .public)s")
    }

    // MARK: – Status polling

    private func startPolling() {
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                if Task.isCancelled { return }
                await self?.pollStatusOnce()
            }
        }
    }

    private func stopPolling() {
        pollTask?.cancel(); pollTask = nil
    }

    private func pollStatusOnce() async {
        if activeProfiles.isEmpty { stopPolling(); return }
        if restartingForRegime { return }
        guard manager?.connection.status == .connected else { return }
        guard let data = try? await send(UnifiedIPC.StatusRequest()),
              let reply = UnifiedIPC.decode(UnifiedIPC.StatusReply.self, from: data) else { return }

        for id in activeProfiles.keys {
            let state = reply.statuses[id.uuidString].flatMap(UnifiedIPC.UpstreamState.init(rawValue:))
            // Clear any showing MFA prompt the moment we leave the needsMFA state.
            if state != .needsMFA, mfaSubjects[id]?.value != nil { mfaSubject(for: id).send(nil) }
            // Same for an SSO challenge once we leave needsSSO.
            if state != .needsSSO, ssoSubjects[id]?.value != nil { ssoSubject(for: id).send(nil) }
            switch state {
            case .connected:    emit(id, .connected)
            case .connecting:   emit(id, .connecting)
            case .reconnecting: emit(id, .reconnecting)
            case .needsMFA:
                emit(id, .connecting)
                if mfaSubject(for: id).value == nil {
                    var prompt = "Enter your verification code"
                    if let d = try? await send(UnifiedIPC.mfaPrompt(id.uuidString)),
                       let s = String(data: d, encoding: .utf8), !s.isEmpty { prompt = s }
                    mfaSubject(for: id).send(MFAChallenge(prompt: prompt))
                }
            case .needsSSO:
                emit(id, .connecting)
                if ssoSubject(for: id).value == nil,
                   let d = try? await send(UnifiedIPC.ssoRequest(id.uuidString)),
                   let req = UnifiedIPC.decode(SSOLoginRequest.self, from: d) {
                    ssoSubject(for: id).send(req)
                }
            case .failed:
                var msg = "Connection failed"
                if let d = try? await send(UnifiedIPC.lastError(id.uuidString)),
                   let s = String(data: d, encoding: .utf8), !s.isEmpty { msg = s }
                emit(id, .failed(msg))
            case .disconnected, .none:
                emit(id, .disconnected)
            }
        }
    }

    // MARK: – Helpers

    private func sharedConfig(from profile: VPNProfile) -> SharedTunnelConfig {
        var c = SharedTunnelConfig()
        c.profileID    = profile.id.uuidString
        c.providerType = profile.provider.rawValue
        c.userAgent    = profile.provider.userAgent
        let (mode, manual) = liveRoutingMode[profile.id]
            .map { ($0.mode, $0.manualRoutes) } ?? routingMode(for: profile)
        c.partialMode  = mode
        c.manualRoutes = manual
        c.dtlsEnabled  = UserDefaults.standard.object(forKey: "velun.dtlsEnabled") as? Bool ?? true
        switch profile.config {
        case .sslVPN(let oc):
            c.host = oc.host; c.port = oc.port; c.username = oc.username
            c.password = oc.password; c.group = oc.group; c.totpSecret = oc.totpSecret
            c.clientCertP12 = oc.clientCertP12; c.clientCertPassword = oc.clientCertPassword
        case .wireguard(let wg):
            c.wgConf = wg.confText
        }
        return c
    }

    private func routingMode(for profile: VPNProfile) -> (PartialTunnelMode, String) {
        guard profile.config.partialEnabled else { return (.full, "") }
        let trimmed = profile.config.splitRoutes.trimmingCharacters(in: .whitespacesAndNewlines)
        return (trimmed.isEmpty ? .partialAuto : .partialManual, trimmed)
    }

    private var liveRoutingMode: [UUID: (mode: PartialTunnelMode, manualRoutes: String)] = [:]

    private func effectiveMode(_ id: UUID, _ profile: VPNProfile) -> PartialTunnelMode {
        liveRoutingMode[id]?.mode ?? routingMode(for: profile).0
    }

    private func send<T: Encodable>(_ message: T, timeout: TimeInterval = 10) async throws -> Data? {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            throw NEBackendError.noProfile("No active tunnel session")
        }
        guard let data = UnifiedIPC.encode(message) else {
            throw NEBackendError.noProfile("IPC encode failed")
        }
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data?, Error>) in
            let once = ResumeOnce<Data?>(cont)
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                once.resume(throwing: NEBackendError.noProfile("The VPN extension did not respond."))
            }
            do { try session.sendProviderMessage(data) { once.resume(returning: $0) } }
            catch { once.resume(throwing: error) }
        }
    }

    // MARK: – System extension activation (same flow as the old NE backend)

    private func ensureSysext() async throws {
        if Self.sysExtActivated { return }

        let bundlePath = Bundle.main.bundlePath
        if !bundlePath.hasPrefix("/Applications/") {
            throw NEBackendError.noProfile(
                "velun must be installed in /Applications to load its VPN " +
                "system extension. It's currently running from:\n\n\(bundlePath)\n\n" +
                "Quit velun, drag velun.app into your /Applications folder, " +
                "and launch it from there.")
        }

        let result: SystemExtensionInstaller.Result = await withCheckedContinuation { cont in
            SystemExtensionInstaller.shared.activate { cont.resume(returning: $0) }
        }
        switch result {
        case .completed:
            Self.sysExtActivated = true
        case .needsApproval:
            if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") {
                NSWorkspace.shared.open(url)
            }
            throw NEBackendError.noProfile(
                "velun needs your approval to install its network extension.\n\n" +
                "Open System Settings → General → Login Items & Extensions. " +
                "Scroll down to the \"Extensions\" section, click the ⓘ next to " +
                "\"Network Extensions\" (the category — not the apps list above), " +
                "turn on velun, then click Done.\n\n" +
                "Then click Connect again here. If you dismissed the macOS " +
                "prompt, clicking Connect simply re-requests it.\n\n" +
                "If velun never appears in that list, a previous denial may be " +
                "cached: run `systemextensionsctl reset` in Terminal and retry.")
        case .failed(let msg):
            throw NEBackendError.noProfile("System extension install failed: \(msg)")
        }
    }
}
