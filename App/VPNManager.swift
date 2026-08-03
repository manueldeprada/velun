import Foundation
import Combine
import Darwin
import OSLog

struct TransferStats: Equatable {
    var bytesSent:     UInt64
    var bytesReceived: UInt64
    var startTime:     Date
}

private let logger = Logger(subsystem: "com.manueldeprada.velun", category: "VPNManager")

@MainActor
class VPNManager: ObservableObject {
    static let shared = VPNManager()

    @Published var profiles:            [VPNProfile]                  = []
    @Published var statuses:            [UUID: ConnectionStatus]      = [:]
    @Published var errors:              [UUID: String]                = [:]
    @Published var fullTunnelOverrides: Set<UUID>                     = []
    @Published var mfaChallenges:       [UUID: MFAChallenge]          = [:]
    @Published var ssoChallenges:       [UUID: SSOLoginRequest]       = [:]
    @Published var appliedRoutes:       [UUID: AppliedRoutesReport]   = [:]
    @Published var sessionStats:        [UUID: TransferStats]          = [:]

    @Published var systemImportNotice: Int? = nil

    @Published var autoreconnectEnabled: Bool {
        didSet { UserDefaults.standard.set(autoreconnectEnabled, forKey: Self.autoreconnectKey) }
    }
    @Published var autoReconnectOnNetworkRestore: Bool {
        didSet { UserDefaults.standard.set(autoReconnectOnNetworkRestore, forKey: Self.autoReconnectOnNetworkKey) }
    }
    @Published var dtlsEnabled: Bool {
        didSet { UserDefaults.standard.set(dtlsEnabled, forKey: Self.dtlsEnabledKey) }
    }
    @Published var killSwitchEnabled: Bool {
        didSet {
            UserDefaults.standard.set(killSwitchEnabled, forKey: UnifiedNEController.killSwitchKey)
            refreshKillSwitchState()
        }
    }
    @Published private(set) var killSwitchActive = false
    @Published private(set) var killSwitchPending = false
    @Published private(set) var ipv6RoutedViaTunnel = false
    private static let autoreconnectKey      = "velun.autoreconnect"
    private static let autoReconnectOnNetworkKey = "velun.autoReconnectOnNetwork"
    private static let dtlsEnabledKey        = "velun.dtlsEnabled"
    private static let lastConnectedKey      = "velun.lastConnectedIDs"
    private static let hasEverConnectedKey   = "velun.hasEverConnected"
    private static let didAttemptSystemImportKey = "velun.didAttemptSystemImport"

    private var explicitDisconnects: Set<UUID> = []
    private var userActionAt: [UUID: Date] = [:]
    private static let userActionQuietWindow: TimeInterval = 10.0
    private func isInUserActionWindow(_ id: UUID) -> Bool {
        guard let at = userActionAt[id] else { return false }
        return Date().timeIntervalSince(at) < Self.userActionQuietWindow
    }
    @Published private(set) var connectionLost: Set<UUID> = []
    private var hasBeenConnected: Set<UUID> = []
    private var licenseDeniedDisconnects: Set<UUID> = []
    private var pendingAutoconnect: Set<UUID> = []

    @Published private(set) var keychainLoadFailures: Set<UUID> = []

    private var backends:      [UUID: any VPNBackend]    = [:]
    private var statusTasks:   [UUID: Task<Void, Never>] = [:]
    private var mfaTasks:      [UUID: Task<Void, Never>] = [:]
    private var ssoTasks:      [UUID: Task<Void, Never>] = [:]
    private var monitorTasks:  [UUID: Task<Void, Never>] = [:]
    private var domainRouteTasks: [UUID: Task<Void, Never>] = [:]
    private var lastPushedDomainRoutes: [UUID: [String]] = [:]
    private var reconnectTasks: [UUID: Task<Void, Never>] = [:]
    private var connectsInFlight: Set<UUID> = []

    // MARK: – Profile CRUD

    @Published var newlyAddedProfileID: UUID?

    @Published var newlyImportedProfileID: UUID?

    @discardableResult
    func addProfile() -> VPNProfile {
        let p = VPNProfile()
        profiles.append(p)
        newlyAddedProfileID = p.id
        persist()
        return p
    }

    func removeProfile(_ profile: VPNProfile) {
        disconnect(profile)
        KeychainHelper.delete(for: profile.id)
        fullTunnelOverrides.remove(profile.id)
        backends.removeValue(forKey: profile.id)
        statusTasks[profile.id]?.cancel()
        statusTasks.removeValue(forKey: profile.id)
        mfaTasks[profile.id]?.cancel()
        mfaTasks.removeValue(forKey: profile.id)
        ssoTasks[profile.id]?.cancel()
        ssoTasks.removeValue(forKey: profile.id)
        monitorTasks[profile.id]?.cancel()
        monitorTasks.removeValue(forKey: profile.id)
        domainRouteTasks[profile.id]?.cancel()
        domainRouteTasks.removeValue(forKey: profile.id)
        lastPushedDomainRoutes.removeValue(forKey: profile.id)
        cancelAutoReconnect(profile.id)
        statuses.removeValue(forKey: profile.id)
        errors.removeValue(forKey: profile.id)
        mfaChallenges.removeValue(forKey: profile.id)
        ssoChallenges.removeValue(forKey: profile.id)
        appliedRoutes.removeValue(forKey: profile.id)
        sessionStats.removeValue(forKey: profile.id)
        connectionLost.remove(profile.id)
        hasBeenConnected.remove(profile.id)
        keychainLoadFailures.remove(profile.id)
        profiles.removeAll { $0.id == profile.id }
        persist()
    }

    // MARK: – Export / Import

    func exportBlob(includeCredentials: Bool = false,
                    profiles: [VPNProfile]? = nil) -> String {
        TunnelExport.encodeBlob(profiles ?? self.profiles,
                                includeCredentials: includeCredentials)
    }

    @discardableResult
    func adoptImported(_ incoming: [VPNProfile]) -> [VPNProfile] {
        for p in incoming {
            switch p.config {
            case .sslVPN(let oc):
                if !oc.password.isEmpty   { KeychainHelper.savePassword(oc.password,  for: p.id) }
                if !oc.totpSecret.isEmpty { KeychainHelper.saveTOTP    (oc.totpSecret, for: p.id) }
            case .wireguard(let wg):
                if !wg.confText.isEmpty {
                    KeychainHelper.saveWireGuardConf(wg.confText, for: p.id)
                }
            }
            keychainLoadFailures.remove(p.id)
            profiles.append(p)
        }
        persist()
        if incoming.count == 1 { newlyImportedProfileID = incoming[0].id }
        return incoming
    }

    @discardableResult
    func importBlob(_ text: String) throws -> [VPNProfile] {
        adoptImported(try TunnelExport.decodeBlob(text))
    }

    struct SystemImportResult {
        /// Total connections found on this Mac (before dedup).
        var found: Int
        /// The ones actually added (not already present).
        var added: [VPNProfile]
        /// Found but skipped because the user already has them (host+group match).
        var alreadyPresent: Int { found - added.count }
    }

    @discardableResult
    func importFromSystem() -> SystemImportResult {
        let candidates = SystemProfileImporter.scan()
        let fresh = SystemProfileImporter.profiles(from: candidates, excluding: profiles)
        let added = fresh.isEmpty ? [] : adoptImported(fresh)
        return SystemImportResult(found: candidates.count, added: added)
    }

    func attemptFirstRunSystemImport() {
        let ud = UserDefaults.standard
        guard !ud.bool(forKey: Self.didAttemptSystemImportKey) else { return }
        ud.set(true, forKey: Self.didAttemptSystemImportKey)
        guard profiles.isEmpty else { return }
        let found = SystemProfileImporter.discoverProfiles(excluding: profiles)
        guard !found.isEmpty else { return }
        adoptImported(found)
        systemImportNotice = found.count
        logger.info("first-run system import added \(found.count, privacy: .public) profile(s)")
    }

    func updateProfile(_ profile: VPNProfile) {
        if let idx = profiles.firstIndex(where: { $0.id == profile.id }) {
            profiles[idx] = profile
        }
        if hasNonEmptySecret(profile) {
            keychainLoadFailures.remove(profile.id)
        }
        persist()
    }

    private func hasNonEmptySecret(_ profile: VPNProfile) -> Bool {
        switch profile.config {
        case .sslVPN(let oc): return !oc.password.isEmpty
        case .wireguard  (let wg): return !wg.confText.isEmpty
        }
    }

    // MARK: – Connect / Disconnect

    func connect(_ profile: VPNProfile) {
        guard AboutScreenManager.shared.isAccessGranted else {
            let msg = "Trial ended. Enter a license to reconnect."
            errors[profile.id] = msg
            logger.info("[\(profile.name)] connect blocked: trial expired / no license")
            return
        }
        guard mfaChallenges[profile.id] == nil else {
            logger.info("[\(profile.name)] connect ignored — awaiting MFA verification code")
            return
        }
        guard ssoChallenges[profile.id] == nil else {
            logger.info("[\(profile.name)] connect ignored — awaiting SSO browser login")
            return
        }
        guard !connectsInFlight.contains(profile.id) else {
            logger.info("[\(profile.name)] connect ignored — an attempt is already in flight")
            return
        }
        connectsInFlight.insert(profile.id)
        explicitDisconnects.remove(profile.id)
        userActionAt.removeValue(forKey: profile.id)
        Task {
            defer { connectsInFlight.remove(profile.id) }
            errors[profile.id] = nil
            connectionLost.remove(profile.id)
            appliedRoutes.removeValue(forKey: profile.id)
            monitorTasks[profile.id]?.cancel()
            monitorTasks.removeValue(forKey: profile.id)
            domainRouteTasks[profile.id]?.cancel()
            domainRouteTasks.removeValue(forKey: profile.id)
            sessionStats.removeValue(forKey: profile.id)
            let backend = ensureBackend(for: profile)
            var p = profile
            // Apply session-only full-tunnel override before the backend reads it.
            if fullTunnelOverrides.contains(profile.id) {
                p.config.partialEnabled = false
                p.config.splitRoutes    = ""
            }
            do {
                try await backend.connect(profile: p)
            } catch {
                let msg = error.localizedDescription
                errors[profile.id] = msg
                logger.error("[\(profile.name)] connect failed: \(msg)")
            }
        }
    }

    func disconnect(_ profile: VPNProfile) {
        backends[profile.id]?.disconnect()
    }

    func userDisconnect(_ profile: VPNProfile) {
        logger.info("userDisconnect: [\(profile.name)] explicit=true clearing connectionLost+errors, opening quiet window")
        explicitDisconnects.insert(profile.id)
        connectionLost.remove(profile.id)
        cancelAutoReconnect(profile.id)
        errors[profile.id] = nil
        userActionAt[profile.id] = Date()
        disconnect(profile)
    }

    func dismissConnectionLost(_ profile: VPNProfile) {
        logger.info("dismissConnectionLost: [\(profile.name)] opening quiet window")
        connectionLost.remove(profile.id)
        cancelAutoReconnect(profile.id)
        userActionAt[profile.id] = Date()
    }

    func disconnectAll() {
        for profile in profiles { disconnect(profile) }
    }

    func reconnectAsFull(_ profile: VPNProfile) {
        fullTunnelOverrides.insert(profile.id)
        if tryHotSwitch(profile, mode: .full, manualRoutes: "") { return }
        statuses[profile.id] = .reconnecting
        disconnect(profile)
        Task { await waitThenConnect(profile) }
    }

    // Revert a full-tunnel override back to the profile's saved split routes.
    func reconnectWithSplits(_ profile: VPNProfile) {
        fullTunnelOverrides.remove(profile.id)
        let mode: PartialTunnelMode = profile.config.partialEnabled
            ? (profile.config.splitRoutes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
               ? .partialAuto : .partialManual)
            : .full
        if tryHotSwitch(profile, mode: mode, manualRoutes: profile.config.splitRoutes) { return }
        statuses[profile.id] = .reconnecting
        disconnect(profile)
        Task { await waitThenConnect(profile) }
    }

    // Returns true if the switch was dispatched as a live update.
    private func tryHotSwitch(_ profile: VPNProfile,
                              mode: PartialTunnelMode,
                              manualRoutes: String) -> Bool {
        guard let ne = backends[profile.id] as? NEControllable,
              ne.isConnected else { return false }
        Task {
            do {
                try await ne.setRoutingLive(mode: mode, manualRoutes: manualRoutes)
                fetchAppliedRoutes(for: profile)
                refreshKillSwitchState()
            } catch {
                let msg = error.localizedDescription
                errors[profile.id] = msg
                logger.error("[\(profile.name)] live routing switch failed: \(msg); falling back to reconnect")
                statuses[profile.id] = .reconnecting
                disconnect(profile)
                await waitThenConnect(profile)
            }
        }
        return true
    }

    private func fetchAppliedRoutes(for profile: VPNProfile) {
        let id = profile.id
        guard let ne = backends[id] as? NEControllable else { return }
        Task { [weak self] in
            for delayMS: UInt64 in [50, 150, 300, 600, 1000] {
                try? await Task.sleep(nanoseconds: delayMS * 1_000_000)
                if var r = await ne.fetchAppliedRoutes() {
                    // Run netstat off main actor for the initial conflict check
                    r.routeConflictWarning = await Task.detached(priority: .utility) { [weak self] in
                        self?.detectRouteConflicts(for: r)
                    }.value
                    await MainActor.run {
                        self?.appliedRoutes[id] = r
                        self?.promoteAutoRoutesIfNeeded(profileID: id, report: r)
                        self?.startConnectionMonitor(for: id)
                    }
                    return
                }
            }
        }
    }

    private func startConnectionMonitor(for profileID: UUID) {
        monitorTasks[profileID]?.cancel()
        let startTime = Date()

        monitorTasks[profileID] = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                guard !Task.isCancelled else { break }
                guard self?.statuses[profileID] == .connected else { break }

                let report = self?.appliedRoutes[profileID]

                // Netstat off main actor (~50 ms).
                let warn: String? = await Task.detached(priority: .utility) { [weak self] in
                    guard let r = report else { return nil }
                    return self?.detectRouteConflicts(for: r)
                }.value

                // Same pass, second question: is v6 genuinely routed here?
                let v6Routed = await Task.detached(priority: .utility) { [weak self] in
                    self?.detectIPv6RoutedViaTunnel() ?? false
                }.value
                if self?.ipv6RoutedViaTunnel != v6Routed { self?.ipv6RoutedViaTunnel = v6Routed }

                if let ne = self?.backends[profileID] as? NEControllable,
                   let s = await ne.fetchStats() {
                    self?.sessionStats[profileID] = TransferStats(
                        bytesSent: s.sent, bytesReceived: s.rcvd, startTime: startTime)
                }

                if var r = self?.appliedRoutes[profileID],
                   r.routeConflictWarning != warn {
                    r.routeConflictWarning = warn
                    self?.appliedRoutes[profileID] = r
                }

                self?.refreshKillSwitchState()
            }
            self?.sessionStats.removeValue(forKey: profileID)
        }
    }

    // MARK: – Kill switch

    func refreshKillSwitchState() {
        let c = UnifiedNEController.shared
        let active = c.isKillSwitchInForce
        let pending = c.isKillSwitchPending
        if killSwitchActive != active { killSwitchActive = active }
        if killSwitchPending != pending { killSwitchPending = pending }
    }

    func applyKillSwitchNow() {
        Task { @MainActor in
            do { try await UnifiedNEController.shared.applyKillSwitchRegimeNow() }
            catch { logger.error("apply kill switch failed: \(error.localizedDescription, privacy: .public)") }
            refreshKillSwitchState()
        }
    }

    nonisolated private func detectRouteConflicts(for report: AppliedRoutesReport) -> String? {
        guard report.source != .full, !report.routes.isEmpty else { return nil }

        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/netstat")
        task.arguments = ["-rn", "-f", "inet"]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()
        guard (try? task.run()) != nil else { return nil }
        task.waitUntilExit()

        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(),
                            encoding: .utf8) ?? ""

        var prefixToIfaces: [String: [String]] = [:]
        for line in output.components(separatedBy: "\n") {
            let cols = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard cols.count >= 4 else { continue }
            let dest = cols[0], flags = cols[2], iface = cols[3]
            guard iface.hasPrefix("utun"), !flags.contains("H") else { continue }
            let key = expandCIDR(dest)
            if !prefixToIfaces[key, default: []].contains(iface) {
                prefixToIfaces[key, default: []].append(iface)
            }
        }

        let conflicting = report.routes.filter { prefixToIfaces[expandCIDR($0), default: []].count > 1 }
        guard !conflicting.isEmpty else { return nil }

        let detail = conflicting.map { cidr -> String in
            let ifaces = prefixToIfaces[expandCIDR(cidr), default: []].sorted()
            return "\(cidr) (\(ifaces.joined(separator: ", ")))"
        }.joined(separator: ", ")
        return "Competing route on another tunnel: \(detail). Another VPN (e.g. Tailscale) may intercept traffic meant for this tunnel."
    }

    nonisolated private func detectIPv6RoutedViaTunnel() -> Bool {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/netstat")
        task.arguments = ["-rn", "-f", "inet6"]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()
        guard (try? task.run()) != nil else { return false }
        task.waitUntilExit()
        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

        for line in output.components(separatedBy: "\n") {
            let cols = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard cols.count >= 4 else { continue }
            let dest = cols[0], flags = cols[2], iface = cols[3]
            guard iface.hasPrefix("utun"), !flags.contains("I") else { continue }
            if dest == "default" || dest == "::/1" || dest == "8000::/1" || dest == "::/0" { return true }
        }
        return false
    }

    nonisolated private func expandCIDR(_ s: String) -> String {
        let parts = s.components(separatedBy: "/")
        guard parts.count == 2 else { return s }
        var octets = parts[0].components(separatedBy: ".")
        while octets.count < 4 { octets.append("0") }
        return "\(octets.joined(separator: "."))/\(parts[1])"
    }

    private func promoteAutoRoutesIfNeeded(profileID: UUID,
                                           report: AppliedRoutesReport) {
        guard report.source == .auto, !report.routes.isEmpty,
              let idx = profiles.firstIndex(where: { $0.id == profileID }) else { return }
        let joined = report.routes.joined(separator: " ")
        guard profiles[idx].config.splitRoutes != joined else { return }
        profiles[idx].config.splitRoutes = joined
        profiles[idx].config.partialEnabled = true
        persist()
        logger.info("[\(self.profiles[idx].name)] promoted auto-detected routes: \(joined)")
    }

    // Waits for the old tunnel to fully tear down before reconnecting.
    private func waitThenConnect(_ profile: VPNProfile) async {
        let ne = backends[profile.id] as? NEControllable
        for _ in 0..<40 {  // poll up to 20 s
            if ne?.isTrulyDisconnected ?? true { break }
            try? await Task.sleep(nanoseconds: 500_000_000)
        }
        try? await Task.sleep(nanoseconds: 300_000_000)
        connect(profile)
    }

    func isPartialTunnel(_ profile: VPNProfile) -> Bool {
        profile.config.partialEnabled && !fullTunnelOverrides.contains(profile.id)
    }

    // MARK: – MFA

    func submitMFA(for profile: VPNProfile, code: String) {
        backends[profile.id]?.submitMFA(code: code)
        mfaChallenges.removeValue(forKey: profile.id)
    }

    // MARK: – SSO

    func submitSSO(for id: UUID, token: String?) {
        backends[id]?.submitSSO(token: token)
        ssoChallenges.removeValue(forKey: id)
    }

    // MARK: – Save

    func save(profile: VPNProfile) async {
        updateProfile(profile)
        do {
            try await ensureBackend(for: profile).saveProfile(profile: profile)
            errors[profile.id] = nil
        } catch {
            let msg = error.localizedDescription
            errors[profile.id] = msg
            logger.error("[\(profile.name)] save failed: \(msg)")
        }
        if statuses[profile.id] == .connected {
            let (mode, manual) = currentRoutingMode(for: profile)
            _ = tryHotSwitch(profile, mode: mode, manualRoutes: manual)
            startDomainRouteRefresh(for: profile)
        }
    }

    // MARK: – Domain routes ("also tunnel these hostnames")

    private func startDomainRouteRefresh(for profile: VPNProfile) {
        let id = profile.id
        domainRouteTasks[id]?.cancel()
        domainRouteTasks.removeValue(forKey: id)
        let raw = profile.config.tunnelDomains
        let hasDomains = !DomainRouteResolver.hostnames(from: raw).isEmpty
        // Nothing listed and nothing to retract → no task (the common case).
        guard hasDomains || !(lastPushedDomainRoutes[id] ?? []).isEmpty else { return }

        domainRouteTasks[id] = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, self.statuses[id] == .connected else { return }
                // getaddrinfo blocks — resolve off the main actor.
                let cidrs = await Task.detached(priority: .utility) {
                    DomainRouteResolver.system.cidrs(from: raw)
                }.value
                guard !Task.isCancelled, self.statuses[id] == .connected else { return }
                if cidrs != (self.lastPushedDomainRoutes[id] ?? []),
                   let ne = self.backends[id] as? NEControllable {
                    do {
                        try await ne.setDomainRoutes(cidrs)
                        self.lastPushedDomainRoutes[id] = cidrs
                        logger.info("[\(profile.name)] hostname routes → [\(cidrs.joined(separator: " "))]")
                        self.fetchAppliedRoutes(for: profile)   // refresh the popover panel
                    } catch {
                        logger.error("[\(profile.name)] setDomainRoutes failed: \(error.localizedDescription)")
                    }
                }
                if !hasDomains { return }   // retraction delivered; nothing to keep fresh
                try? await Task.sleep(nanoseconds: Self.domainRouteRefreshNanos)
            }
        }
    }

    private func stopDomainRouteRefresh(_ id: UUID) {
        domainRouteTasks[id]?.cancel()
        domainRouteTasks.removeValue(forKey: id)
        lastPushedDomainRoutes.removeValue(forKey: id)
    }

    private static let domainRouteRefreshNanos: UInt64 = 300 * 1_000_000_000

    private func currentRoutingMode(for profile: VPNProfile) -> (PartialTunnelMode, String) {
        if fullTunnelOverrides.contains(profile.id) {
            return (.full, "")
        }
        guard profile.config.partialEnabled else {
            return (.full, "")
        }
        let trimmed = profile.config.splitRoutes
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return (trimmed.isEmpty ? .partialAuto : .partialManual, trimmed)
    }

    // MARK: – Status helpers

    var anyConnected: Bool { statuses.values.contains(.connected) }
    var anyActive:    Bool { statuses.values.contains(where: { $0.isActive }) }

    func status(for profile: VPNProfile) -> ConnectionStatus {
        statuses[profile.id] ?? .disconnected
    }

    // MARK: – Private

    private var networkWatcher: NetworkPathWatcher?

    private init() {
        autoreconnectEnabled = UserDefaults.standard.object(forKey: Self.autoreconnectKey) as? Bool ?? false
        autoReconnectOnNetworkRestore = UserDefaults.standard.object(forKey: Self.autoReconnectOnNetworkKey) as? Bool ?? true
        dtlsEnabled = UserDefaults.standard.object(forKey: Self.dtlsEnabledKey) as? Bool ?? true
        killSwitchEnabled = UnifiedNEController.killSwitchPreference
        let saved = UserDefaults.standard.array(forKey: Self.lastConnectedKey) as? [String] ?? []
        pendingAutoconnect = Set(saved.compactMap(UUID.init(uuidString:)))
        load()
        attemptFirstRunSystemImport()
    }

    func startNetworkPathWatcher() {
        guard networkWatcher == nil else { return }
        networkWatcher = NetworkPathWatcher { [weak self] in
            Task { @MainActor [weak self] in
                self?.autoReconnectAfterNetworkRestore()
            }
        }
        networkWatcher?.start()
    }

    private func autoReconnectAfterNetworkRestore() {
        guard autoReconnectOnNetworkRestore else { return }
        guard !connectionLost.isEmpty else { return }
        // Snapshot first; `connect(_:)` mutates `connectionLost`.
        let candidates = connectionLost
        for id in candidates {
            guard let profile = profiles.first(where: { $0.id == id }) else { continue }
            if isInUserActionWindow(id) {
                logger.info("network restore: skipping [\(profile.name)] — user-action quiet window active")
                continue
            }
            let current = statuses[id] ?? .disconnected
            switch current {
            case .connecting, .connected, .reconnecting:
                continue  // already on it
            default:
                break
            }
            logger.info("network restore: reconnecting [\(profile.name)]")
            connect(profile)
        }
    }

    // MARK: – Passive-drop reconnect supervisor

    private static let maxAutoReconnectAttempts = 8

    private static func autoReconnectDelay(attempt: Int, usesTOTP: Bool) -> TimeInterval {
        if usesTOTP {
            return attempt == 0 ? 5 : 33
        }
        return min(3.0 * pow(2.0, Double(attempt)), 30.0)  // 3,6,12,24,30,30…
    }

    private func scheduleAutoReconnect(_ id: UUID) {
        guard autoReconnectOnNetworkRestore else { return }
        guard reconnectTasks[id] == nil else { return }   // already supervising
        guard let profile = profiles.first(where: { $0.id == id }) else { return }
        let usesTOTP: Bool = {
            if case .sslVPN(let c) = profile.config {
                return !c.totpSecret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            }
            return false
        }()
        let name = profile.name
        logger.info("auto-reconnect [\(name)]: scheduling supervisor after passive drop")
        reconnectTasks[id] = Task { @MainActor [weak self] in
            guard let self else { return }
            var attempt = 0
            while !Task.isCancelled, attempt < Self.maxAutoReconnectAttempts {
                let delay = Self.autoReconnectDelay(attempt: attempt, usesTOTP: usesTOTP)
                attempt += 1
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                if Task.isCancelled { break }

                // Re-validate every guard — state may have moved during the sleep.
                guard self.autoReconnectOnNetworkRestore,
                      self.connectionLost.contains(id),          // recovered or user-dismissed → stop
                      !self.explicitDisconnects.contains(id),    // user disconnected → stop
                      AboutScreenManager.shared.isAccessGranted      // trial/license gate → stop
                else { break }
                if self.isInUserActionWindow(id) { continue }    // user mid-action → wait it out
                switch self.statuses[id] ?? .disconnected {
                case .connected:                 break           // beat us to it (handled below)
                case .connecting, .reconnecting: continue        // an attempt is in flight → wait
                default:
                    guard let p = self.profiles.first(where: { $0.id == id }) else { break }
                    logger.info("auto-reconnect [\(name)]: attempt \(attempt)/\(Self.maxAutoReconnectAttempts)")
                    self.connect(p)
                    if await self.awaitConnectOutcome(id) {
                        logger.info("auto-reconnect [\(name)]: reconnected")
                    }
                }
                if self.statuses[id] == .connected { break }     // success — stop retrying
            }
            if !Task.isCancelled, self.statuses[id] != .connected {
                logger.notice("auto-reconnect [\(name)]: gave up after \(attempt) attempt(s); manual Reconnect needed")
            }
            if !Task.isCancelled { self.reconnectTasks[id] = nil }
        }
    }

    private func cancelAutoReconnect(_ id: UUID) {
        reconnectTasks[id]?.cancel()
        reconnectTasks.removeValue(forKey: id)
    }

    private func awaitConnectOutcome(_ id: UUID) async -> Bool {
        try? await Task.sleep(nanoseconds: 2_000_000_000)   // let .connecting register
        for _ in 0..<100 {                                   // then up to ~50 s
            if Task.isCancelled { break }
            switch statuses[id] ?? .disconnected {
            case .connected:    return true
            case .disconnected: return false
            default:            break   // .connecting / .reconnecting → keep waiting
            }
            try? await Task.sleep(nanoseconds: 500_000_000)
        }
        return statuses[id] == .connected
    }

    func runAutoconnect() {
        defer { pendingAutoconnect.removeAll() }
        guard autoreconnectEnabled else { return }
        let toConnect = profiles.filter { pendingAutoconnect.contains($0.id) }
        let sorted = toConnect.enumerated().sorted { (a, b) -> Bool in
            let aFull = self.currentRoutingMode(for: a.element).0 == .full
            let bFull = self.currentRoutingMode(for: b.element).0 == .full
            if aFull != bFull { return aFull }
            return a.offset < b.offset
        }.map { $0.element }
        for p in sorted {
            logger.info("autoconnect: restoring [\(p.name)] mode=\(self.currentRoutingMode(for: p).0.rawValue)")
            connect(p)
        }
    }

    private func applyFirstConnectDefaults() {
        guard !UserDefaults.standard.bool(forKey: Self.hasEverConnectedKey) else { return }
        UserDefaults.standard.set(true, forKey: Self.hasEverConnectedKey)
        autoreconnectEnabled = true
        LaunchAtLoginManager.shared.setEnabled(true)
        logger.info("first connect: enabled auto-reconnect and launch-at-login")
    }

    private func persistLastConnected() {
        let connected = profiles
            .filter { statuses[$0.id] == .connected || statuses[$0.id] == .reconnecting }
            .map { $0.id.uuidString }
        let filtered = connected.filter {
            !explicitDisconnects.contains(UUID(uuidString: $0)!)
        }
        UserDefaults.standard.set(filtered, forKey: Self.lastConnectedKey)
    }

    func snapshotConnectedForRestart() {
        persistLastConnected()
    }

    private func ensureBackend(for profile: VPNProfile) -> any VPNBackend {
        if let b = backends[profile.id] { return b }

        let b: any VPNBackend = UnifiedNEBackendProxy(profileID: profile.id)
        backends[profile.id] = b

        let id = profile.id

        statusTasks[id] = Task { [weak self] in
            for await s in b.statusPublisher.values {
                await MainActor.run {
                    guard let self = self else { return }
                    if s == .disconnected, self.statuses[id] == .reconnecting { return }
                    if case .failed(let msg) = s {
                        self.statuses[id] = .disconnected
                        self.appliedRoutes.removeValue(forKey: id)
                        self.monitorTasks[id]?.cancel()
                        self.monitorTasks.removeValue(forKey: id)
                        self.stopDomainRouteRefresh(id)
                        self.sessionStats.removeValue(forKey: id)
                        if self.explicitDisconnects.contains(id) || self.isInUserActionWindow(id) {
                            logger.info("status [\(id)]: .failed(\(msg)) suppressed — user-initiated within quiet window")
                            self.errors[id] = nil
                        } else {
                            logger.info("status [\(id)]: .failed(\(msg)) surfaced as connection-lost")
                            self.errors[id] = msg
                            if self.hasBeenConnected.contains(id) {
                                self.connectionLost.insert(id)
                                self.scheduleAutoReconnect(id)
                            }
                        }
                    } else {
                        self.statuses[id] = s
                        if s == .connected {
                            self.errors[id] = nil
                            self.connectionLost.remove(id)
                            self.cancelAutoReconnect(id)
                            self.hasBeenConnected.insert(id)
                            self.mfaChallenges.removeValue(forKey: id)
                            self.ssoChallenges.removeValue(forKey: id)
                            self.applyFirstConnectDefaults()
                            if let p = self.profiles.first(where: { $0.id == id }) {
                                self.fetchAppliedRoutes(for: p)
                                self.startDomainRouteRefresh(for: p)
                                if AboutScreenManager.shared.isLicenseStale {
                                    Task { @MainActor [weak self] in
                                        let confirmed = await AboutScreenManager.shared.verifyHeartbeat()
                                        guard let self, !confirmed else { return }
                                        logger.warning("[\(p.name)] license verification failed past the grace window — disconnecting")
                                        self.errors[id] = "velun couldn't verify your license. Connect to the internet and reconnect."
                                        self.licenseDeniedDisconnects.insert(id)
                                        self.disconnect(p)
                                    }
                                }
                            }
                        } else if s == .disconnected {
                            self.appliedRoutes.removeValue(forKey: id)
                            self.monitorTasks[id]?.cancel()
                            self.monitorTasks.removeValue(forKey: id)
                            self.stopDomainRouteRefresh(id)
                            self.sessionStats.removeValue(forKey: id)
                            if self.licenseDeniedDisconnects.remove(id) != nil {
                                logger.info("status [\(id)]: .disconnected suppressed — license verification denial")
                            } else if self.hasBeenConnected.contains(id),
                               !self.explicitDisconnects.contains(id),
                               !self.isInUserActionWindow(id) {
                                logger.info("status [\(id)]: passive .disconnected → inserting into connectionLost")
                                self.connectionLost.insert(id)
                                self.scheduleAutoReconnect(id)
                            } else if self.isInUserActionWindow(id) {
                                logger.info("status [\(id)]: .disconnected suppressed by quiet window")
                            }
                        }
                    }
                    self.persistLastConnected()
                }
            }
        }

        mfaTasks[id] = Task { [weak self] in
            for await challenge in b.mfaChallengePublisher.values {
                await MainActor.run {
                    if let c = challenge {
                        self?.mfaChallenges[id] = c
                    } else {
                        self?.mfaChallenges.removeValue(forKey: id)
                    }
                }
            }
        }

        ssoTasks[id] = Task { [weak self] in
            for await challenge in b.ssoChallengePublisher.values {
                await MainActor.run {
                    if let c = challenge {
                        self?.ssoChallenges[id] = c
                    } else {
                        self?.ssoChallenges.removeValue(forKey: id)
                    }
                }
            }
        }

        return b
    }

    // MARK: – Persistence

    private static let udKey = "velun.profiles.v3"

    private func persist() {
        if let data = try? JSONEncoder().encode(profiles) {
            UserDefaults.standard.set(data, forKey: Self.udKey)
        }
        for p in profiles {
            guard !keychainLoadFailures.contains(p.id) else { continue }
            switch p.config {
            case .sslVPN(let oc):
                KeychainHelper.savePassword(oc.password,  for: p.id)
                KeychainHelper.saveTOTP    (oc.totpSecret, for: p.id)
                KeychainHelper.saveClientCert(oc.clientCertP12, for: p.id)
                KeychainHelper.saveClientCertPassword(oc.clientCertPassword, for: p.id)
            case .wireguard(let wg):
                KeychainHelper.saveWireGuardConf(wg.confText, for: p.id)
            }
        }
    }

    private func load() {
        if let data = UserDefaults.standard.data(forKey: Self.udKey),
           let saved = try? JSONDecoder().decode([VPNProfile].self, from: data) {
            profiles = saved
        } else {
            profiles = []
        }
        var healedAny = false
        for i in profiles.indices where profiles[i].normalizeServerAddress() { healedAny = true }

        for i in profiles.indices {
            let id = profiles[i].id
            switch profiles[i].config {
            case .sslVPN(var oc):
                let pw   = KeychainHelper.loadPassword(for: id)
                let totp = KeychainHelper.loadTOTP    (for: id)
                oc.password   = pw   ?? ""
                oc.totpSecret = totp ?? ""
                oc.clientCertP12      = KeychainHelper.loadClientCert(for: id) ?? ""
                oc.clientCertPassword = KeychainHelper.loadClientCertPassword(for: id) ?? ""
                if pw == nil { keychainLoadFailures.insert(id) }
                profiles[i].config = .sslVPN(oc)
            case .wireguard(var wg):
                let conf = KeychainHelper.loadWireGuardConf(for: id)
                wg.confText = conf ?? ""
                if conf == nil { keychainLoadFailures.insert(id) }
                profiles[i].config = .wireguard(wg)
            }
        }
        if !keychainLoadFailures.isEmpty {
            logger.error("Keychain read failed for \(self.keychainLoadFailures.count) profile(s) at startup — Connect buttons will stay disabled until the user relaunches")
        }
        if healedAny { persist() }
    }
}
