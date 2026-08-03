import NetworkExtension
import Foundation
import Network
import OSLog
import Darwin
import SystemConfiguration
import WireGuardKit

private let log = Logger(subsystem: "com.manueldeprada.velun.PacketTunnel", category: "Unified")

private let kUtunInnerIPString  = "198.18.0.1"
private let kUtunInnerIP: UInt32 = 0xC612_0001   // 198.18.0.1
private let kUtunRemoteString   = "198.18.0.2"

private let kUtunInnerIP6String = "2001:2::1"
private let kUtunInnerIP6 = IPv6Addr("2001:2::1") ?? .zero

private let kReconnectAttemptTimeout: TimeInterval = 10

// MARK: – PacketFlow adapter

final class PacketFlowAdapter: PacketFlowIO, @unchecked Sendable {
    private let flow: NEPacketTunnelFlow
    init(_ flow: NEPacketTunnelFlow) { self.flow = flow }

    func readInbound() async -> [Data] {
        await withCheckedContinuation { (cont: CheckedContinuation<[Data], Never>) in
            flow.readPackets { pkts, _ in cont.resume(returning: pkts) }
        }
    }

    func writeOutbound(_ packets: [Data]) {
        flow.writePackets(packets, withProtocols: packets.map {
            NSNumber(value: ($0.first.map { $0 >> 4 } == 6) ? AF_INET6 : AF_INET)
        })
    }
}

// MARK: – Managed upstream

final class ManagedUpstream: RouterUpstream, @unchecked Sendable {
    let profileID: String
    let providerType: ProviderType

    // data plane
    var assignedIP: UInt32 = 0                 // stable after connect; read lock-free
    var assignedIP6: IPv6Addr = .zero
    private let tlock = NSLock()
    private var _tunnel: SSLVPNFamilyTunnel?      // SSL-VPN-family transport
    private var _wg: WireGuardCallbackAdapter?         // WireGuard transport
    var tunnel: SSLVPNFamilyTunnel? {
        get { tlock.lock(); defer { tlock.unlock() }; return _tunnel }
        set { tlock.lock(); _tunnel = newValue; tlock.unlock() }
    }
    var wg: WireGuardCallbackAdapter? {
        get { tlock.lock(); defer { tlock.unlock() }; return _wg }
        set { tlock.lock(); _wg = newValue; tlock.unlock() }
    }
    var wgDeliverContinuation: AsyncStream<Data>.Continuation?

    // control plane (provider.lock)
    var config: SharedTunnelConfig
    var partialMode: PartialTunnelMode
    var manualRoutes: String
    var netCfg: TunnelNetworkConfig?
    var routeCIDRs: [String] = []
    var routeCIDRs6: [String] = []
    var domainRoutes: [String] = []
    var dnsServers: [String] = []
    var searchDomains: [String] = []
    var dnsSuffixes: [String] = []
    var report: AppliedRoutesReport?
    var state: UnifiedIPC.UpstreamState = .connecting
    var lastError: String?
    var mfaPrompt: String?
    var mfaContinuation: CheckedContinuation<String?, Never>?
    var ssoRequest: SSOLoginRequest?
    var ssoContinuation: CheckedContinuation<String?, Never>?
    var isReconnecting = false
    var readTask: Task<Void, Never>?
    var generation: Int = 0

    init(_ cfg: SharedTunnelConfig) {
        profileID = cfg.profileID
        providerType = ProviderType(rawValue: cfg.providerType) ?? .anyConnect
        config = cfg
        partialMode = cfg.partialMode
        manualRoutes = cfg.manualRoutes
    }

    func writeInner(_ packet: Data) async throws {
        tlock.lock(); let oc = _tunnel; let w = _wg; tlock.unlock()
        if let w { w.inject(packet); return }       // WireGuard: enqueue for wireguard-go
        guard let oc else { return }
        try await oc.writeDataPacket(packet)
    }
}

// MARK: – Unified provider

final class UnifiedTunnelProvider: NEPacketTunnelProvider {

    private var router: UnifiedRouter!
    private var flowAdapter: PacketFlowAdapter?
    private let lock = NSLock()
    private var upstreams: [String: ManagedUpstream] = [:]
    private var killSwitch = false

    private var dnsSuffixCache: [String: [String]] = [:]

    private var applyingSettings = false
    private var reapplyPending = false

    private struct DNSKey: Hashable { let profileID: String; let port: UInt16 }
    private struct DNSEntry { let hostPort: UInt16; let at: Date }
    private var dnsMap: [DNSKey: DNSEntry] = [:]
    private var dnsPortCounter: UInt16 = 40000
    private static let dnsEntryTTL: TimeInterval = 5

    private var flowKeeper: FlowKeeper!
    private var keepaliveTimer: DispatchSourceTimer?
    private static let keepaliveInterval: TimeInterval = 75
    private static let verifyBurstGap: TimeInterval = 4
    private static let verifyBurstCycles = 12          // hard bound ≈ 48 s per burst
    private static let flowGraceWindow: TimeInterval = 180
    private static let flowGraceObservationGap: TimeInterval = 160
    private var flowGrace: [String: (downSince: Date, lastSeen: Date)] = [:]

    private var dpdWatchdogTimer: DispatchSourceTimer?
    private static let dpdTimeout: TimeInterval = 50
    private static let dpdCheckInterval: TimeInterval = 15

    private static let mfaPromptTimeout: TimeInterval = 120

    private static let ssoPromptTimeout: TimeInterval = 300

    private let pathMonitor = NWPathMonitor()
    private let pathQueue = DispatchQueue(label: "com.manueldeprada.velun.pathmon")
    private let pathLock = NSLock()
    private var pathIsSatisfied = true
    private var pathWaiters: [CheckedContinuation<Void, Never>] = []

    @inline(__always)
    private func withLock<T>(_ body: () -> T) -> T {
        lock.lock(); defer { lock.unlock() }; return body()
    }

    // MARK: lifecycle

    override func startTunnel(options: [String: NSObject]?,
                             completionHandler: @escaping (Error?) -> Void) {
        killSwitch = protocolConfiguration.includeAllNetworks
        log.info("startTunnel (unified) killSwitch=\(self.killSwitch, privacy: .public)")
        let adapter = PacketFlowAdapter(packetFlow)
        flowAdapter = adapter
        router = UnifiedRouter(utunInnerIP: kUtunInnerIP, utunInnerIP6: kUtunInnerIP6, packetFlow: adapter)
        router.dnsHook = self
        flowKeeper = FlowKeeper(utunInnerIP: kUtunInnerIP, verifyProbeGap: Self.verifyBurstGap)
        router.flowKeeper = flowKeeper
        pathMonitor.pathUpdateHandler = { [weak self] path in
            self?.updatePath(satisfied: path.status == .satisfied)
        }
        pathMonitor.start(queue: pathQueue)

        Task {
            do {
                try await applySettingsOnce()
                router.start()
                startKeepaliveTimer()
                startDPDWatchdog()
                completionHandler(nil)
                log.info("startTunnel (unified) up; awaiting addUpstream")
            } catch {
                log.error("startTunnel (unified) failed: \(error.localizedDescription, privacy: .public)")
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                            completionHandler: @escaping () -> Void) {
        log.info("stopTunnel (unified) reason=\(reason.rawValue, privacy: .public)")
        keepaliveTimer?.cancel(); keepaliveTimer = nil
        dpdWatchdogTimer?.cancel(); dpdWatchdogTimer = nil
        pathMonitor.cancel()
        updatePath(satisfied: true)   // drain any parked reconnect waiters
        router?.stop()
        lock.lock()
        let all = Array(upstreams.values)
        upstreams.removeAll()
        lock.unlock()
        for mu in all { teardownTransport(mu) }
        completionHandler()
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        log.notice("system sleep")
        completionHandler()
    }

    override func wake() {
        log.notice("system wake — probing tunneled flows")
        Task { await self.runKeepaliveBurst() }
    }

    // MARK: IPC

    override func handleAppMessage(_ messageData: Data,
                                   completionHandler: ((Data?) -> Void)? = nil) {
        guard let action = UnifiedIPC.action(in: messageData) else {
            completionHandler?(nil); return
        }
        guard router != nil else {
            log.error("handleAppMessage(\(action, privacy: .public)) before startTunnel — tunnel not running")
            completionHandler?(UnifiedIPC.err("tunnel not running").data(using: .utf8))
            return
        }
        switch action {
        case UnifiedIPC.Action.addUpstream:
            guard let req = UnifiedIPC.decode(UnifiedIPC.AddUpstream.self, from: messageData) else {
                completionHandler?(UnifiedIPC.err("bad addUpstream").data(using: .utf8)); return
            }
            completionHandler?(UnifiedIPC.ok.data(using: .utf8))
            Task { await self.addUpstream(req.config) }

        case UnifiedIPC.Action.removeUpstream:
            guard let req = UnifiedIPC.decode(UnifiedIPC.ByProfile.self, from: messageData) else {
                completionHandler?(UnifiedIPC.err("bad removeUpstream").data(using: .utf8)); return
            }
            completionHandler?(UnifiedIPC.ok.data(using: .utf8))
            Task { await self.removeUpstream(req.profileID) }

        case UnifiedIPC.Action.setRouting:
            guard let req = UnifiedIPC.decode(UnifiedIPC.SetRouting.self, from: messageData) else {
                completionHandler?(UnifiedIPC.err("bad setRouting").data(using: .utf8)); return
            }
            Task {
                let result = await self.setRouting(req)
                completionHandler?(result.data(using: .utf8))
            }

        case UnifiedIPC.Action.setDomainRoutes:
            guard let req = UnifiedIPC.decode(UnifiedIPC.SetDomainRoutes.self, from: messageData) else {
                completionHandler?(UnifiedIPC.err("bad setDomainRoutes").data(using: .utf8)); return
            }
            Task {
                let result = await self.setDomainRoutes(req)
                completionHandler?(result.data(using: .utf8))
            }

        case UnifiedIPC.Action.status:
            completionHandler?(UnifiedIPC.encode(statusReply()))

        case UnifiedIPC.Action.stats:
            let s = router.stats()
            let map = Dictionary(uniqueKeysWithValues: s.map { ($0.key, [$0.value.sent, $0.value.rcvd]) })
            completionHandler?(UnifiedIPC.encode(UnifiedIPC.StatsReply(stats: map)))

        case UnifiedIPC.Action.appliedRoutes:
            guard let req = UnifiedIPC.decode(UnifiedIPC.ByProfile.self, from: messageData) else {
                completionHandler?(nil); return
            }
            lock.lock(); let report = upstreams[req.profileID]?.report; lock.unlock()
            completionHandler?(report.flatMap { try? JSONEncoder().encode($0) })

        case UnifiedIPC.Action.lastError:
            guard let req = UnifiedIPC.decode(UnifiedIPC.ByProfile.self, from: messageData) else {
                completionHandler?(nil); return
            }
            lock.lock(); let msg = upstreams[req.profileID]?.lastError; lock.unlock()
            completionHandler?(msg?.data(using: .utf8))

        case UnifiedIPC.Action.mfaPrompt:
            guard let req = UnifiedIPC.decode(UnifiedIPC.ByProfile.self, from: messageData) else {
                completionHandler?(nil); return
            }
            lock.lock(); let prompt = upstreams[req.profileID]?.mfaPrompt; lock.unlock()
            completionHandler?(prompt?.data(using: .utf8))

        case UnifiedIPC.Action.submitMFA:
            guard let req = UnifiedIPC.decode(UnifiedIPC.SubmitMFA.self, from: messageData) else {
                completionHandler?(UnifiedIPC.err("bad submitMFA").data(using: .utf8)); return
            }
            if let mu = withLock({ upstreams[req.profileID] }) {
                deliverMFA(mu, code: req.code)
            }
            completionHandler?(UnifiedIPC.ok.data(using: .utf8))

        case UnifiedIPC.Action.ssoRequest:
            guard let req = UnifiedIPC.decode(UnifiedIPC.ByProfile.self, from: messageData) else {
                completionHandler?(nil); return
            }
            lock.lock(); let sso = upstreams[req.profileID]?.ssoRequest; lock.unlock()
            completionHandler?(sso.flatMap { try? JSONEncoder().encode($0) })

        case UnifiedIPC.Action.submitSSO:
            guard let req = UnifiedIPC.decode(UnifiedIPC.SubmitSSO.self, from: messageData) else {
                completionHandler?(UnifiedIPC.err("bad submitSSO").data(using: .utf8)); return
            }
            if let mu = withLock({ upstreams[req.profileID] }) {
                // Empty token = the user cancelled / closed the window → nil fails it.
                deliverSSO(mu, token: req.token.isEmpty ? nil : req.token)
            }
            completionHandler?(UnifiedIPC.ok.data(using: .utf8))

        default:
            log.error("handleAppMessage: unknown action '\(action, privacy: .public)'")
            completionHandler?(nil)
        }
    }

    private func statusReply() -> UnifiedIPC.StatusReply {
        lock.lock(); defer { lock.unlock() }
        var map: [String: String] = [:]
        for (id, mu) in upstreams { map[id] = mu.state.rawValue }
        return UnifiedIPC.StatusReply(statuses: map)
    }

    // MARK: upstream connect / remove / hot-switch

    private func addUpstream(_ cfg: SharedTunnelConfig) async {
        let id = cfg.profileID
        guard !id.isEmpty else { return }
        log.notice("⏱ connect:start \(id, privacy: .public)")

        let (mu, myGen): (ManagedUpstream, Int) = withLock {
            let mu = upstreams[id] ?? ManagedUpstream(cfg)
            mu.config = cfg
            mu.partialMode = cfg.partialMode
            mu.manualRoutes = cfg.manualRoutes
            mu.state = .connecting
            mu.lastError = nil
            mu.generation += 1
            upstreams[id] = mu
            return (mu, mu.generation)
        }
        teardownTransport(mu)

        if mu.providerType == .wireguard {
            await connectWireGuardUpstream(mu, gen: myGen)
            return
        }

        // Marker kept (effectively 0 now) so the benchmark's phase split parses.
        log.notice("⏱ connect:totp-done \(id, privacy: .public)")

        do {
            let tunnel = Self.makeTunnel(mu.providerType)
            if cfg.totpSecret.isEmpty, let cstp = tunnel as? CSTPTunnelBackend {
                cstp.secondaryPasswordProvider = { [weak self, weak mu] prompt in
                    guard let self, let mu else { return nil }
                    return await self.requestSecondaryPassword(mu, prompt: prompt)
                }
            }
            if let cstp = tunnel as? CSTPTunnelBackend {
                cstp.ssoTokenProvider = { [weak self, weak mu] req in
                    guard let self, let mu else { return nil }
                    return await self.requestSSO(mu, request: req)
                }
            }
            let netCfg = try await tunnel.connect(config: cfg)

            guard isCurrentGen(mu, myGen) else { tunnel.disconnect(); return }

            guard IPv4.toUInt32(netCfg.ipAddress) != nil else {
                tunnel.disconnect()
                failUpstream(mu, "Server did not assign an IPv4 address (got \"\(netCfg.ipAddress)\").")
                return
            }
            log.notice("upstream \(id, privacy: .public) connected ip=\(netCfg.ipAddress, privacy: .public) ip6=\(netCfg.ipv6Address.isEmpty ? "none" : netCfg.ipv6Address, privacy: .public) split=\(netCfg.splitIncludes.joined(separator: ","), privacy: .public)")

            var suffixes: [String] = []
            var fromCache = false
            if cfg.partialMode != .full {
                if let cached = withLock({ dnsSuffixCache[id] }) {
                    suffixes = cached
                    fromCache = true
                } else {
                    suffixes = await DnsSuffixAutoDetect.detectViaTunnel(for: netCfg, tunnel: tunnel)
                    withLock { dnsSuffixCache[id] = suffixes }
                }
            }
            log.notice("⏱ connect:dns-done \(id, privacy: .public) n=\(suffixes.count, privacy: .public) cached=\(fromCache, privacy: .public)")

            // Commit atomically, gated on still being the current attempt.
            let result: (prefixes: [RoutePrefix], prefixes6: [RoutePrefix6], ipChanged: Bool)? = withLock {
                guard mu.generation == myGen else { return nil }
                let oldIP = mu.assignedIP
                let newIP = IPv4.toUInt32(netCfg.ipAddress) ?? 0
                mu.assignedIP = newIP
                mu.assignedIP6 = IPv6Addr(netCfg.ipv6Address) ?? .zero
                mu.tunnel = tunnel
                mu.netCfg = netCfg
                mu.dnsSuffixes = suffixes
                computeRoutesLocked(mu)
                mu.state = .connected
                mu.lastError = nil
                return (routerPrefixesLocked(mu), routerPrefixes6Locked(mu), oldIP != 0 && newIP != oldIP)
            }
            guard let result else { tunnel.disconnect(); return }
            if result.ipChanged { flushDeadFlows(id) }
            else { flowKeeper?.onTransportRebuilt(profileID: id) }

            router.addUpstream(mu, prefixes: result.prefixes, prefixes6: result.prefixes6)
            startReadLoop(mu)
            Task { await self.runKeepaliveBurst() }
            await applySettings()
            log.notice("⏱ connect:done \(id, privacy: .public)")
        } catch {
            guard isCurrentGen(mu, myGen) else { return }
            failUpstream(mu, error.localizedDescription)
        }
    }

    private func isCurrentGen(_ mu: ManagedUpstream, _ gen: Int) -> Bool {
        withLock { mu.generation == gen }
    }

    private func removeUpstream(_ id: String) async {
        flushDeadFlows(id)   // tunnel going away → RST its inner sockets so they fail fast
        let mu = withLock { () -> ManagedUpstream? in
            dnsSuffixCache[id] = nil
            let removed = upstreams.removeValue(forKey: id)
            removed?.generation += 1
            return removed
        }
        router?.removeUpstream(profileID: id)
        if let mu { teardownTransport(mu) }
        await applySettings()
        log.info("removeUpstream \(id, privacy: .public)")
    }

    private func teardownTransport(_ mu: ManagedUpstream) {
        deliverMFA(mu, code: nil)   // unblock any auth parked on an MFA prompt
        deliverSSO(mu, token: nil)  // unblock any auth parked on an SSO login
        mu.readTask?.cancel(); mu.readTask = nil
        mu.wgDeliverContinuation?.finish(); mu.wgDeliverContinuation = nil
        mu.wg?.stop(); mu.wg = nil
        mu.tunnel?.disconnect(); mu.tunnel = nil
    }

    private func setRouting(_ req: UnifiedIPC.SetRouting) async -> String {
        let mode = PartialTunnelMode(rawValue: req.partialMode) ?? .full
        let prefixesOpt: (v4: [RoutePrefix], v6: [RoutePrefix6])? = withLock {
            guard let mu = upstreams[req.profileID], mu.netCfg != nil else { return nil }
            mu.partialMode = mode
            mu.manualRoutes = req.manualRoutes
            computeRoutesLocked(mu)
            return (routerPrefixesLocked(mu), routerPrefixes6Locked(mu))
        }
        guard let prefixes = prefixesOpt else { return UnifiedIPC.err("upstream not connected") }

        router.updateRoutes(profileID: req.profileID, prefixes: prefixes.v4, prefixes6: prefixes.v6)
        await applySettings()
        return UnifiedIPC.ok
    }

    private func setDomainRoutes(_ req: UnifiedIPC.SetDomainRoutes) async -> String {
        let cidrs = req.cidrs.filter { RoutePrefix.parse($0) != nil }
        let prefixesOpt: (v4: [RoutePrefix], v6: [RoutePrefix6])? = withLock {
            guard let mu = upstreams[req.profileID], mu.netCfg != nil else { return nil }
            mu.domainRoutes = cidrs
            computeRoutesLocked(mu)   // refresh the report's resolvedHostRoutes
            return (routerPrefixesLocked(mu), routerPrefixes6Locked(mu))
        }
        guard let prefixes = prefixesOpt else { return UnifiedIPC.err("upstream not connected") }
        log.info("setDomainRoutes \(req.profileID, privacy: .public) cidrs=\(cidrs.joined(separator: ","), privacy: .public)")

        router.updateRoutes(profileID: req.profileID, prefixes: prefixes.v4, prefixes6: prefixes.v6)
        await applySettings()
        return UnifiedIPC.ok
    }

    private func failUpstream(_ mu: ManagedUpstream, _ message: String) {
        log.error("upstream \(mu.profileID, privacy: .public) failed: \(message, privacy: .public)")
        withLock { mu.lastError = message; mu.state = .failed }
        teardownTransport(mu)
    }

    // MARK: interactive MFA (no stored TOTP secret)

    private func requestSecondaryPassword(_ mu: ManagedUpstream, prompt: String) async -> String? {
        log.notice("upstream \(mu.profileID, privacy: .public) needs interactive MFA")
        let timeout = Task { [weak self, weak mu] in
            try? await Task.sleep(nanoseconds: UInt64(Self.mfaPromptTimeout * 1_000_000_000))
            if let self, let mu { self.deliverMFA(mu, code: nil) }
        }
        defer { timeout.cancel() }
        return await withCheckedContinuation { (cont: CheckedContinuation<String?, Never>) in
            withLock {
                mu.mfaPrompt = prompt
                mu.state = .needsMFA
                mu.mfaContinuation = cont
            }
        }
    }

    private func deliverMFA(_ mu: ManagedUpstream, code: String?) {
        let cont = withLock { () -> CheckedContinuation<String?, Never>? in
            let c = mu.mfaContinuation
            mu.mfaContinuation = nil
            mu.mfaPrompt = nil
            if code != nil, mu.state == .needsMFA { mu.state = .connecting }
            return c
        }
        cont?.resume(returning: code)
    }

    // MARK: SAML / SSO browser login

    private func requestSSO(_ mu: ManagedUpstream, request: SSOLoginRequest) async -> String? {
        log.notice("upstream \(mu.profileID, privacy: .public) needs SAML/SSO browser login")
        let timeout = Task { [weak self, weak mu] in
            try? await Task.sleep(nanoseconds: UInt64(Self.ssoPromptTimeout * 1_000_000_000))
            if let self, let mu { self.deliverSSO(mu, token: nil) }
        }
        defer { timeout.cancel() }
        return await withCheckedContinuation { (cont: CheckedContinuation<String?, Never>) in
            withLock {
                mu.ssoRequest = request
                mu.state = .needsSSO
                mu.ssoContinuation = cont
            }
        }
    }

    private func deliverSSO(_ mu: ManagedUpstream, token: String?) {
        let cont = withLock { () -> CheckedContinuation<String?, Never>? in
            let c = mu.ssoContinuation
            mu.ssoContinuation = nil
            mu.ssoRequest = nil
            if token != nil, mu.state == .needsSSO { mu.state = .connecting }
            return c
        }
        cont?.resume(returning: token)
    }

    // MARK: WireGuard upstream

    private func connectWireGuardUpstream(_ mu: ManagedUpstream, gen myGen: Int) async {
        let id = mu.profileID
        do {
            let parsed = try WireGuardQuickConfig.parse(mu.config.wgConf)
            let netCfg = try makeWGNetworkConfig(from: parsed)
            let wide = wideAllowedIPsConfig(from: parsed)

            var continuation: AsyncStream<Data>.Continuation!
            let stream = AsyncStream<Data>(Data.self, bufferingPolicy: .bufferingNewest(4096)) {
                continuation = $0
            }
            let adapter = WireGuardCallbackAdapter(logHandler: { level, msg in
                if level == .error { log.error("[wg] \(msg, privacy: .public)") }
                else { log.debug("[wg] \(msg, privacy: .public)") }
            })
            let ifindex = primaryPhysicalIfindex()
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                adapter.start(tunnelConfiguration: wide, mtu: netCfg.mtu, ifindex: ifindex,
                              onDeliver: { continuation.yield($0) }) { err in
                    if let err { cont.resume(throwing: err) } else { cont.resume() }
                }
            }

            // Superseded while the handshake ran? Drop our adapter + stream.
            guard isCurrentGen(mu, myGen) else { adapter.stop(); continuation.finish(); return }
            log.info("upstream \(id, privacy: .public) (wg) connected ip=\(netCfg.ipAddress, privacy: .public)")

            let consumer = Task { [weak self, weak mu] in
                for await pkt in stream {
                    guard let self, let mu else { break }
                    await self.router.handleInbound(pkt, from: mu)
                }
            }
            // Commit atomically, gated on still being the current attempt.
            let prefixes: (v4: [RoutePrefix], v6: [RoutePrefix6])? = withLock {
                guard mu.generation == myGen else { return nil }
                mu.assignedIP = IPv4.toUInt32(netCfg.ipAddress) ?? 0
                mu.assignedIP6 = IPv6Addr(netCfg.ipv6Address) ?? .zero
                mu.netCfg = netCfg
                mu.wg = adapter
                mu.wgDeliverContinuation = continuation
                mu.readTask = consumer
                mu.dnsSuffixes = []   // WG has no PTR probe; suffixes come from the conf's DNS= search entries
                computeRoutesLocked(mu)
                mu.state = .connected
                mu.lastError = nil
                return (routerPrefixesLocked(mu), routerPrefixes6Locked(mu))
            }
            guard let prefixes else { consumer.cancel(); adapter.stop(); continuation.finish(); return }
            flowKeeper?.onTransportRebuilt(profileID: id)
            router.addUpstream(mu, prefixes: prefixes.v4, prefixes6: prefixes.v6)
            Task { await self.runKeepaliveBurst() }
            await applySettings()
        } catch {
            guard isCurrentGen(mu, myGen) else { return }
            failUpstream(mu, "WireGuard: \(error.localizedDescription)")
        }
    }

    private func makeWGNetworkConfig(from parsed: TunnelConfiguration) throws -> TunnelNetworkConfig {
        guard let firstAddr = parsed.interface.addresses.first(where: { $0.address is IPv4Address }) else {
            throw NSError(domain: "velun", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "WireGuard config has no IPv4 Address"])
        }
        let mtu = Int(parsed.interface.mtu ?? 1280)
        let dnsServers = parsed.interface.dns.filter { $0.address is IPv4Address }.map { "\($0.address)" }
        let firstAddr6 = parsed.interface.addresses.first { $0.address is IPv6Address }
        var splitIncludes: [String] = []
        var splitIncludes6: [String] = []
        var seen = Set<String>()
        for peer in parsed.peers {
            for range in peer.allowedIPs {
                let s = range.stringRepresentation
                guard seen.insert(s).inserted else { continue }
                if range.address is IPv6Address { splitIncludes6.append(s) } else { splitIncludes.append(s) }
            }
        }
        return TunnelNetworkConfig(
            ipAddress: "\(firstAddr.address)",
            netmask: Self.prefixToMask(Int(firstAddr.networkPrefixLength)),
            gateway: "",
            dnsServers: dnsServers,
            searchDomains: parsed.interface.dnsSearch,
            mtu: mtu,
            splitIncludes: splitIncludes,
            splitExcludes: [],
            ipv6Address: firstAddr6.map { "\($0.address)" } ?? "",
            ipv6PrefixLength: firstAddr6.map { Int($0.networkPrefixLength) } ?? 0,
            ipv6SplitIncludes: firstAddr6 == nil ? [] : splitIncludes6)
    }

    private func wideAllowedIPsConfig(from parsed: TunnelConfiguration) -> TunnelConfiguration {
        let v4 = IPAddressRange(from: "0.0.0.0/0")!
        let v6 = IPAddressRange(from: "::/0")!
        var peers = parsed.peers
        for i in peers.indices { peers[i].allowedIPs = [v4, v6] }
        return TunnelConfiguration(name: parsed.name, interface: parsed.interface, peers: peers)
    }

    private static func prefixToMask(_ prefix: Int) -> String {
        let bits: UInt32 = prefix == 0 ? 0 : ~UInt32(0) << (32 - prefix)
        return [24, 16, 8, 0].map { String((bits >> $0) & 0xff) }.joined(separator: ".")
    }

    // MARK: per-upstream read loop + seamless reconnect

    private func startReadLoop(_ mu: ManagedUpstream) {
        let id = mu.profileID
        let task = Task { [weak self, weak mu] in
            let reconnector = ReconnectController()
            while !Task.isCancelled {
                guard let self, let mu, let tunnel = mu.tunnel else { return }
                do {
                    guard let pkt = try await tunnel.readDataPacket() else { continue }
                    await self.router.handleInbound(pkt, from: mu)
                } catch {
                    if Task.isCancelled { return }
                    log.error("upstream \(id, privacy: .public) read error: \(error.localizedDescription, privacy: .public)")

                    guard tunnel.supportsSeamlessReconnect else {
                        await self.handleUpstreamDrop(mu, error: error.localizedDescription)
                        return
                    }
                    self.withLock {
                        mu.isReconnecting = true
                        if mu.state == .connected { mu.state = .reconnecting }
                    }
                    let outcome = await reconnector.run { [weak self, weak mu] in
                        await self?.awaitUsablePath()
                        guard let mu, let t = mu.tunnel else {
                            throw NSError(domain: "velun", code: 1,
                                          userInfo: [NSLocalizedDescriptionKey: "upstream gone mid-reconnect"])
                        }
                        do {
                            try await withTimeout(seconds: kReconnectAttemptTimeout,
                                                  onTimeout: { [weak mu] in mu?.tunnel?.abortTransport() }) {
                                try await t.reconnectTransport()
                            }
                        } catch {
                            log.notice("upstream \(id, privacy: .public) reconnect attempt failed: \(error.localizedDescription, privacy: .public)")
                            throw error
                        }
                    }
                    self.withLock { mu.isReconnecting = false }
                    if Task.isCancelled { return }
                    switch outcome {
                    case .succeeded(let n):
                        log.notice("upstream \(id, privacy: .public) transport rebuilt after \(n) attempt(s)")
                        // Back to healthy — undo the `.reconnecting` we set above.
                        self.withLock { if mu.state == .reconnecting { mu.state = .connected } }
                        self.flowKeeper?.onTransportRebuilt(profileID: id)   // outage wasn't the flows' fault — verify them now
                        Task { await self.runKeepaliveBurst() }              // fast keep-or-RST verdict, not the 75s tick
                        continue
                    case .exhausted(_, let lastError):
                        await self.handleUpstreamDrop(mu, error: "Reconnect failed: \(lastError)")
                        return
                    }
                }
            }
        }
        lock.lock(); mu.readTask = task; lock.unlock()
    }

    private func handleUpstreamDrop(_ mu: ManagedUpstream, error: String) async {
        withLock { mu.lastError = error; mu.state = .failed }
        router.removeUpstream(profileID: mu.profileID)
        teardownTransport(mu)
        await applySettings()
    }

    // MARK: keepalive engine + physical-path gate

    private func startKeepaliveTimer() {
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + Self.keepaliveInterval, repeating: Self.keepaliveInterval)
        timer.setEventHandler { [weak self] in
            Task { await self?.runKeepaliveBurst() }
        }
        timer.resume()
        keepaliveTimer = timer
    }

    private func runKeepaliveBurst() async {
        for _ in 0..<Self.verifyBurstCycles {
            await runKeepaliveCycle()
            let connected = withLock { Set(upstreams.filter { $0.value.state == .connected }.map(\.key)) }
            guard flowKeeper?.hasVerifyingFlows(connected: connected) == true else { return }
            try? await Task.sleep(nanoseconds: UInt64(Self.verifyBurstGap * 1_000_000_000))
        }
    }

    private func runKeepaliveCycle() async {
        guard flowKeeper != nil else { return }
        pathLock.lock(); let pathUp = pathIsSatisfied; pathLock.unlock()
        guard pathUp else { return }
        flushLongDeadFlows(now: Date())
        let connected = withLock { Set(upstreams.filter { $0.value.state == .connected }.map(\.key)) }
        guard !connected.isEmpty else { return }
        let actions = flowKeeper.runCycle(connected: connected, now: Date())
        for action in actions {
            switch action {
            case let .keepalive(profileID, packet):
                guard let mu = withLock({ upstreams[profileID] }), mu.assignedIP != 0 else { continue }
                var p = packet
                _ = PacketNAT.rewriteSource(&p, to: mu.assignedIP)
                try? await mu.writeInner(p)
            case .reset(_, let packet):
                flowAdapter?.writeOutbound([packet])
            }
        }
    }

    private func flushDeadFlows(_ profileID: String) {
        guard flowKeeper != nil else { return }
        let rsts = flowKeeper.flushAsDead(profileID: profileID)
        guard !rsts.isEmpty else { return }
        log.notice("RST \(rsts.count, privacy: .public) orphaned flow(s) for \(profileID, privacy: .public)")
        flowAdapter?.writeOutbound(rsts)
    }

    private func flushLongDeadFlows(now: Date) {
        let overdue: [String] = withLock {
            var flush: [String] = []
            for (id, mu) in upstreams {
                if mu.state == .connected { flowGrace[id] = nil; continue }
                guard let g = flowGrace[id] else { flowGrace[id] = (now, now); continue }
                if now.timeIntervalSince(g.lastSeen) > Self.flowGraceObservationGap {
                    flowGrace[id] = (now, now)
                } else if now.timeIntervalSince(g.downSince) >= Self.flowGraceWindow {
                    flowGrace[id] = nil
                    flush.append(id)
                } else {
                    flowGrace[id] = (g.downSince, now)
                }
            }
            // Upstreams removed entirely were flushed by removeUpstream.
            for id in flowGrace.keys where upstreams[id] == nil { flowGrace[id] = nil }
            return flush
        }
        for id in overdue {
            log.notice("upstream \(id, privacy: .public) down > \(Int(Self.flowGraceWindow), privacy: .public)s — flushing its flows")
            flushDeadFlows(id)
        }
    }

    private func startDPDWatchdog() {
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + Self.dpdCheckInterval, repeating: Self.dpdCheckInterval)
        timer.setEventHandler { [weak self] in self?.runDPDCheck() }
        timer.resume()
        dpdWatchdogTimer = timer
    }

    private func runDPDCheck() {
        let stale: [(String, SSLVPNFamilyTunnel)] = withLock {
            upstreams.values.compactMap { mu -> (String, SSLVPNFamilyTunnel)? in
                guard mu.state == .connected, !mu.isReconnecting, let t = mu.tunnel,
                      let idle = t.secondsSinceLastInbound, idle > Self.dpdTimeout else { return nil }
                return (mu.profileID, t)
            }
        }
        for (id, t) in stale {
            log.notice("DPD: upstream \(id, privacy: .public) silent — forcing reconnect")
            t.abortTransport()
        }
    }

    private func abortStaleTransports(reason: String) {
        let tunnels: [SSLVPNFamilyTunnel] = withLock {
            upstreams.values.compactMap { ($0.state == .connected && !$0.isReconnecting) ? $0.tunnel : nil }
        }
        guard !tunnels.isEmpty else { return }
        log.notice("\(reason, privacy: .public) — reconnecting \(tunnels.count, privacy: .public) transport(s)")
        for t in tunnels { t.abortTransport() }
    }

    private func updatePath(satisfied: Bool) {
        pathLock.lock()
        let wasSatisfied = pathIsSatisfied
        pathIsSatisfied = satisfied
        let waiters = satisfied ? pathWaiters : []
        if satisfied { pathWaiters.removeAll() }
        pathLock.unlock()
        for c in waiters { c.resume() }
        if satisfied != wasSatisfied {
            abortStaleTransports(reason: satisfied ? "network path restored" : "network path lost")
        }
    }

    private func awaitUsablePath() async {
        pathLock.lock()
        if pathIsSatisfied { pathLock.unlock(); return }
        pathLock.unlock()
        await withTaskCancellationHandler {
            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                pathLock.lock()
                if pathIsSatisfied {
                    pathLock.unlock(); cont.resume()
                } else {
                    pathWaiters.append(cont); pathLock.unlock()
                }
            }
        } onCancel: {
            pathLock.lock()
            let waiters = pathWaiters; pathWaiters.removeAll()
            pathLock.unlock()
            for c in waiters { c.resume() }
        }
    }

    // MARK: routing computation (under lock)

    private func computeRoutesLocked(_ mu: ManagedUpstream) {
        guard let netCfg = mu.netCfg else { return }
        mu.dnsServers = netCfg.dnsServers
        mu.searchDomains = netCfg.searchDomains

        let (routes, base): ([String], AppliedRoutesReport)
        switch mu.partialMode {
        case .full:
            (routes, base) = (["0.0.0.0/0"],
                              AppliedRoutesReport(source: .full, routes: ["0.0.0.0/0"], explanation: ""))
        case .partialManual:
            let r = mu.manualRoutes
                .components(separatedBy: CharacterSet(charactersIn: " ,"))
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
            (routes, base) = (r, AppliedRoutesReport(source: .manual, routes: r, explanation: "from saved settings"))
        case .partialAuto:
            if !netCfg.splitIncludes.isEmpty {
                (routes, base) = (netCfg.splitIncludes,
                                  AppliedRoutesReport(source: .server, routes: netCfg.splitIncludes,
                                                      explanation: "from VPN server settings"))
            } else {
                let derived = RouteAutoDetect.detect(for: netCfg)
                if !derived.isEmpty {
                    (routes, base) = (derived,
                                      AppliedRoutesReport(source: .auto, routes: derived,
                                                          explanation: "best guess from server hints — edit if a service can't be reached"))
                } else {
                    (routes, base) = (["0.0.0.0/0"],
                                      AppliedRoutesReport(source: .full, routes: ["0.0.0.0/0"],
                                                          explanation: "no usable hints from server — using full tunnel"))
                }
            }
        }
        mu.routeCIDRs = routes
        mu.routeCIDRs6 = computeRoutes6Locked(mu, netCfg: netCfg)
        var report = base
        report.assignedIP = kUtunInnerIPString    // host locates the shared utun by U0
        report.dnsSuffixes = mu.dnsSuffixes
        report.resolvedHostRoutes = mu.domainRoutes
        report.ipv6Routes = mu.routeCIDRs6
        mu.report = report
    }

    private func computeRoutes6Locked(_ mu: ManagedUpstream, netCfg: TunnelNetworkConfig) -> [String] {
        guard !mu.assignedIP6.isZero else { return [] }
        if mu.partialMode == .full { return ["::/0"] }
        if !netCfg.ipv6SplitIncludes.isEmpty { return netCfg.ipv6SplitIncludes }
        let prefixLen = netCfg.ipv6PrefixLength > 0 ? netCfg.ipv6PrefixLength : 64
        let net = RoutePrefix6(network: mu.assignedIP6, prefix: prefixLen)
        return ["\(net.network.string)/\(net.prefix)"]
    }

    private func routerPrefixesLocked(_ mu: ManagedUpstream) -> [RoutePrefix] {
        let isFull = mu.routeCIDRs == ["0.0.0.0/0"]
        var cidrs = mu.routeCIDRs
        if !isFull { cidrs += mu.dnsServers.map { "\($0)/32" } + mu.domainRoutes }
        return cidrs.compactMap(RoutePrefix.parse)
    }

    /// v6 router prefixes for an upstream. Caller holds lock.
    private func routerPrefixes6Locked(_ mu: ManagedUpstream) -> [RoutePrefix6] {
        guard !mu.assignedIP6.isZero else { return [] }
        return mu.routeCIDRs6.compactMap(RoutePrefix6.parse)
    }

    // MARK: settings (union of all connected upstreams)

    private func applySettings() async {
        let proceed = withLock { () -> Bool in
            if applyingSettings { reapplyPending = true; return false }
            applyingSettings = true
            return true
        }
        guard proceed else { return }
        while true {
            do { try await applySettingsOnce() }
            catch { log.error("applySettings failed: \(error.localizedDescription, privacy: .public)") }
            let again = withLock { () -> Bool in
                let a = reapplyPending
                reapplyPending = false
                if !a { applyingSettings = false }
                return a
            }
            if !again { break }
        }
    }

    private func applySettingsOnce() async throws {
        let settings = buildUnionSettings()
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            setTunnelNetworkSettings(settings) { err in
                if let err { cont.resume(throwing: err) } else { cont.resume() }
            }
        }
    }

    private func buildUnionSettings() -> NEPacketTunnelNetworkSettings {
        lock.lock()
        let connected = upstreams.values.filter { $0.state == .connected }
        let hasFull = connected.contains { $0.routeCIDRs == ["0.0.0.0/0"] }
        let mtu = connected.compactMap { $0.netCfg?.mtu }.min() ?? 1400
        var partialRoutes: [String] = []
        var partialRoutes6: [String] = []
        var dnsServers: [String] = []
        var matchSet: [String] = []
        var anyV6Upstream = false
        for u in connected {
            if u.routeCIDRs != ["0.0.0.0/0"] {
                partialRoutes += u.routeCIDRs
                partialRoutes += u.dnsServers.map { "\($0)/32" }
                partialRoutes += u.domainRoutes
            }
            if !u.assignedIP6.isZero {
                anyV6Upstream = true
                if u.routeCIDRs6 != ["::/0"] { partialRoutes6 += u.routeCIDRs6 }
            }
            dnsServers += u.dnsServers
            matchSet += u.searchDomains + u.dnsSuffixes
        }
        let killSwitch = self.killSwitch
        lock.unlock()

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: kUtunRemoteString)
        settings.mtu = NSNumber(value: mtu)

        let anyDNS = connected.contains { !$0.dnsServers.isEmpty }
        let matchDomains: [String] = (killSwitch || hasFull)
            ? (anyDNS ? [""] : [])
            : dedup(matchSet).filter { !DnsSuffixAutoDetect.denyList.contains($0) }
        let useProxy = anyDNS && !matchDomains.isEmpty

        let v4 = NEIPv4Settings(addresses: [kUtunInnerIPString], subnetMasks: ["255.255.255.255"])
        if killSwitch || hasFull {
            v4.includedRoutes = [NEIPv4Route.default()]
        } else {
            var inc = partialRoutes.compactMap(Self.cidrToRoute)
            if useProxy, let r = Self.cidrToRoute("\(UnifiedDNSProxy.proxyIPString)/32") { inc.append(r) }
            v4.includedRoutes = inc
            v4.excludedRoutes = [NEIPv4Route.default()]
        }
        settings.ipv4Settings = v4

        if killSwitch || hasFull {
            let v6 = NEIPv6Settings(addresses: [kUtunInnerIP6String], networkPrefixLengths: [128])
            v6.includedRoutes = [
                NEIPv6Route(destinationAddress: "::",     networkPrefixLength: 1),
                NEIPv6Route(destinationAddress: "8000::", networkPrefixLength: 1),
            ]
            settings.ipv6Settings = v6
            log.notice("IPv6: claiming ::/1 + 8000::/1 — \(anyV6Upstream ? "routed through the tunnel" : "no upstream carries v6, so blocked", privacy: .public)")
        } else if !partialRoutes6.isEmpty {
            let v6 = NEIPv6Settings(addresses: [kUtunInnerIP6String], networkPrefixLengths: [128])
            v6.includedRoutes = dedup(partialRoutes6).compactMap(Self.cidrToRoute6)
            v6.excludedRoutes = [NEIPv6Route.default()]
            settings.ipv6Settings = v6
        }

        if useProxy {
            let dnsSettings = NEDNSSettings(servers: [UnifiedDNSProxy.proxyIPString])
            dnsSettings.searchDomains = dedup(matchSet)
            dnsSettings.matchDomains = matchDomains
            settings.dnsSettings = dnsSettings
        }
        return settings
    }

    // MARK: helpers

    private static func makeTunnel(_ provider: ProviderType) -> SSLVPNFamilyTunnel {
        switch provider {
        case .anyConnect:    return CSTPTunnelBackend()
        case .fortinet:      return FortinetTunnelBackend()
        case .globalProtect: return GPTunnelBackend()
        case .wireguard:     return CSTPTunnelBackend()   // unreachable (guarded in addUpstream)
        }
    }

    private static func cidrToRoute(_ cidr: String) -> NEIPv4Route? {
        let parts = cidr.split(separator: "/").map(String.init)
        guard parts.count == 2, let prefix = Int(parts[1]), prefix >= 0, prefix <= 32 else { return nil }
        let bits: UInt32 = prefix == 0 ? 0 : ~UInt32(0) << (32 - prefix)
        let mask = [24, 16, 8, 0].map { String((bits >> $0) & 0xff) }.joined(separator: ".")
        return NEIPv4Route(destinationAddress: parts[0], subnetMask: mask)
    }

    private static func cidrToRoute6(_ cidr: String) -> NEIPv6Route? {
        guard let p = RoutePrefix6.parse(cidr) else { return nil }
        return NEIPv6Route(destinationAddress: p.network.string,
                           networkPrefixLength: NSNumber(value: p.prefix))
    }

    private func dedup(_ list: [String]) -> [String] {
        var seen = Set<String>(); var out: [String] = []
        for s in list {
            let v = s.trimmingCharacters(in: .whitespaces).lowercased()
            if !v.isEmpty, seen.insert(v).inserted { out.append(v) }
        }
        return out
    }
}

// MARK: – DNS proxy (suffix-routed multi-corp DNS)

extension UnifiedTunnelProvider: RouterDNSHook {
    var dnsProxyIP: UInt32 { UnifiedDNSProxy.proxyIP }

    func handleDNSQuery(_ packet: Data) async {
        guard let (qport, dport, dns) = DnsSuffixAutoDetect.parseUDPInIPv4(packet), dport == 53,
              let qname = UnifiedDNSProxy.queryName(from: dns) else { return }

        struct Target { let mu: ManagedUpstream; let dnsServer: String }
        let target: Target? = withLock {
            let connected = upstreams.values.filter { $0.state == .connected }
            let suffixLists = connected.map { mu in
                (id: mu.profileID,
                 suffixes: dedup(mu.searchDomains + mu.dnsSuffixes)
                            .filter { !DnsSuffixAutoDetect.denyList.contains($0) })
            }
            let defaultID = connected.first { $0.routeCIDRs == ["0.0.0.0/0"] }?.profileID
            guard let id = UnifiedDNSProxy.route(qname: qname, suffixes: suffixLists, defaultID: defaultID),
                  let mu = upstreams[id], let dnsServer = mu.dnsServers.first, mu.assignedIP != 0
            else { return nil }
            return Target(mu: mu, dnsServer: dnsServer)
        }
        guard let t = target else {
            log.debug("dns proxy: no connected upstream resolves \(qname, privacy: .public) — SERVFAIL")
            if let fail = UnifiedDNSProxy.servfailResponse(for: dns) {
                let resp = DnsSuffixAutoDetect.buildIPv4UDPPacket(
                    srcIP: UnifiedDNSProxy.proxyIPString, dstIP: kUtunInnerIPString,
                    srcPort: 53, dstPort: qport, payload: fail, ipID: qport)
                if !resp.isEmpty { flowAdapter?.writeOutbound([resp]) }
            }
            return
        }
        let pport = withLock { allocateDNSPortLocked(profileID: t.mu.profileID, hostPort: qport) }
        let fwd = DnsSuffixAutoDetect.buildIPv4UDPPacket(
            srcIP: IPv4.toString(t.mu.assignedIP), dstIP: t.dnsServer,
            srcPort: pport, dstPort: 53, payload: dns, ipID: pport)
        if !fwd.isEmpty { try? await t.mu.writeInner(fwd) }
    }

    func claimsDNSResponse(profileID: String, dstPort: UInt16) -> Bool {
        withLock { dnsMap[DNSKey(profileID: profileID, port: dstPort)] != nil }
    }

    func handleDNSResponse(_ packet: Data, from upstream: RouterUpstream) async {
        guard let (sp, dp, payload) = DnsSuffixAutoDetect.parseUDPInIPv4(packet), sp == 53 else { return }
        let entry = withLock { dnsMap.removeValue(forKey: DNSKey(profileID: upstream.profileID, port: dp)) }
        guard let entry else { return }
        let resp = DnsSuffixAutoDetect.buildIPv4UDPPacket(
            srcIP: UnifiedDNSProxy.proxyIPString, dstIP: kUtunInnerIPString,
            srcPort: 53, dstPort: entry.hostPort, payload: payload, ipID: dp)
        if !resp.isEmpty { flowAdapter?.writeOutbound([resp]) }
    }

    private func allocateDNSPortLocked(profileID: String, hostPort: UInt16) -> UInt16 {
        let now = Date()
        dnsMap = dnsMap.filter { now.timeIntervalSince($0.value.at) < Self.dnsEntryTTL }
        for _ in 0..<1000 {
            let port = dnsPortCounter
            dnsPortCounter = dnsPortCounter >= 40999 ? 40000 : dnsPortCounter + 1
            let key = DNSKey(profileID: profileID, port: port)
            if dnsMap[key] == nil {
                dnsMap[key] = DNSEntry(hostPort: hostPort, at: now)
                return port
            }
        }
        let key = DNSKey(profileID: profileID, port: dnsPortCounter)
        dnsMap[key] = DNSEntry(hostPort: hostPort, at: now)
        return dnsPortCounter
    }
}

// MARK: – Primary physical interface resolution (for WG bind pinning)

fileprivate func primaryPhysicalIfindex() -> Int32 {
    if let name = scPrimaryInterface(), !name.hasPrefix("utun") {
        let idx = if_nametoindex(name)
        if idx > 0 { return Int32(idx) }
    }
    return fallbackPhysicalIfindex()
}

fileprivate func scPrimaryInterface() -> String? {
    guard let store = SCDynamicStoreCreate(nil, "velun-unified" as CFString, nil, nil) else { return nil }
    guard let value = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString)
            as? [String: Any] else { return nil }
    return value["PrimaryInterface"] as? String
}

fileprivate func fallbackPhysicalIfindex() -> Int32 {
    var ifap: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifap) == 0, let head = ifap else { return 0 }
    defer { freeifaddrs(ifap) }
    let virtualPrefixes = ["utun", "awdl", "llw", "anpi", "bridge", "stf", "gif"]
    var p: UnsafeMutablePointer<ifaddrs>? = head
    while let cur = p {
        defer { p = cur.pointee.ifa_next }
        guard let nameCStr = cur.pointee.ifa_name else { continue }
        let name = String(cString: nameCStr)
        if name == "lo0" { continue }
        if virtualPrefixes.contains(where: { name.hasPrefix($0) }) { continue }
        guard let addr = cur.pointee.ifa_addr,
              addr.pointee.sa_family == sa_family_t(AF_INET) else { continue }
        let flags = Int32(cur.pointee.ifa_flags)
        if (flags & IFF_UP) == 0 || (flags & IFF_LOOPBACK) != 0 { continue }
        let idx = if_nametoindex(name)
        if idx > 0 { return Int32(idx) }
    }
    return 0
}
