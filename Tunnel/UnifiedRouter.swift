import Foundation
import OSLog

private let log = Logger(subsystem: "com.manueldeprada.velun.PacketTunnel", category: "UnifiedRouter")

// MARK: – Route prefix + table (pure, fully testable)

struct RoutePrefix: Equatable {
    let network: UInt32   // host-order, already masked to `prefix` bits
    let prefix: Int       // 0...32

    init(network: UInt32, prefix: Int) {
        self.prefix = prefix
        self.network = prefix == 0 ? 0 : network & (~UInt32(0) << (32 - prefix))
    }

    func contains(_ ip: UInt32) -> Bool {
        if prefix == 0 { return true }
        let mask = ~UInt32(0) << (32 - prefix)
        return (ip & mask) == network
    }

    /// Parse "10.15.0.0/16" or a bare "10.15.0.0" (treated as /32).
    static func parse(_ cidr: String) -> RoutePrefix? {
        let parts = cidr.split(separator: "/", maxSplits: 1).map(String.init)
        guard let net = IPv4.toUInt32(parts[0].trimmingCharacters(in: .whitespaces)) else { return nil }
        let p: Int
        if parts.count == 2 {
            guard let parsed = Int(parts[1].trimmingCharacters(in: .whitespaces)),
                  parsed >= 0, parsed <= 32 else { return nil }
            p = parsed
        } else {
            p = 32
        }
        return RoutePrefix(network: net, prefix: p)
    }
}

struct RoutingTable {
    private struct Entry { let prefix: RoutePrefix; let id: String }
    private let entries: [Entry]

    init(_ upstreams: [(id: String, prefixes: [RoutePrefix])]) {
        var es: [(Entry, Int)] = []
        var order = 0
        for (id, prefixes) in upstreams {
            for p in prefixes { es.append((Entry(prefix: p, id: id), order)) }
            order += 1
        }
        entries = es.sorted {
            $0.0.prefix.prefix != $1.0.prefix.prefix
                ? $0.0.prefix.prefix > $1.0.prefix.prefix
                : $0.1 < $1.1
        }.map { $0.0 }
    }

    func upstreamID(forDest dest: UInt32) -> String? {
        for e in entries where e.prefix.contains(dest) { return e.id }
        return nil
    }
}

// MARK: – Abstractions the provider supplies (stubbed in tests)

protocol RouterUpstream: AnyObject {
    var profileID: String { get }
    var assignedIP: UInt32 { get }
    var assignedIP6: IPv6Addr { get }
    /// host → peer: send an inner packet (src already rewritten to `assignedIP`).
    func writeInner(_ packet: Data) async throws
}

extension RouterUpstream {
    /// v4-only upstreams (and test stubs) opt out by omission.
    var assignedIP6: IPv6Addr { .zero }
}

/// The shared utun's packet I/O. Real impl wraps NEPacketTunnelFlow.
protocol PacketFlowIO: AnyObject {
    func readInbound() async -> [Data]      // host → VPN
    func writeOutbound(_ packets: [Data])   // VPN → host
}

protocol RouterDNSHook: AnyObject {
    /// The synthetic resolver IP the utun advertises (0 = proxy disabled).
    var dnsProxyIP: UInt32 { get }
    /// host → proxy: a DNS query addressed to dnsProxyIP.
    func handleDNSQuery(_ packet: Data) async
    func claimsDNSResponse(profileID: String, dstPort: UInt16) -> Bool
    /// peer → host: a DNS reply the proxy must NAT back to the original asker.
    func handleDNSResponse(_ packet: Data, from upstream: RouterUpstream) async
}

// MARK: – Router

final class UnifiedRouter {

    let utunInnerIP: UInt32

    let utunInnerIP6: IPv6Addr

    private let packetFlow: PacketFlowIO
    private let lock = NSLock()
    private var upstreams: [String: RouterUpstream] = [:]
    private var routes: [String: [RoutePrefix]] = [:]  // route set per upstream, router-owned
    private var routes6: [String: [RoutePrefix6]] = [:]
    private var order: [String] = []                   // registration order for tie-breaks
    private var table = RoutingTable([])
    private var table6 = RoutingTable6([])
    private var bytesOut: [String: UInt64] = [:]
    private var bytesIn:  [String: UInt64] = [:]

    private var packetFlowTask: Task<Void, Never>?
    private var started = false

    /// Optional DNS proxy. Weak: the provider owns the router.
    weak var dnsHook: RouterDNSHook?

    var flowKeeper: FlowKeeper?

    init(utunInnerIP: UInt32, utunInnerIP6: IPv6Addr = .zero, packetFlow: PacketFlowIO) {
        self.utunInnerIP = utunInnerIP
        self.utunInnerIP6 = utunInnerIP6
        self.packetFlow = packetFlow
    }

    // MARK: upstream registry

    func addUpstream(_ u: RouterUpstream, prefixes: [RoutePrefix], prefixes6: [RoutePrefix6] = []) {
        lock.lock()
        if upstreams[u.profileID] == nil { order.append(u.profileID) }
        upstreams[u.profileID] = u
        routes[u.profileID] = u.assignedIP == 0 ? [] : prefixes
        routes6[u.profileID] = u.assignedIP6.isZero ? [] : prefixes6
        rebuildTableLocked()
        lock.unlock()
        log.info("addUpstream \(u.profileID, privacy: .public) ip=\(IPv4.toString(u.assignedIP), privacy: .public) prefixes=\(prefixes.count) ip6=\(u.assignedIP6.isZero ? "none" : u.assignedIP6.string, privacy: .public) prefixes6=\(prefixes6.count)")
    }

    func updateRoutes(profileID: String, prefixes: [RoutePrefix], prefixes6: [RoutePrefix6] = []) {
        lock.lock()
        guard let u = upstreams[profileID] else { lock.unlock(); return }
        routes[profileID] = u.assignedIP == 0 ? [] : prefixes
        routes6[profileID] = u.assignedIP6.isZero ? [] : prefixes6
        rebuildTableLocked()
        lock.unlock()
        log.info("updateRoutes \(profileID, privacy: .public) prefixes=\(prefixes.count) prefixes6=\(prefixes6.count)")
    }

    func removeUpstream(profileID: String) {
        lock.lock()
        upstreams.removeValue(forKey: profileID)
        routes.removeValue(forKey: profileID)
        routes6.removeValue(forKey: profileID)
        order.removeAll { $0 == profileID }
        bytesOut.removeValue(forKey: profileID)
        bytesIn.removeValue(forKey: profileID)
        rebuildTableLocked()
        lock.unlock()
        log.info("removeUpstream \(profileID, privacy: .public)")
    }

    /// Snapshot of currently-registered profile IDs (for status replies).
    var activeProfileIDs: [String] {
        lock.lock(); defer { lock.unlock() }
        return order
    }

    /// Per-upstream cumulative byte counters, keyed by profileID → (sent, rcvd).
    func stats() -> [String: (sent: UInt64, rcvd: UInt64)] {
        lock.lock(); defer { lock.unlock() }
        var out: [String: (UInt64, UInt64)] = [:]
        for id in order { out[id] = (bytesOut[id] ?? 0, bytesIn[id] ?? 0) }
        return out
    }

    private func rebuildTableLocked() {
        table = RoutingTable(order.compactMap { id in
            routes[id].map { (id: id, prefixes: $0) }
        })
        table6 = RoutingTable6(order.compactMap { id in
            routes6[id].flatMap { $0.isEmpty ? nil : (id: id, prefixes: $0) }
        })
    }

    var carriesIPv6: Bool {
        lock.lock(); defer { lock.unlock() }
        return !table6.isEmpty
    }

    // MARK: lifecycle

    func start() {
        lock.lock()
        guard !started else { lock.unlock(); return }
        started = true
        lock.unlock()

        packetFlowTask = Task { [weak self] in
            while !Task.isCancelled {
                let pkts = await self?.packetFlow.readInbound() ?? []
                if Task.isCancelled { return }
                for p in pkts { await self?.handleOutbound(p) }
            }
        }
    }

    func stop() {
        lock.lock(); started = false; lock.unlock()
        packetFlowTask?.cancel(); packetFlowTask = nil
    }

    private func routeOutbound(dest: UInt32, byteCount: Int) -> RouterUpstream? {
        lock.lock(); defer { lock.unlock() }
        guard let id = table.upstreamID(forDest: dest), let u = upstreams[id] else { return nil }
        bytesOut[id, default: 0] += UInt64(byteCount)
        return u
    }

    private func recordInbound(_ profileID: String, _ byteCount: Int) {
        lock.lock(); bytesIn[profileID, default: 0] += UInt64(byteCount); lock.unlock()
    }

    private func routeOutbound6(dest: IPv6Addr, byteCount: Int) -> RouterUpstream? {
        lock.lock(); defer { lock.unlock() }
        guard let id = table6.upstreamID(forDest: dest), let u = upstreams[id] else { return nil }
        bytesOut[id, default: 0] += UInt64(byteCount)
        return u
    }

    // MARK: data path (called from the loops; unit-tested directly)

    func handleOutbound(_ packet: Data) async {
        guard let first = packet.first else { return }
        let version = first >> 4
        if version == 6 { await handleOutbound6(packet); return }
        guard version == 4 else {
            log.debug("outbound: dropping non-IP (version \(version))")
            return
        }
        guard let ip = IPv4Header.parse(packet) else { return }

        if let hook = dnsHook, hook.dnsProxyIP != 0, ip.destinationAddress == hook.dnsProxyIP {
            await hook.handleDNSQuery(packet)
            return
        }

        guard let u = routeOutbound(dest: ip.destinationAddress, byteCount: packet.count) else {
            log.debug("outbound: no route for \(IPv4.toString(ip.destinationAddress), privacy: .public) — dropping")
            return
        }
        flowKeeper?.observeOutbound(packet, profileID: u.profileID)
        var p = packet
        PacketNAT.rewriteSource(&p, to: u.assignedIP)
        do { try await u.writeInner(p) }
        catch { log.error("outbound: write to \(u.profileID, privacy: .public) failed: \(error.localizedDescription, privacy: .public)") }
    }

    private func handleOutbound6(_ packet: Data) async {
        guard let ip = IPv6Header.parse(packet) else { return }
        guard !ip.destination.isLinkLocal, !ip.destination.isMulticast else { return }

        guard let u = routeOutbound6(dest: ip.destination, byteCount: packet.count) else {
            log.debug("outbound6: no route for \(ip.destination.string, privacy: .public) — dropping")
            return
        }
        var p = packet
        PacketNAT.rewriteSource6(&p, to: u.assignedIP6)
        do { try await u.writeInner(p) }
        catch { log.error("outbound6: write to \(u.profileID, privacy: .public) failed: \(error.localizedDescription, privacy: .public)") }
    }

    func handleInbound(_ packet: Data, from u: RouterUpstream) async {
        guard let first = packet.first else { return }
        if first >> 4 == 6 { await handleInbound6(packet, from: u); return }
        guard first >> 4 == 4 else { return }
        guard let ip = IPv4Header.parse(packet) else { return }

        if let hook = dnsHook, ip.proto == 17 {
            let hl = ip.headerLength
            let b = [UInt8](packet)
            if b.count >= hl + 4 {
                let srcPort = UInt16(b[hl]) << 8 | UInt16(b[hl + 1])
                let dstPort = UInt16(b[hl + 2]) << 8 | UInt16(b[hl + 3])
                if srcPort == 53, hook.claimsDNSResponse(profileID: u.profileID, dstPort: dstPort) {
                    await hook.handleDNSResponse(packet, from: u)
                    return
                }
            }
        }

        guard ip.destinationAddress == u.assignedIP else {
            log.debug("inbound from \(u.profileID, privacy: .public): dst \(IPv4.toString(ip.destinationAddress), privacy: .public) != assigned — dropping")
            return
        }
        recordInbound(u.profileID, packet.count)
        flowKeeper?.observeInbound(packet, profileID: u.profileID)
        var p = packet
        PacketNAT.rewriteDestination(&p, to: utunInnerIP)
        packetFlow.writeOutbound([p])
    }

    /// peer → host, IPv6. Rewrite dst A_u6 → U0_6 and deliver to the utun.
    private func handleInbound6(_ packet: Data, from u: RouterUpstream) async {
        guard !u.assignedIP6.isZero, !utunInnerIP6.isZero else { return }
        guard let ip = IPv6Header.parse(packet) else { return }
        guard ip.destination == u.assignedIP6 else {
            log.debug("inbound6 from \(u.profileID, privacy: .public): dst \(ip.destination.string, privacy: .public) != assigned — dropping")
            return
        }
        recordInbound(u.profileID, packet.count)
        var p = packet
        PacketNAT.rewriteDestination6(&p, to: utunInnerIP6)
        packetFlow.writeOutbound([p])
    }
}
