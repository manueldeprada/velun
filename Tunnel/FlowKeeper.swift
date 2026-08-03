import Foundation
import OSLog

private let log = Logger(subsystem: "com.manueldeprada.velun.PacketTunnel", category: "FlowKeeper")

struct FlowKey: Hashable {
    let profileID: String
    let peerIP:   UInt32
    let peerPort: UInt16
    let hostPort: UInt16
}

final class FlowKeeper {

    struct Flow {
        var sndNxt: UInt32          // next seq the host will send (max seq+len+SYN/FIN seen outbound)
        var rcvNxt: UInt32          // next seq the host expects (max ACK seen outbound) = host RCV.NXT
        var window: UInt16          // host's last advertised receive window
        var lastOutbound: Date
        var lastInbound:  Date
        var lastProbe:    Date?
        var unanswered:   Int
        var verifying: Bool = false
    }

    /// What a probe cycle wants the provider to put on the wire.
    enum Action: Equatable {
        case keepalive(profileID: String, packet: Data)
        case reset(profileID: String, packet: Data)
    }

    private let utunInnerIP: UInt32
    private let idleThreshold: TimeInterval   // skip flows with inbound newer than this (alive)
    private let verifyProbeGap: TimeInterval  // re-probe cadence for flows in verify mode
    private let deadAfter: Int                // consecutive unanswered probes ⇒ dead
    private let maxIdle: TimeInterval          // hard eviction for flows we never resolve
    private let maxFlows: Int

    private let lock = NSLock()
    private var flows: [FlowKey: Flow] = [:]

    init(utunInnerIP: UInt32,
         idleThreshold: TimeInterval = 25,
         verifyProbeGap: TimeInterval = 4,
         deadAfter: Int = 4,
         maxIdle: TimeInterval = 3600,
         maxFlows: Int = 512) {
        self.utunInnerIP    = utunInnerIP
        self.idleThreshold  = idleThreshold
        self.verifyProbeGap = verifyProbeGap
        self.deadAfter      = deadAfter
        self.maxIdle        = maxIdle
        self.maxFlows       = maxFlows
    }

    // MARK: serial-number arithmetic (RFC 1982 / TCP wraparound)

    /// True if `a` is at-or-after `b` in TCP sequence space.
    @inline(__always) private static func seqGE(_ a: UInt32, _ b: UInt32) -> Bool {
        Int32(bitPattern: a &- b) >= 0
    }

    // MARK: observation (called from the router's data path)

    /// host → peer. `packet` is pre-NAT (src == U0). Creates/updates the flow.
    func observeOutbound(_ packet: Data, profileID: String, now: Date = Date()) {
        guard let (ip, tcp) = Self.parseTCP(packet), ip.sourceAddress == utunInnerIP else { return }
        let key = FlowKey(profileID: profileID,
                          peerIP: ip.destinationAddress,
                          peerPort: tcp.destinationPort,
                          hostPort: tcp.sourcePort)

        lock.lock(); defer { lock.unlock() }

        if tcp.flags.contains(.rst) || tcp.flags.contains(.fin) {
            flows.removeValue(forKey: key)
            return
        }

        let segLen = UInt32(tcp.payload.count) + (tcp.flags.contains(.syn) ? 1 : 0)
        let candidateSnd = tcp.sequenceNumber &+ segLen

        if var f = flows[key] {
            if Self.seqGE(candidateSnd, f.sndNxt) { f.sndNxt = candidateSnd }
            if tcp.flags.contains(.ack), Self.seqGE(tcp.ackNumber, f.rcvNxt) { f.rcvNxt = tcp.ackNumber }
            f.window = tcp.window
            f.lastOutbound = now
            flows[key] = f
        } else {
            guard flows.count < maxFlows else { return }   // backstop; don't grow unbounded
            flows[key] = Flow(sndNxt: candidateSnd,
                              rcvNxt: tcp.flags.contains(.ack) ? tcp.ackNumber : 0,
                              window: tcp.window,
                              lastOutbound: now, lastInbound: now,
                              lastProbe: nil, unanswered: 0)
        }
    }

    func observeInbound(_ packet: Data, profileID: String, now: Date = Date()) {
        guard let (ip, tcp) = Self.parseTCP(packet) else { return }
        let key = FlowKey(profileID: profileID,
                          peerIP: ip.sourceAddress,
                          peerPort: tcp.sourcePort,
                          hostPort: tcp.destinationPort)

        lock.lock(); defer { lock.unlock() }
        guard var f = flows[key] else { return }
        if tcp.flags.contains(.rst) || tcp.flags.contains(.fin) {
            flows.removeValue(forKey: key)
            return
        }
        f.lastInbound = now
        f.unanswered  = 0
        f.verifying   = false
        flows[key] = f
    }

    // MARK: lifecycle

    func removeUpstream(profileID: String) {
        lock.lock(); defer { lock.unlock() }
        flows = flows.filter { $0.key.profileID != profileID }
    }

    func onTransportRebuilt(profileID: String) {
        lock.lock(); defer { lock.unlock() }
        for (k, var f) in flows where k.profileID == profileID {
            f.unanswered = 0
            f.lastProbe  = nil
            f.verifying  = true
            flows[k] = f
        }
    }

    func hasVerifyingFlows(connected: Set<String>) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return flows.contains { connected.contains($0.key.profileID) && $0.value.verifying }
    }

    func flushAsDead(profileID: String) -> [Data] {
        lock.lock(); defer { lock.unlock() }
        var rsts: [Data] = []
        for (key, flow) in flows where key.profileID == profileID {
            rsts.append(buildRST(key, flow))
            flows.removeValue(forKey: key)
        }
        return rsts
    }

    var trackedCount: Int { lock.lock(); defer { lock.unlock() }; return flows.count }

    // MARK: probe cycle (driven by the provider's timer / wake)

    func runCycle(connected: Set<String>, now: Date = Date()) -> [Action] {
        lock.lock(); defer { lock.unlock() }
        var actions: [Action] = []

        for (key, var f) in flows {
            // Hard eviction for anything we've completely lost track of.
            if now.timeIntervalSince(f.lastOutbound) > maxIdle,
               now.timeIntervalSince(f.lastInbound) > maxIdle {
                flows.removeValue(forKey: key); continue
            }
            guard connected.contains(key.profileID) else { continue }

            guard now.timeIntervalSince(f.lastInbound) >= idleThreshold else {
                f.unanswered = 0; f.lastProbe = nil; f.verifying = false
                flows[key] = f; continue
            }

            if now.timeIntervalSince(f.lastOutbound) < idleThreshold { f.verifying = true }

            let minGap = f.verifying ? verifyProbeGap : idleThreshold
            if let lp = f.lastProbe, now.timeIntervalSince(lp) < minGap {
                flows[key] = f; continue
            }

            // Count the previous probe as unanswered if nothing came back since.
            if let lp = f.lastProbe, f.lastInbound <= lp { f.unanswered += 1 }

            if f.unanswered >= deadAfter {
                actions.append(.reset(profileID: key.profileID, packet: buildRST(key, f)))
                flows.removeValue(forKey: key)
                log.notice("flow \(IPv4.toString(key.peerIP), privacy: .public):\(key.peerPort, privacy: .public) dead after \(self.deadAfter, privacy: .public) probes — RST")
                continue
            }

            actions.append(.keepalive(profileID: key.profileID, packet: buildKeepalive(key, f)))
            f.lastProbe = now
            flows[key] = f
        }
        return actions
    }

    // MARK: packet construction

    private func buildKeepalive(_ key: FlowKey, _ f: Flow) -> Data {
        PacketBuilder.ipv4TCP(srcIP: utunInnerIP, dstIP: key.peerIP,
                              srcPort: key.hostPort, dstPort: key.peerPort,
                              seq: f.sndNxt &- 1, ack: f.rcvNxt,
                              flags: [.ack], window: f.window, payload: Data())
    }

    private func buildRST(_ key: FlowKey, _ f: Flow) -> Data {
        PacketBuilder.ipv4TCP(srcIP: key.peerIP, dstIP: utunInnerIP,
                              srcPort: key.peerPort, dstPort: key.hostPort,
                              seq: f.rcvNxt, ack: f.sndNxt,
                              flags: [.rst, .ack], window: 0, payload: Data())
    }

    // MARK: helpers

    private static func parseTCP(_ packet: Data) -> (IPv4Header, TCPSegment)? {
        guard let ip = IPv4Header.parse(packet), ip.proto == IPProtocol.tcp.rawValue,
              packet.count >= ip.headerLength + TCPSegment.minLength else { return nil }
        guard let tcp = TCPSegment.parse(Data(packet.suffix(from: ip.headerLength))) else { return nil }
        return (ip, tcp)
    }
}
