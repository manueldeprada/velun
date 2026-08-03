import Foundation

private let U0: UInt32   = 0xC612_0001   // 198.18.0.1
private let PEER: UInt32 = 0x0A0F_0129   // 10.15.1.41
private let HOST_PORT: UInt16 = 53822
private let PEER_PORT: UInt16 = 22

private func outbound(seq: UInt32, ack: UInt32, flags: TCPFlags,
                      payloadLen: Int = 0, window: UInt16 = 65535) -> Data {
    PacketBuilder.ipv4TCP(srcIP: U0, dstIP: PEER,
                          srcPort: HOST_PORT, dstPort: PEER_PORT,
                          seq: seq, ack: ack, flags: flags, window: window,
                          payload: Data(repeating: 0x41, count: payloadLen))
}

private func inbound(seq: UInt32, ack: UInt32, flags: TCPFlags,
                     payloadLen: Int = 0) -> Data {
    PacketBuilder.ipv4TCP(srcIP: PEER, dstIP: U0,
                          srcPort: PEER_PORT, dstPort: HOST_PORT,
                          seq: seq, ack: ack, flags: flags, window: 65535,
                          payload: Data(repeating: 0x42, count: payloadLen))
}

private func parse(_ data: Data) -> (IPv4Header, TCPSegment)? {
    guard let ip = IPv4Header.parse(data),
          let tcp = TCPSegment.parse(Data(data.suffix(from: ip.headerLength))) else { return nil }
    return (ip, tcp)
}

private let T0 = Date(timeIntervalSince1970: 1_700_000_000)

func testFlowKeeperProbesIdleFlow() {
    R.enter("FlowKeeper/Probe")
    let fk = FlowKeeper(utunInnerIP: U0)
    // host sent 5 bytes at seq 1000, acking peer up to 5000
    fk.observeOutbound(outbound(seq: 1000, ack: 5000, flags: [.ack, .psh], payloadLen: 5),
                       profileID: "p", now: T0)
    R.assertEqual(fk.trackedCount, 1, "flow tracked after first outbound")

    // active (10s < idleThreshold 25) ⇒ no probe
    R.assertEqual(fk.runCycle(connected: ["p"], now: T0.addingTimeInterval(10)).count, 0,
                  "active flow not probed")

    // idle ⇒ exactly one keepalive
    let acts = fk.runCycle(connected: ["p"], now: T0.addingTimeInterval(30))
    R.assertEqual(acts.count, 1, "one keepalive for the idle flow")
    guard case let .keepalive(pid, pkt)? = acts.first else {
        R.assertTrue(false, "action is a keepalive"); return
    }
    R.assertEqual(pid, "p", "keepalive carries profileID")
    guard let (ip, tcp) = parse(pkt) else { R.assertTrue(false, "keepalive parses"); return }
    R.assertEqual(ip.sourceAddress, U0, "keepalive src = U0 (provider NATs to A_u)")
    R.assertEqual(ip.destinationAddress, PEER, "keepalive dst = peer")
    R.assertEqual(tcp.sourcePort, HOST_PORT, "keepalive src port = host port")
    R.assertEqual(tcp.destinationPort, PEER_PORT, "keepalive dst port = peer port")
    R.assertEqual(tcp.sequenceNumber, 1004, "keepalive seq = SND.NXT-1 (1005-1)")
    R.assertEqual(tcp.ackNumber, 5000, "keepalive ack = host RCV.NXT")
    R.assertTrue(tcp.flags.contains(.ack), "keepalive has ACK")
    R.assertTrue(!tcp.flags.contains(.rst) && !tcp.flags.contains(.syn), "keepalive is a bare ACK")
    R.assertEqual(tcp.payload.count, 0, "keepalive carries no payload")
}

func testFlowKeeperAnsweredStaysWarm() {
    R.enter("FlowKeeper/Warm")
    let fk = FlowKeeper(utunInnerIP: U0)
    fk.observeOutbound(outbound(seq: 1000, ack: 5000, flags: [.ack]), profileID: "p", now: T0)
    var now = T0
    var sawReset = false
    for _ in 1...10 {
        now = now.addingTimeInterval(30)
        let acts = fk.runCycle(connected: ["p"], now: now)
        for a in acts {
            if case .reset = a { sawReset = true }
            if case .keepalive = a {
                // peer answers the probe with a bare ACK
                fk.observeInbound(inbound(seq: 5000, ack: 1000, flags: [.ack]),
                                  profileID: "p", now: now.addingTimeInterval(1))
            }
        }
    }
    R.assertTrue(!sawReset, "answered flow is never RST")
    R.assertEqual(fk.trackedCount, 1, "answered flow stays tracked")
}

func testFlowKeeperRSTsDeadFlow() {
    R.enter("FlowKeeper/Reset")
    let fk = FlowKeeper(utunInnerIP: U0, deadAfter: 4)
    fk.observeOutbound(outbound(seq: 1000, ack: 5000, flags: [.ack]), profileID: "p", now: T0)
    var now = T0
    var reset: Data?
    for _ in 1...6 {
        now = now.addingTimeInterval(30)
        for a in fk.runCycle(connected: ["p"], now: now) {
            if case let .reset(_, pkt) = a { reset = pkt }
        }
    }
    R.assertTrue(reset != nil, "dead flow eventually RST")
    R.assertEqual(fk.trackedCount, 0, "RST'd flow is evicted")
    guard let pkt = reset, let (ip, tcp) = parse(pkt) else {
        R.assertTrue(false, "RST parses"); return
    }
    R.assertEqual(ip.sourceAddress, PEER, "RST src = peer (host-facing)")
    R.assertEqual(ip.destinationAddress, U0, "RST dst = U0")
    R.assertEqual(tcp.sourcePort, PEER_PORT, "RST src port = peer port")
    R.assertEqual(tcp.destinationPort, HOST_PORT, "RST dst port = host port")
    R.assertTrue(tcp.flags.contains(.rst), "RST flag set")
    R.assertEqual(tcp.sequenceNumber, 5000, "RST seq = host RCV.NXT (RFC 5961)")
}

func testFlowKeeperDisconnectedNoPenalty() {
    R.enter("FlowKeeper/Disconnected")
    let fk = FlowKeeper(utunInnerIP: U0)
    fk.observeOutbound(outbound(seq: 1000, ack: 5000, flags: [.ack]), profileID: "p", now: T0)
    var now = T0
    for _ in 1...10 {
        now = now.addingTimeInterval(30)
        R.assertEqual(fk.runCycle(connected: [], now: now).count, 0,
                      "no actions while upstream disconnected")
    }
    R.assertEqual(fk.trackedCount, 1, "flow retained, never falsely RST while down")
}

func testFlowKeeperEvictsOnClose() {
    R.enter("FlowKeeper/Close")
    let fk = FlowKeeper(utunInnerIP: U0)
    fk.observeOutbound(outbound(seq: 1000, ack: 5000, flags: [.ack]), profileID: "p", now: T0)
    fk.observeOutbound(outbound(seq: 1000, ack: 5000, flags: [.fin, .ack]), profileID: "p", now: T0)
    R.assertEqual(fk.trackedCount, 0, "host FIN evicts the flow")

    fk.observeOutbound(outbound(seq: 2000, ack: 6000, flags: [.ack]), profileID: "p", now: T0)
    fk.observeInbound(inbound(seq: 6000, ack: 2000, flags: [.rst]), profileID: "p", now: T0)
    R.assertEqual(fk.trackedCount, 0, "peer RST evicts the flow")
}

func testFlowKeeperRebuildResetsProbes() {
    R.enter("FlowKeeper/Rebuild")
    let fk = FlowKeeper(utunInnerIP: U0, deadAfter: 4)
    fk.observeOutbound(outbound(seq: 1000, ack: 5000, flags: [.ack]), profileID: "p", now: T0)
    var now = T0
    for _ in 1...4 { now = now.addingTimeInterval(30); _ = fk.runCycle(connected: ["p"], now: now) }
    // unanswered is now 3 — one more cycle would RST. A rebuild clears it.
    fk.onTransportRebuilt(profileID: "p")
    now = now.addingTimeInterval(30)
    var sawReset = false, sawKeepalive = false
    for a in fk.runCycle(connected: ["p"], now: now) {
        if case .reset = a { sawReset = true }
        if case .keepalive = a { sawKeepalive = true }
    }
    R.assertTrue(!sawReset, "no RST right after a transport rebuild")
    R.assertTrue(sawKeepalive, "probing resumes after rebuild")
    R.assertEqual(fk.trackedCount, 1, "flow survived the rebuild")
}

func testFlowKeeperThrottlesNearCycles() {
    R.enter("FlowKeeper/Throttle")
    let fk = FlowKeeper(utunInnerIP: U0)
    fk.observeOutbound(outbound(seq: 1000, ack: 5000, flags: [.ack]), profileID: "p", now: T0)
    // First idle cycle probes.
    let first = fk.runCycle(connected: ["p"], now: T0.addingTimeInterval(30))
    R.assertEqual(first.count, 1, "first idle cycle probes")
    // A near-simultaneous second cycle (a wake() racing the timer) is throttled.
    let second = fk.runCycle(connected: ["p"], now: T0.addingTimeInterval(31))
    R.assertEqual(second.count, 0, "near-duplicate cycle is throttled (no double probe)")
    // A cycle past idleThreshold probes again.
    let third = fk.runCycle(connected: ["p"], now: T0.addingTimeInterval(60))
    R.assertEqual(third.count, 1, "cycle past idleThreshold probes again")
}

func testFlowKeeperFlushAsDead() {
    R.enter("FlowKeeper/Flush")
    let fk = FlowKeeper(utunInnerIP: U0)
    fk.observeOutbound(outbound(seq: 1000, ack: 5000, flags: [.ack]), profileID: "p", now: T0)
    R.assertEqual(fk.trackedCount, 1, "flow tracked")
    let rsts = fk.flushAsDead(profileID: "p")
    R.assertEqual(rsts.count, 1, "one RST emitted for the flushed flow")
    R.assertEqual(fk.trackedCount, 0, "flows cleared after flush")
    guard let (ip, tcp) = parse(rsts[0]) else { R.assertTrue(false, "flush RST parses"); return }
    R.assertEqual(ip.sourceAddress, PEER, "flush RST src = peer")
    R.assertEqual(ip.destinationAddress, U0, "flush RST dst = U0")
    R.assertTrue(tcp.flags.contains(.rst), "flush RST has RST flag")
    R.assertEqual(tcp.sequenceNumber, 5000, "flush RST seq = host RCV.NXT")
    R.assertEqual(fk.flushAsDead(profileID: "absent").count, 0, "flush of unknown profile is empty")
}

func testFlowKeeperRetransmitsDontShieldZombie() {
    R.enter("FlowKeeper/RetransmitZombie")
    let fk = FlowKeeper(utunInnerIP: U0, deadAfter: 4)
    fk.observeOutbound(outbound(seq: 1000, ack: 5000, flags: [.ack, .psh], payloadLen: 5),
                       profileID: "p", now: T0)
    var now = T0
    var reset: Data?
    for _ in 1...40 where reset == nil {
        now = now.addingTimeInterval(5)
        fk.observeOutbound(outbound(seq: 1000, ack: 5000, flags: [.ack, .psh], payloadLen: 5),
                           profileID: "p", now: now)   // retransmit
        for a in fk.runCycle(connected: ["p"], now: now) {
            if case let .reset(_, pkt) = a { reset = pkt }
        }
    }
    R.assertTrue(reset != nil, "retransmitting zombie is RST despite continuous outbound")
    R.assertTrue(now.timeIntervalSince(T0) <= 60, "verdict lands fast (auto-promoted to verify cadence)")
    R.assertEqual(fk.trackedCount, 0, "RST'd zombie is evicted")
    guard let pkt = reset, let (_, tcp) = parse(pkt) else { R.assertTrue(false, "RST parses"); return }
    R.assertEqual(tcp.sequenceNumber, 5000, "RST seq = host RCV.NXT")
}

func testFlowKeeperVerifyModeFastVerdict() {
    R.enter("FlowKeeper/Verify")
    let fk = FlowKeeper(utunInnerIP: U0, deadAfter: 4)
    fk.observeOutbound(outbound(seq: 1000, ack: 5000, flags: [.ack]), profileID: "p", now: T0)
    let alivePort: UInt16 = 54000
    fk.observeOutbound(PacketBuilder.ipv4TCP(srcIP: U0, dstIP: PEER,
                                             srcPort: alivePort, dstPort: PEER_PORT,
                                             seq: 2000, ack: 7000, flags: [.ack],
                                             window: 65535, payload: Data()),
                       profileID: "p", now: T0)
    fk.onTransportRebuilt(profileID: "p")
    R.assertTrue(fk.hasVerifyingFlows(connected: ["p"]), "flows verifying after rebuild")
    R.assertTrue(!fk.hasVerifyingFlows(connected: []), "verify check scoped to connected upstreams")

    // Burst cycles at the 4 s verify cadence, as the provider drives them.
    var now = T0.addingTimeInterval(60)
    var reset: Data?
    var answered = false
    for _ in 1...8 where reset == nil {
        for a in fk.runCycle(connected: ["p"], now: now) {
            if case let .reset(_, pkt) = a { reset = pkt }
            if case let .keepalive(_, pkt) = a, let (_, tcp) = parse(pkt),
               tcp.sourcePort == alivePort, !answered {
                answered = true
                fk.observeInbound(PacketBuilder.ipv4TCP(srcIP: PEER, dstIP: U0,
                                                        srcPort: PEER_PORT, dstPort: alivePort,
                                                        seq: 7000, ack: 2000, flags: [.ack],
                                                        window: 65535, payload: Data()),
                                  profileID: "p", now: now.addingTimeInterval(1))
            }
        }
        now = now.addingTimeInterval(4)
    }
    R.assertTrue(reset != nil, "dead flow RST at the verify cadence")
    R.assertTrue(now.timeIntervalSince(T0.addingTimeInterval(60)) <= 24,
                 "verdict within ~20 s of the rebuild, not 4 × 75 s")
    guard let pkt = reset, let (_, tcp) = parse(pkt) else { R.assertTrue(false, "RST parses"); return }
    R.assertEqual(tcp.destinationPort, HOST_PORT, "the dead flow (not the answered one) was RST")
    R.assertEqual(fk.trackedCount, 1, "answered flow survives verification")
    R.assertTrue(!fk.hasVerifyingFlows(connected: ["p"]), "nothing left verifying after the verdict")
}

func testFlowKeeperScopesByProfile() {
    R.enter("FlowKeeper/Scope")
    let fk = FlowKeeper(utunInnerIP: U0)
    fk.observeOutbound(outbound(seq: 1000, ack: 5000, flags: [.ack]), profileID: "a", now: T0)
    fk.observeOutbound(outbound(seq: 1000, ack: 5000, flags: [.ack]), profileID: "b", now: T0)
    R.assertEqual(fk.trackedCount, 2, "same 5-tuple on two upstreams = two flows")
    fk.removeUpstream(profileID: "a")
    R.assertEqual(fk.trackedCount, 1, "removeUpstream drops only that profile's flows")
}
