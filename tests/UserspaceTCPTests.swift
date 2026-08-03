import Foundation

private final class CaptureDelegate: UserspaceTCPDelegate {
    var emitted: [Data] = []
    var received: [Data] = []
    var established = 0
    var closed = 0
    var closeError: Error?

    func tcpDidEmitPacket(_ packet: Data, connection: UserspaceTCPConnection) {
        emitted.append(packet)
    }
    func tcpDidReceiveData(_ data: Data, connection: UserspaceTCPConnection) {
        received.append(data)
    }
    func tcpDidEstablish(_ connection: UserspaceTCPConnection) { established += 1 }
    func tcpDidClose(_ connection: UserspaceTCPConnection, error: Error?) {
        closed += 1; closeError = error
    }

    func lastTCP() -> TCPSegment? {
        guard let last = emitted.last,
              let ip = IPv4Header.parse(last) else { return nil }
        return TCPSegment.parse(Data(last.suffix(from: ip.headerLength)))
    }
}

private func conn() -> (UserspaceTCPConnection, CaptureDelegate) {
    let c = UserspaceTCPConnection(
        localIP: 0x0a000001, localPort: 12345,
        remoteIP: 0x0a000002, remotePort: 22,
        mss: 1380
    )
    let d = CaptureDelegate()
    c.delegate = d
    return (c, d)
}

// Inbound segment from the peer to drive `c.handle(...)`.
private func peerSegment(srcPort: UInt16 = 22,
                         dstPort: UInt16 = 12345,
                         seq: UInt32, ack: UInt32,
                         flags: TCPFlags,
                         payload: Data = Data()) -> TCPSegment {
    TCPSegment(
        sourcePort: srcPort, destinationPort: dstPort,
        sequenceNumber: seq, ackNumber: ack,
        dataOffset: 5, flags: flags, window: 65535,
        checksum: 0, urgentPointer: 0, payload: payload, mss: nil
    )
}

func testTCPOpenSendsSYN() {
    R.enter("UserspaceTCP/Open")
    let (c, d) = conn()
    c.open()
    R.assertEqual(c.state, .synSent, "state .synSent after open")
    R.assertEqual(d.emitted.count, 1, "one packet emitted")
    R.assertTrue(d.lastTCP()?.flags.contains(.syn) ?? false, "SYN flag set")
    R.assertEqual(d.lastTCP()?.mss ?? 0, 1380, "SYN includes MSS option")
}

func testTCPSynAckCompletesHandshake() {
    R.enter("UserspaceTCP/Handshake")
    let (c, d) = conn()
    c.open()
    let sentSeq = d.lastTCP()!.sequenceNumber
    let synAck = peerSegment(seq: 5000,
                             ack: sentSeq &+ 1,
                             flags: [.syn, .ack])
    c.handle(synAck)
    R.assertEqual(c.state, .established, "state .established")
    R.assertEqual(d.established, 1, "onEstablished fired")
    R.assertTrue(d.lastTCP()?.flags.contains(.ack) ?? false, "ACK reply emitted")
    R.assertEqual(d.lastTCP()?.ackNumber ?? 0, 5001, "ack number = peer seq + 1")
}

func testTCPSendBuffersUntilEstablished() {
    R.enter("UserspaceTCP/Send")
    let (c, _) = conn()
    c.open()
    c.send(Data("hi".utf8))
    R.assertEqual(c.state, .synSent, "still .synSent before SYN-ACK")
    // Data should not flush before .established.
}

func testTCPSendFlushesAfterEstablished() {
    R.enter("UserspaceTCP/Send")
    let (c, d) = conn()
    c.open()
    let openSeq = d.lastTCP()!.sequenceNumber
    c.handle(peerSegment(seq: 1000, ack: openSeq &+ 1, flags: [.syn, .ack]))
    d.emitted.removeAll()
    c.send(Data("hi".utf8))

    R.assertEqual(d.emitted.count, 1, "one data packet emitted")
    let last = d.lastTCP()!
    R.assertTrue(last.flags.contains(.psh), "PSH on payload")
    R.assertTrue(last.flags.contains(.ack), "ACK piggybacked")
    R.assertEqual(String(decoding: last.payload, as: UTF8.self), "hi", "payload bytes")
}

func testTCPReceivedDataDeliveredInOrder() {
    R.enter("UserspaceTCP/Receive")
    let (c, d) = conn()
    c.open()
    let openSeq = d.lastTCP()!.sequenceNumber
    c.handle(peerSegment(seq: 1000, ack: openSeq &+ 1, flags: [.syn, .ack]))

    c.handle(peerSegment(seq: 1001, ack: openSeq &+ 1,
                         flags: [.psh, .ack], payload: Data("ABC".utf8)))
    R.assertEqual(d.received.count, 1, "one data callback")
    R.assertEqual(String(decoding: d.received.last ?? Data(), as: UTF8.self), "ABC", "bytes delivered")
}

func testTCPCloseSendsFINInEstablished() {
    R.enter("UserspaceTCP/Close")
    let (c, d) = conn()
    c.open()
    let openSeq = d.lastTCP()!.sequenceNumber
    c.handle(peerSegment(seq: 1000, ack: openSeq &+ 1, flags: [.syn, .ack]))
    d.emitted.removeAll()
    c.close()
    R.assertEqual(c.state, .finWait1, "state .finWait1")
    R.assertTrue(d.lastTCP()?.flags.contains(.fin) ?? false, "FIN flag")
}

func testTCPPeerFINTransitionsToCloseWait() {
    R.enter("UserspaceTCP/Close")
    let (c, d) = conn()
    c.open()
    let openSeq = d.lastTCP()!.sequenceNumber
    c.handle(peerSegment(seq: 1000, ack: openSeq &+ 1, flags: [.syn, .ack]))
    c.handle(peerSegment(seq: 1001, ack: openSeq &+ 1, flags: [.fin, .ack]))
    R.assertEqual(c.state, .closeWait, "state .closeWait")
    // Empty data delivered as EOF marker.
    R.assertEqual(d.received.last?.count ?? -1, 0, "EOF marker (empty data)")
}

func testTCPRSTTearsDown() {
    R.enter("UserspaceTCP/Reset")
    let (c, d) = conn()
    c.open()
    c.handle(peerSegment(seq: 0, ack: 0, flags: [.rst]))
    R.assertEqual(c.state, .closed, "state .closed")
    R.assertEqual(d.closed, 1, "onClose fired")
    R.assertTrue(d.closeError != nil, "error reported")
}
