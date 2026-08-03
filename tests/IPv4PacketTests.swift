import Foundation

func testIPv4HeaderParseRejectsShort() {
    R.enter("IPv4HeaderParse")
    R.assertTrue(IPv4Header.parse(Data()) == nil, "empty data → nil")
    R.assertTrue(IPv4Header.parse(Data(repeating: 0, count: 19)) == nil, "<20 bytes → nil")
    R.assertTrue(IPv4Header.parse(Data([0x55] + Array(repeating: UInt8(0), count: 19))) == nil,
                 "IHL=5 in IPv6 packet → nil (version mismatch)")
}

func testIPv4HeaderParsesMinimalHeader() {
    R.enter("IPv4HeaderParse")
    let bytes: [UInt8] = [
        0x45, 0x00, 0x00, 0x28, 0xab, 0xcd, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        10, 0, 0, 1,
        10, 0, 0, 2,
    ]
    guard let h = IPv4Header.parse(Data(bytes)) else {
        R.assertTrue(false, "minimal header parsed"); return
    }
    R.assertEqual(h.version, 4, "version 4")
    R.assertEqual(h.ihl, 5, "IHL 5")
    R.assertEqual(h.totalLength, 40, "total length 40")
    R.assertEqual(h.proto, 6, "proto TCP")
    R.assertEqual(h.sourceAddress, 0x0a000001, "src 10.0.0.1")
    R.assertEqual(h.destinationAddress, 0x0a000002, "dst 10.0.0.2")
    R.assertEqual(h.headerLength, 20, "header length 20")
}

func testTCPSegmentParseRejectsShort() {
    R.enter("TCPSegmentParse")
    R.assertTrue(TCPSegment.parse(Data()) == nil, "empty → nil")
    R.assertTrue(TCPSegment.parse(Data(repeating: 0, count: 19)) == nil, "<20 bytes → nil")
}

func testTCPSegmentParsesSYNWithMSS() {
    R.enter("TCPSegmentParse")
    let bytes: [UInt8] = [
        0x30, 0x39, 0x00, 0x16,                     // src 12345, dst 22
        0x12, 0x34, 0x56, 0x78,                     // seq
        0x00, 0x00, 0x00, 0x00,                     // ack
        0x60, 0x02,                                 // dataOffset=6, SYN
        0x20, 0x00,                                 // window 8192
        0x00, 0x00, 0x00, 0x00,                     // csum, urg
        0x02, 0x04, 0x05, 0x64,                     // MSS option, 1380
    ]
    guard let s = TCPSegment.parse(Data(bytes)) else {
        R.assertTrue(false, "SYN segment parsed"); return
    }
    R.assertEqual(s.sourcePort, 12345, "src port")
    R.assertEqual(s.destinationPort, 22, "dst port")
    R.assertEqual(s.sequenceNumber, 0x12345678, "seq")
    R.assertTrue(s.flags.contains(.syn), "SYN flag")
    R.assertEqual(s.window, 8192, "window")
    R.assertEqual(s.headerLength, 24, "header 24 bytes")
    R.assertEqual(s.mss ?? 0, 1380, "MSS option")
    R.assertEqual(s.payload.count, 0, "no payload")
}

func testTCPSegmentParsesPayload() {
    R.enter("TCPSegmentParse")
    var bytes: [UInt8] = [
        0x00, 0x16, 0x30, 0x39,                     // src 22, dst 12345
        0x00, 0x00, 0x00, 0x10,                     // seq 16
        0x12, 0x34, 0x56, 0x79,                     // ack
        0x50, 0x18,                                 // dataOffset=5, PSH+ACK
        0xff, 0xff,                                 // window
        0x00, 0x00, 0x00, 0x00,                     // csum, urg
    ]
    bytes.append(contentsOf: "hi".utf8)
    guard let s = TCPSegment.parse(Data(bytes)) else {
        R.assertTrue(false, "payload segment parsed"); return
    }
    R.assertTrue(s.flags.contains(.psh), "PSH flag")
    R.assertTrue(s.flags.contains(.ack), "ACK flag")
    R.assertEqual(String(decoding: s.payload, as: UTF8.self), "hi", "payload")
}

func testPacketBuilderProducesParseableSYN() {
    R.enter("PacketBuilder")
    let pkt = PacketBuilder.ipv4TCP(
        srcIP: 0x0a000001, dstIP: 0x0a000002,
        srcPort: 12345, dstPort: 22,
        seq: 1000, ack: 0,
        flags: [.syn], window: 65535,
        payload: Data(),
        mss: 1380, ipID: 0xabcd
    )
    guard let ip = IPv4Header.parse(pkt) else {
        R.assertTrue(false, "IP parses"); return
    }
    R.assertEqual(ip.proto, 6, "TCP proto")
    R.assertEqual(Int(ip.totalLength), pkt.count, "total length matches")
    let tcp = TCPSegment.parse(Data(pkt.suffix(from: ip.headerLength)))
    R.assertTrue(tcp != nil, "TCP parses")
    R.assertEqual(tcp?.sourcePort ?? 0, 12345, "src port round-trip")
    R.assertEqual(tcp?.destinationPort ?? 0, 22, "dst port round-trip")
    R.assertEqual(tcp?.mss ?? 0, 1380, "MSS round-trip")
    R.assertTrue(tcp?.flags.contains(.syn) ?? false, "SYN flag")
}

func testPacketBuilderRoundTripsPayload() {
    R.enter("PacketBuilder")
    let payload = Data("hello world".utf8)
    let pkt = PacketBuilder.ipv4TCP(
        srcIP: 0x0a000001, dstIP: 0x0a000002,
        srcPort: 1234, dstPort: 80,
        seq: 0xdeadbeef, ack: 0xbabeface,
        flags: [.psh, .ack], window: 65535,
        payload: payload
    )
    let ip = IPv4Header.parse(pkt)!
    let tcp = TCPSegment.parse(Data(pkt.suffix(from: ip.headerLength)))!
    R.assertEqual(tcp.sequenceNumber, 0xdeadbeef, "seq round-trip")
    R.assertEqual(tcp.ackNumber, 0xbabeface, "ack round-trip")
    R.assertTrue(tcp.flags.contains(.psh), "PSH set")
    R.assertTrue(tcp.flags.contains(.ack), "ACK set")
    R.assertEqual(tcp.payload, payload, "payload bytes round-trip")
}

func testIPChecksumIsZeroWhenComputedOverFullHeader() {
    R.enter("Checksum")
    // RFC 1071: a header containing its own checksum must compute to 0.
    let pkt = PacketBuilder.ipv4TCP(
        srcIP: 0x0a000001, dstIP: 0x0a000002,
        srcPort: 10, dstPort: 20,
        seq: 0, ack: 0,
        flags: [.ack], window: 0,
        payload: Data()
    )
    let ipHdr = pkt.prefix(20)
    R.assertEqual(ipChecksum(Data(ipHdr)), 0, "header re-checksum is 0")
}

func testIPv4StringRoundTrip() {
    R.enter("IPv4String")
    R.assertEqual(IPv4.toUInt32("10.0.0.1"), 0x0a000001, "10.0.0.1 → uint32")
    R.assertEqual(IPv4.toString(0x0a000001), "10.0.0.1", "uint32 → 10.0.0.1")
    R.assertEqual(IPv4.toString(0xffffffff), "255.255.255.255", "broadcast")
    R.assertTrue(IPv4.toUInt32("not-an-ip") == nil, "garbage → nil")
    R.assertTrue(IPv4.toUInt32("256.0.0.0") == nil, "out-of-range → nil")
}
