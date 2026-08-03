import Foundation

// MARK: – local builders / validators (independent of PacketNAT)

private func addrBytes(_ ip: UInt32) -> [UInt8] {
    [UInt8((ip >> 24) & 0xff), UInt8((ip >> 16) & 0xff),
     UInt8((ip >> 8) & 0xff),  UInt8(ip & 0xff)]
}

private func words16(_ bytes: [UInt8]) -> [UInt16] {
    var out: [UInt16] = []
    var i = 0
    while i + 1 < bytes.count { out.append(UInt16(bytes[i]) << 8 | UInt16(bytes[i + 1])); i += 2 }
    if i < bytes.count { out.append(UInt16(bytes[i]) << 8) }   // pad odd tail
    return out
}

private func onesSum(_ ws: [UInt16]) -> UInt16 {
    var sum: UInt32 = 0
    for w in ws { sum += UInt32(w) }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
    return UInt16(sum & 0xffff)
}

private func ipHeaderValid(_ pkt: Data) -> Bool {
    let b = [UInt8](pkt)
    guard b.count >= 20 else { return false }
    let hl = Int(b[0] & 0x0f) * 4
    guard b.count >= hl else { return false }
    return onesSum(words16(Array(b[0..<hl]))) == 0xffff
}

private func transportValid(_ pkt: Data, proto: UInt8) -> Bool {
    let b = [UInt8](pkt)
    let hl = Int(b[0] & 0x0f) * 4
    let total = Int(UInt16(b[2]) << 8 | UInt16(b[3]))
    guard total <= b.count, total > hl else { return false }
    let seg = Array(b[hl..<total])
    var pseudo = Array(b[12..<20])          // src + dst addresses
    pseudo += [0, proto]
    let len = UInt16(seg.count)
    pseudo += [UInt8(len >> 8), UInt8(len & 0xff)]
    return onesSum(words16(pseudo + seg)) == 0xffff
}

private func icmpChecksumBytes(_ pkt: Data) -> [UInt8] {
    let b = [UInt8](pkt)
    let hl = Int(b[0] & 0x0f) * 4
    return [b[hl + 2], b[hl + 3]]            // ICMP checksum is at L4 off 2..3
}

private func buildIPv4(proto: UInt8, srcIP: UInt32, dstIP: UInt32,
                       transport: Data, ipID: UInt16 = 0x1234) -> Data {
    let totalLen = UInt16(20 + transport.count)
    var ip: [UInt8] = [0x45, 0x00,
                       UInt8(totalLen >> 8), UInt8(totalLen & 0xff),
                       UInt8(ipID >> 8), UInt8(ipID & 0xff),
                       0x40, 0x00, 64, proto, 0, 0]
    ip += addrBytes(srcIP)
    ip += addrBytes(dstIP)
    let cs = ipChecksum(Data(ip))            // from IPv4Packet.swift
    ip[10] = UInt8(cs >> 8); ip[11] = UInt8(cs & 0xff)
    return Data(ip) + transport
}

private func transportChecksum(srcIP: UInt32, dstIP: UInt32, proto: UInt8,
                               segment: Data) -> UInt16 {
    var pseudo = Data(addrBytes(srcIP) + addrBytes(dstIP))
    pseudo.append(0); pseudo.append(proto)
    let len = UInt16(segment.count)
    pseudo.append(UInt8(len >> 8)); pseudo.append(UInt8(len & 0xff))
    return ipChecksum(pseudo + segment)
}

private func buildUDP(srcIP: UInt32, dstIP: UInt32, srcPort: UInt16, dstPort: UInt16,
                      payload: Data, zeroChecksum: Bool = false) -> Data {
    let udpLen = UInt16(8 + payload.count)
    var udp: [UInt8] = [UInt8(srcPort >> 8), UInt8(srcPort & 0xff),
                        UInt8(dstPort >> 8), UInt8(dstPort & 0xff),
                        UInt8(udpLen >> 8),  UInt8(udpLen & 0xff),
                        0, 0]                // checksum placeholder
    var seg = Data(udp) + payload
    if !zeroChecksum {
        let cs = transportChecksum(srcIP: srcIP, dstIP: dstIP, proto: 17, segment: seg)
        seg[6] = UInt8(cs >> 8); seg[7] = UInt8(cs & 0xff)
    }
    _ = udp
    return buildIPv4(proto: 17, srcIP: srcIP, dstIP: dstIP, transport: seg)
}

private func buildICMPEcho(srcIP: UInt32, dstIP: UInt32, payload: Data) -> Data {
    var icmp: [UInt8] = [8, 0, 0, 0, 0x00, 0x01, 0x00, 0x05]   // type/code/cksum/id/seq
    var seg = Data(icmp) + payload
    let cs = ipChecksum(seg)                  // ICMP checksum covers ICMP message only
    seg[2] = UInt8(cs >> 8); seg[3] = UInt8(cs & 0xff)
    _ = icmp
    return buildIPv4(proto: 1, srcIP: srcIP, dstIP: dstIP, transport: seg)
}

// MARK: – tests

func testPacketNATRejectsNonIPv4() {
    R.enter("PacketNAT rejects non-IPv4 / short")
    var ipv6 = Data([0x60, 0, 0, 0] + [UInt8](repeating: 0, count: 36))
    let before6 = ipv6
    R.assertTrue(!PacketNAT.rewriteSource(&ipv6, to: 0x0a000001), "IPv6 first nibble rejected")
    R.assertEqual(ipv6, before6, "IPv6 packet left untouched")

    var short = Data([0x45, 0, 0, 8, 0, 0, 0, 0])
    let beforeS = short
    R.assertTrue(!PacketNAT.rewriteSource(&short, to: 0x0a000001), "truncated header rejected")
    R.assertEqual(short, beforeS, "short packet left untouched")
}

func testPacketNATSourceRewriteTCP() {
    R.enter("PacketNAT source rewrite (TCP)")
    let s: UInt32 = 0x6442_0105   // 100.66.1.5
    let d: UInt32 = 0x81_84_fa_05 // 129.132.250.5
    let s2: UInt32 = 0x0a0f_0007  // 10.15.0.7
    var pkt = PacketBuilder.ipv4TCP(srcIP: s, dstIP: d, srcPort: 51000, dstPort: 22,
                                    seq: 0x1111_2222, ack: 0x3333_4444,
                                    flags: [.psh, .ack], window: 65535,
                                    payload: Data("hello tunnel".utf8))
    R.assertTrue(ipHeaderValid(pkt), "built TCP packet: IP checksum valid")
    R.assertTrue(transportValid(pkt, proto: 6), "built TCP packet: TCP checksum valid")

    R.assertTrue(PacketNAT.rewriteSource(&pkt, to: s2), "rewriteSource returns true")
    let b = [UInt8](pkt)
    R.assertEqual(UInt32(b[12]) << 24 | UInt32(b[13]) << 16 | UInt32(b[14]) << 8 | UInt32(b[15]),
                  s2, "source address now s2")
    R.assertTrue(ipHeaderValid(pkt), "after rewrite: IP checksum still valid")
    R.assertTrue(transportValid(pkt, proto: 6), "after rewrite: TCP checksum still valid (incremental == recompute)")
}

func testPacketNATRoundTripTCP() {
    R.enter("PacketNAT round-trips (TCP)")
    let s: UInt32 = 0x6442_0105
    let d: UInt32 = 0x0a0f_0001
    let orig = PacketBuilder.ipv4TCP(srcIP: s, dstIP: d, srcPort: 40000, dstPort: 443,
                                     seq: 7, ack: 9, flags: [.syn], window: 1024,
                                     payload: Data(), mss: 1380)
    var pkt = orig
    R.assertTrue(PacketNAT.rewriteSource(&pkt, to: 0x0a0f_00ff), "rewrite away")
    R.assertTrue(PacketNAT.rewriteSource(&pkt, to: s), "rewrite back")
    R.assertEqual(pkt, orig, "src A→B→A restores original bytes exactly")

    // dest round-trip too
    var pkt2 = orig
    R.assertTrue(PacketNAT.rewriteDestination(&pkt2, to: 0x0808_0808), "dst away")
    R.assertTrue(PacketNAT.rewriteDestination(&pkt2, to: d), "dst back")
    R.assertEqual(pkt2, orig, "dst A→B→A restores original bytes exactly")
}

func testPacketNATNoOpSameIP() {
    R.enter("PacketNAT no-op when address unchanged")
    let s: UInt32 = 0x0a0f_0007
    let orig = PacketBuilder.ipv4TCP(srcIP: s, dstIP: 0x0808_0808, srcPort: 1, dstPort: 2,
                                     seq: 0, ack: 0, flags: [.ack], window: 100, payload: Data())
    var pkt = orig
    R.assertTrue(PacketNAT.rewriteSource(&pkt, to: s), "returns true for same-IP")
    R.assertEqual(pkt, orig, "packet unchanged when rewriting to identical IP")
}

func testPacketNATDestRewriteUDP() {
    R.enter("PacketNAT dest rewrite (UDP)")
    let s: UInt32 = 0x0a0f_0007
    let d: UInt32 = 0x0a03_0705   // 10.3.7.5 (corp DNS)
    let d2: UInt32 = 0x6442_0102
    var pkt = buildUDP(srcIP: s, dstIP: d, srcPort: 53001, dstPort: 53,
                       payload: Data([0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]))
    R.assertTrue(ipHeaderValid(pkt), "built UDP packet: IP checksum valid")
    R.assertTrue(transportValid(pkt, proto: 17), "built UDP packet: UDP checksum valid")

    R.assertTrue(PacketNAT.rewriteDestination(&pkt, to: d2), "rewriteDestination returns true")
    let b = [UInt8](pkt)
    R.assertEqual(UInt32(b[16]) << 24 | UInt32(b[17]) << 16 | UInt32(b[18]) << 8 | UInt32(b[19]),
                  d2, "dest address now d2")
    R.assertTrue(ipHeaderValid(pkt), "after rewrite: IP checksum valid")
    R.assertTrue(transportValid(pkt, proto: 17), "after rewrite: UDP checksum valid")
}

func testPacketNATUDPZeroChecksumPreserved() {
    R.enter("PacketNAT preserves UDP checksum=0 (disabled)")
    var pkt = buildUDP(srcIP: 0x0a0f_0007, dstIP: 0x0a03_0705,
                       srcPort: 1, dstPort: 53, payload: Data([1, 2, 3, 4]),
                       zeroChecksum: true)
    let hl = Int([UInt8](pkt)[0] & 0x0f) * 4
    R.assertTrue(PacketNAT.rewriteSource(&pkt, to: 0x6442_0102), "rewrite a zero-checksum UDP packet")
    let b = [UInt8](pkt)
    R.assertTrue(b[hl + 6] == 0 && b[hl + 7] == 0, "UDP checksum stays 0 (never fabricated)")
    R.assertTrue(ipHeaderValid(pkt), "IP checksum still valid")
}

func testPacketNATICMPLeavesL4ChecksumAlone() {
    R.enter("PacketNAT ICMP: IP checksum only")
    let s: UInt32 = 0x0a0f_0007
    var pkt = buildICMPEcho(srcIP: s, dstIP: 0x0a0f_0001, payload: Data("ping".utf8))
    let before = icmpChecksumBytes(pkt)
    R.assertTrue(PacketNAT.rewriteSource(&pkt, to: 0x6442_0109), "rewrite ICMP source")
    let after = icmpChecksumBytes(pkt)
    R.assertEqual(after, before, "ICMP L4 checksum untouched (doesn't cover IP addresses)")
    R.assertTrue(ipHeaderValid(pkt), "IP checksum updated and valid")
    let b = [UInt8](pkt)
    R.assertEqual(UInt32(b[12]) << 24 | UInt32(b[13]) << 16 | UInt32(b[14]) << 8 | UInt32(b[15]),
                  UInt32(0x6442_0109), "ICMP source address changed")
}
