import Foundation

// MARK: – local builders / validators

private func words16(_ bytes: [UInt8]) -> [UInt16] {
    var out: [UInt16] = []
    var i = 0
    while i + 1 < bytes.count { out.append(UInt16(bytes[i]) << 8 | UInt16(bytes[i + 1])); i += 2 }
    if i < bytes.count { out.append(UInt16(bytes[i]) << 8) }
    return out
}

private func onesSum(_ ws: [UInt16]) -> UInt16 {
    var sum: UInt32 = 0
    for w in ws { sum += UInt32(w) }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
    return UInt16(sum & 0xffff)
}

private func v6TransportChecksumValid(_ pkt: Data) -> Bool {
    let b = [UInt8](pkt)
    guard b.count >= 40, let (proto, off) = IPv6ExtensionHeader.transportHeader(b) else { return false }
    let upperLen = b.count - off
    var pseudo: [UInt8] = []
    pseudo += Array(b[8..<24])      // src
    pseudo += Array(b[24..<40])     // dst
    pseudo += [UInt8((upperLen >> 24) & 0xff), UInt8((upperLen >> 16) & 0xff),
               UInt8((upperLen >> 8) & 0xff),  UInt8(upperLen & 0xff)]
    pseudo += [0, 0, 0, proto]
    return onesSum(words16(pseudo) + words16(Array(b[off...]))) == 0xffff
}

private func v6Packet(src: String, dst: String, proto: UInt8, payload: [UInt8]) -> Data {
    var b: [UInt8] = [0x60, 0, 0, 0]
    b += [UInt8((payload.count >> 8) & 0xff), UInt8(payload.count & 0xff)]
    b += [proto, 64]
    b += IPv6Addr(src)!.bytes
    b += IPv6Addr(dst)!.bytes
    b += payload

    // Zero the checksum field, compute, write it back.
    guard let (p, off) = IPv6ExtensionHeader.transportHeader(b) else { return Data(b) }
    let cOff: Int
    switch p {
    case 6:  cOff = off + 16
    case 17: cOff = off + 6
    case 58: cOff = off + 2
    default: return Data(b)
    }
    b[cOff] = 0; b[cOff + 1] = 0
    let upperLen = b.count - off
    var pseudo: [UInt8] = []
    pseudo += Array(b[8..<24]) + Array(b[24..<40])
    pseudo += [UInt8((upperLen >> 24) & 0xff), UInt8((upperLen >> 16) & 0xff),
               UInt8((upperLen >> 8) & 0xff),  UInt8(upperLen & 0xff)]
    pseudo += [0, 0, 0, p]
    let ck = ~onesSum(words16(pseudo) + words16(Array(b[off...])))
    b[cOff] = UInt8(ck >> 8); b[cOff + 1] = UInt8(ck & 0xff)
    return Data(b)
}

/// A 20-byte TCP header plus payload.
private func tcpSegment(sport: UInt16, dport: UInt16, payload: [UInt8] = []) -> [UInt8] {
    var t: [UInt8] = []
    t += [UInt8(sport >> 8), UInt8(sport & 0xff), UInt8(dport >> 8), UInt8(dport & 0xff)]
    t += [0, 0, 0, 1]        // seq
    t += [0, 0, 0, 0]        // ack
    t += [0x50, 0x18]        // data offset 5, PSH|ACK
    t += [0xff, 0xff]        // window
    t += [0, 0]              // checksum (filled by builder)
    t += [0, 0]              // urgent
    return t + payload
}

private func srcOf6(_ d: Data) -> IPv6Addr? { IPv6Addr(bytes: [UInt8](d), at: 8) }
private func dstOf6(_ d: Data) -> IPv6Addr? { IPv6Addr(bytes: [UInt8](d), at: 24) }

// MARK: – Address

func testIPv6AddrParseAndFormat() {
    R.enter("IPv6Addr: parse + canonical format")

    R.assertEqual(IPv6Addr("2001:db8::1")?.string, "2001:db8::1", "round-trips a compressed address")
    R.assertEqual(IPv6Addr("2001:0DB8:0000:0000:0000:0000:0000:0001")?.string, "2001:db8::1",
                  "expands + lowercases to RFC 5952 canonical form")
    R.assertEqual(IPv6Addr("::1")?.string, "::1", "loopback")
    R.assertEqual(IPv6Addr("::")?.string, "::", "unspecified")
    R.assertEqual(IPv6Addr("fe80::1%en0")?.string, "fe80::1", "strips a zone suffix inet_pton would reject")
    R.assertEqual(IPv6Addr("  2001:db8::5  ")?.string, "2001:db8::5", "tolerates surrounding whitespace")

    R.assertTrue(IPv6Addr("nonsense") == nil, "rejects garbage")
    R.assertTrue(IPv6Addr("192.0.2.1") == nil, "rejects a bare IPv4 literal")
    R.assertTrue(IPv6Addr("") == nil, "rejects empty")
    R.assertTrue(IPv6Addr("2001:db8::1::2") == nil, "rejects a double compression")
}

func testIPv6AddrBytesRoundTrip() {
    R.enter("IPv6Addr: byte round-trip + halves")

    let a = IPv6Addr("2001:db8:85a3::8a2e:370:7334")!
    R.assertEqual(a.bytes.count, 16, "16 bytes")
    R.assertEqual(IPv6Addr(bytes: a.bytes, at: 0), a, "bytes → address round-trip")
    R.assertEqual(a.hi, 0x2001_0db8_85a3_0000, "high half is the first 8 wire bytes")
    R.assertEqual(a.lo, 0x0000_8a2e_0370_7334, "low half is the last 8")

    // Offset parsing is what the header reader relies on.
    let padded = [UInt8](repeating: 0xAA, count: 8) + a.bytes
    R.assertEqual(IPv6Addr(bytes: padded, at: 8), a, "parses at an offset")
    R.assertTrue(IPv6Addr(bytes: padded, at: 9) == nil, "refuses to read past the end")

    R.assertEqual(a.words.count, 8, "8 16-bit words")
    R.assertEqual(a.words[0], 0x2001, "first word")
    R.assertEqual(a.words[7], 0x7334, "last word")
}

func testIPv6AddrClassification() {
    R.enter("IPv6Addr: link-local / multicast / zero")

    R.assertTrue(IPv6Addr("fe80::1")!.isLinkLocal, "fe80::1 is link-local")
    R.assertTrue(IPv6Addr("febf:ffff::")!.isLinkLocal, "top of fe80::/10 is link-local")
    R.assertTrue(!IPv6Addr("fec0::1")!.isLinkLocal, "fec0:: is outside fe80::/10")
    R.assertTrue(!IPv6Addr("2001:db8::1")!.isLinkLocal, "global unicast is not link-local")

    R.assertTrue(IPv6Addr("ff02::1")!.isMulticast, "ff02::1 is multicast")
    R.assertTrue(!IPv6Addr("2001:db8::1")!.isMulticast, "global unicast is not multicast")

    R.assertTrue(IPv6Addr.zero.isZero, "zero is zero")
    R.assertTrue(!IPv6Addr("::1")!.isZero, "::1 is not zero")
}

// MARK: – Prefix + table

func testRoutePrefix6Masking() {
    R.enter("RoutePrefix6: masking across the 64-bit boundary")

    // The two-UInt64 split makes /63, /64, /65 the interesting boundaries.
    R.assertEqual(RoutePrefix6(network: IPv6Addr("2001:db8::1")!, prefix: 32).network.string,
                  "2001:db8::", "/32 clears everything below")
    R.assertEqual(RoutePrefix6(network: IPv6Addr("2001:db8:0:1::1")!, prefix: 63).network.string,
                  "2001:db8::", "/63 masks within the high half")
    R.assertEqual(RoutePrefix6(network: IPv6Addr("2001:db8::dead:beef")!, prefix: 64).network.string,
                  "2001:db8::", "/64 clears the whole low half")
    R.assertEqual(RoutePrefix6(network: IPv6Addr("2001:db8::8000:0:0:1")!, prefix: 65).network.string,
                  "2001:db8:0:0:8000::", "/65 keeps the top bit of the low half")
    R.assertEqual(RoutePrefix6(network: IPv6Addr("2001:db8::1")!, prefix: 128).network.string,
                  "2001:db8::1", "/128 is the address itself")
    R.assertEqual(RoutePrefix6(network: IPv6Addr("2001:db8::1")!, prefix: 0).network, IPv6Addr.zero,
                  "/0 is ::")

    let p64 = RoutePrefix6(network: IPv6Addr("2001:db8::")!, prefix: 64)
    R.assertTrue(p64.contains(IPv6Addr("2001:db8::dead")!), "contains an address inside the /64")
    R.assertTrue(!p64.contains(IPv6Addr("2001:db8:0:1::1")!), "excludes the neighbouring /64")

    let def = RoutePrefix6(network: .zero, prefix: 0)
    R.assertTrue(def.contains(IPv6Addr("2606:4700::1111")!), "::/0 contains everything")
}

func testRoutePrefix6Parse() {
    R.enter("RoutePrefix6: parse")

    R.assertEqual(RoutePrefix6.parse("2001:db8::/32")?.prefix, 32, "parses a prefix length")
    R.assertEqual(RoutePrefix6.parse("2001:db8::1")?.prefix, 128, "bare address is a /128")
    R.assertEqual(RoutePrefix6.parse("::/0")?.network, IPv6Addr.zero, "default route")
    R.assertTrue(RoutePrefix6.parse("2001:db8::/129") == nil, "rejects a prefix over 128")
    R.assertTrue(RoutePrefix6.parse("2001:db8::/nope") == nil, "rejects a non-numeric prefix")
    R.assertTrue(RoutePrefix6.parse("10.0.0.0/8") == nil, "rejects a v4 CIDR")
}

func testRoutingTable6LongestPrefix() {
    R.enter("RoutingTable6: longest-prefix match + tie-break")

    let t = RoutingTable6([
        (id: "corp", prefixes: [RoutePrefix6.parse("2001:db8::/32")!]),
        (id: "lab",  prefixes: [RoutePrefix6.parse("2001:db8:1::/48")!]),
        (id: "full", prefixes: [RoutePrefix6.parse("::/0")!]),
    ])

    R.assertEqual(t.upstreamID(forDest: IPv6Addr("2001:db8:1::5")!), "lab", "most specific wins")
    R.assertEqual(t.upstreamID(forDest: IPv6Addr("2001:db8:9::5")!), "corp", "next most specific")
    R.assertEqual(t.upstreamID(forDest: IPv6Addr("2606:4700::1111")!), "full", "::/0 is the default sink")

    // Identical prefixes: registration order decides, deterministically.
    let tie = RoutingTable6([
        (id: "first",  prefixes: [RoutePrefix6.parse("2001:db8::/32")!]),
        (id: "second", prefixes: [RoutePrefix6.parse("2001:db8::/32")!]),
    ])
    R.assertEqual(tie.upstreamID(forDest: IPv6Addr("2001:db8::1")!), "first",
                  "equal prefixes resolve to the earlier upstream")

    R.assertTrue(RoutingTable6([]).isEmpty, "empty table reports empty")
    R.assertTrue(RoutingTable6([]).upstreamID(forDest: IPv6Addr("2001:db8::1")!) == nil,
                 "empty table matches nothing — the v6 block case")
}

// MARK: – Header + extension-header walk

func testIPv6HeaderParse() {
    R.enter("IPv6Header: parse")

    let pkt = v6Packet(src: "2001:db8::1", dst: "2001:db8::2", proto: 6,
                       payload: tcpSegment(sport: 1234, dport: 443))
    guard let h = IPv6Header.parse(pkt) else {
        R.assertTrue(false, "parses a well-formed packet"); return
    }
    R.assertEqual(h.source.string, "2001:db8::1", "source")
    R.assertEqual(h.destination.string, "2001:db8::2", "destination")
    R.assertEqual(h.nextHeader, 6, "next header is TCP")
    R.assertEqual(Int(h.payloadLength), pkt.count - 40, "payload length matches")

    R.assertTrue(IPv6Header.parse(Data([0x60, 0, 0, 0])) == nil, "rejects a truncated header")
    var v4ish = Data([0x45]); v4ish.append(contentsOf: [UInt8](repeating: 0, count: 39))
    R.assertTrue(IPv6Header.parse(v4ish) == nil, "rejects an IPv4 version nibble")
}

func testIPv6TransportHeaderWalk() {
    R.enter("IPv6: extension-header walk")

    let plain = [UInt8](v6Packet(src: "2001:db8::1", dst: "2001:db8::2", proto: 6,
                                 payload: tcpSegment(sport: 1, dport: 2)))
    R.assertEqual(IPv6ExtensionHeader.transportHeader(plain)?.offset, 40, "no extension headers → offset 40")
    R.assertEqual(IPv6ExtensionHeader.transportHeader(plain)?.proto, 6, "finds TCP")

    // One 8-byte destination-options header (next=TCP, hdrExtLen=0) in front.
    let destOpts: [UInt8] = [6, 0, 0, 0, 0, 0, 0, 0]
    var withExt: [UInt8] = [0x60, 0, 0, 0, 0, 0, 60, 64]
    withExt += IPv6Addr("2001:db8::1")!.bytes + IPv6Addr("2001:db8::2")!.bytes
    withExt += destOpts + tcpSegment(sport: 1, dport: 2)
    R.assertEqual(IPv6ExtensionHeader.transportHeader(withExt)?.offset, 48,
                  "skips an 8-byte destination-options header")
    R.assertEqual(IPv6ExtensionHeader.transportHeader(withExt)?.proto, 6, "still finds TCP behind it")

    // Fragment header, offset 0: the transport header is present.
    var frag0: [UInt8] = [0x60, 0, 0, 0, 0, 0, 44, 64]
    frag0 += IPv6Addr("2001:db8::1")!.bytes + IPv6Addr("2001:db8::2")!.bytes
    frag0 += [6, 0, 0x00, 0x01, 0, 0, 0, 1]     // next=TCP, offset 0, M=1
    frag0 += tcpSegment(sport: 1, dport: 2)
    R.assertEqual(IPv6ExtensionHeader.transportHeader(frag0)?.offset, 48, "first fragment has a transport header")

    // Fragment header, non-zero offset: there is none, and NAT must not guess.
    var fragN = Array(frag0.prefix(48))
    fragN[42] = 0x00; fragN[43] = 0xB8          // fragment offset = 23 (<<3)
    fragN += tcpSegment(sport: 1, dport: 2)
    R.assertTrue(IPv6ExtensionHeader.transportHeader(fragN) == nil, "non-first fragment has no transport header")

    // ESP is encrypted; there is nothing to patch behind it.
    var esp: [UInt8] = [0x60, 0, 0, 0, 0, 0, 50, 64]
    esp += IPv6Addr("2001:db8::1")!.bytes + IPv6Addr("2001:db8::2")!.bytes
    esp += [UInt8](repeating: 0, count: 16)
    R.assertTrue(IPv6ExtensionHeader.transportHeader(esp) == nil, "stops at ESP rather than guessing")

    // A chain that never terminates must not spin the data path.
    var loop: [UInt8] = [0x60, 0, 0, 0, 0, 0, 60, 64]
    loop += IPv6Addr("2001:db8::1")!.bytes + IPv6Addr("2001:db8::2")!.bytes
    loop += [UInt8](repeating: 0, count: 200).enumerated().map { i, _ in i % 8 == 0 ? 60 : 0 }
    R.assertTrue(IPv6ExtensionHeader.transportHeader(loop) == nil, "bails out of an endless header chain")
}

// MARK: – PacketNAT, IPv6

func testPacketNAT6RejectsNonIPv6() {
    R.enter("PacketNAT v6: rejects non-IPv6")

    var v4 = Data([0x45, 0, 0, 20]); v4.append(contentsOf: [UInt8](repeating: 0, count: 16))
    R.assertTrue(!PacketNAT.rewriteSource6(&v4, to: IPv6Addr("2001:db8::9")!), "refuses an IPv4 packet")
    var short = Data([0x60, 0, 0, 0])
    R.assertTrue(!PacketNAT.rewriteSource6(&short, to: IPv6Addr("2001:db8::9")!), "refuses a truncated packet")
}

func testPacketNAT6SourceRewriteTCP() {
    R.enter("PacketNAT v6: source rewrite fixes the TCP checksum")

    var pkt = v6Packet(src: "2001:2::1", dst: "2001:db8:c::5", proto: 6,
                       payload: tcpSegment(sport: 51000, dport: 22, payload: [1, 2, 3, 4, 5]))
    R.assertTrue(v6TransportChecksumValid(pkt), "builder produced a valid checksum to start from")

    let newSrc = IPv6Addr("2001:db8:c::1000")!
    R.assertTrue(PacketNAT.rewriteSource6(&pkt, to: newSrc), "rewrite succeeds")
    R.assertEqual(srcOf6(pkt), newSrc, "source replaced")
    R.assertEqual(dstOf6(pkt)?.string, "2001:db8:c::5", "destination untouched")
    R.assertTrue(v6TransportChecksumValid(pkt), "TCP checksum still valid after the incremental fix-up")
}

func testPacketNAT6RoundTrip() {
    R.enter("PacketNAT v6: rewrite round-trip is lossless")

    let original = v6Packet(src: "2001:2::1", dst: "2001:db8:c::5", proto: 6,
                            payload: tcpSegment(sport: 51000, dport: 443, payload: [9, 8, 7]))
    var pkt = original
    PacketNAT.rewriteSource6(&pkt, to: IPv6Addr("2001:db8:c::1000")!)
    R.assertTrue(pkt != original, "packet actually changed")
    PacketNAT.rewriteSource6(&pkt, to: IPv6Addr("2001:2::1")!)
    R.assertEqual(pkt, original, "rewriting back reproduces the original byte-for-byte")
}

func testPacketNAT6NoOpSameAddress() {
    R.enter("PacketNAT v6: rewriting to the same address is a no-op")

    let original = v6Packet(src: "2001:2::1", dst: "2001:db8:c::5", proto: 6,
                            payload: tcpSegment(sport: 1, dport: 2))
    var pkt = original
    R.assertTrue(PacketNAT.rewriteSource6(&pkt, to: IPv6Addr("2001:2::1")!), "reports success")
    R.assertEqual(pkt, original, "bytes unchanged (no checksum churn)")
}

func testPacketNAT6DestRewriteUDP() {
    R.enter("PacketNAT v6: destination rewrite fixes the UDP checksum")

    var udp: [UInt8] = [0x00, 0x35, 0xC0, 0x00]   // sport 53, dport 49152
    udp += [0, 12]                                 // length
    udp += [0, 0]                                  // checksum
    udp += [0xDE, 0xAD, 0xBE, 0xEF]
    var pkt = v6Packet(src: "2001:db8:c::53", dst: "2001:db8:c::1000", proto: 17, payload: udp)
    R.assertTrue(v6TransportChecksumValid(pkt), "builder produced a valid UDP checksum")

    let u0 = IPv6Addr("2001:2::1")!
    R.assertTrue(PacketNAT.rewriteDestination6(&pkt, to: u0), "rewrite succeeds")
    R.assertEqual(dstOf6(pkt), u0, "destination replaced")
    R.assertTrue(v6TransportChecksumValid(pkt), "UDP checksum still valid")

    let b = [UInt8](pkt)
    let (_, off) = IPv6ExtensionHeader.transportHeader(b)!
    R.assertTrue(!(b[off + 6] == 0 && b[off + 7] == 0), "never leaves a zero UDP checksum")
}

func testPacketNAT6ICMPv6ChecksumIsPatched() {
    R.enter("PacketNAT v6: ICMPv6 checksum is patched (unlike v4 ICMP)")

    let icmp: [UInt8] = [128, 0, 0, 0, 0x12, 0x34, 0x00, 0x01, 0xAA, 0xBB]
    var pkt = v6Packet(src: "2001:2::1", dst: "2001:db8:c::5", proto: 58, payload: icmp)
    R.assertTrue(v6TransportChecksumValid(pkt), "builder produced a valid ICMPv6 checksum")

    R.assertTrue(PacketNAT.rewriteSource6(&pkt, to: IPv6Addr("2001:db8:c::1000")!), "rewrite succeeds")
    R.assertTrue(v6TransportChecksumValid(pkt), "ICMPv6 checksum still valid after the rewrite")
}

func testPacketNAT6NonFirstFragmentLeavesL4Alone() {
    R.enter("PacketNAT v6: non-first fragment keeps its payload bytes")

    var pkt: [UInt8] = [0x60, 0, 0, 0, 0, 0, 44, 64]
    pkt += IPv6Addr("2001:2::1")!.bytes + IPv6Addr("2001:db8:c::5")!.bytes
    pkt += [6, 0, 0x00, 0xB8, 0, 0, 0, 1]         // fragment offset 23, so no transport header
    let tail: [UInt8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    pkt += tail

    var d = Data(pkt)
    R.assertTrue(PacketNAT.rewriteSource6(&d, to: IPv6Addr("2001:db8:c::1000")!), "rewrite succeeds")
    R.assertEqual(srcOf6(d), IPv6Addr("2001:db8:c::1000")!, "source still replaced")
    R.assertEqual([UInt8](d).suffix(8), tail[0...], "fragment payload untouched — nothing to checksum")
}
