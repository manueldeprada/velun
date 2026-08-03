import Foundation

private final class StubUpstream: RouterUpstream {
    let profileID: String
    let assignedIP: UInt32
    let assignedIP6: IPv6Addr
    let cidrs: [String]
    let cidrs6: [String]
    var written: [Data] = []
    init(_ id: String, ip: UInt32, _ cidrs: [String],
         ip6: String? = nil, cidrs6: [String] = []) {
        profileID = id
        assignedIP = ip
        assignedIP6 = ip6.flatMap(IPv6Addr.init) ?? .zero
        self.cidrs = cidrs
        self.cidrs6 = cidrs6
    }
    var routePrefixes: [RoutePrefix] { cidrs.compactMap(RoutePrefix.parse) }
    var routePrefixes6: [RoutePrefix6] { cidrs6.compactMap(RoutePrefix6.parse) }
    func writeInner(_ packet: Data) async throws { written.append(packet) }
}

private extension UnifiedRouter {
    func add(_ u: StubUpstream) {
        addUpstream(u, prefixes: u.routePrefixes, prefixes6: u.routePrefixes6)
    }
}

private final class StubPacketFlow: PacketFlowIO {
    var outbound: [Data] = []
    func readInbound() async -> [Data] { [] }
    func writeOutbound(_ packets: [Data]) { outbound.append(contentsOf: packets) }
}

private func srcOf(_ d: Data) -> UInt32 {
    let b = [UInt8](d); return UInt32(b[12]) << 24 | UInt32(b[13]) << 16 | UInt32(b[14]) << 8 | UInt32(b[15])
}
private func dstOf(_ d: Data) -> UInt32 {
    let b = [UInt8](d); return UInt32(b[16]) << 24 | UInt32(b[17]) << 16 | UInt32(b[18]) << 8 | UInt32(b[19])
}
private func tcp(src: UInt32, dst: UInt32) -> Data {
    PacketBuilder.ipv4TCP(srcIP: src, dstIP: dst, srcPort: 50000, dstPort: 22,
                          seq: 1, ack: 0, flags: [.syn], window: 65535,
                          payload: Data(), mss: 1380)
}

private func v6tcp(src: String, dst: String) -> Data {
    var b: [UInt8] = [0x60, 0, 0, 0, 0, 20, 6, 64]
    b += IPv6Addr(src)!.bytes
    b += IPv6Addr(dst)!.bytes
    b += [0xC3, 0x50, 0x00, 0x16, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]
    return Data(b)
}

private let U0: UInt32 = 0x6440_0001         // 100.64.0.1 (synthetic utun inner IP)
private let U0_6 = IPv6Addr("2001:2::1")!    // synthetic utun inner IPv6
private let MPI_IP: UInt32 = 0x0a03_0063     // 10.3.0.99
private let ETH_IP: UInt32 = 0x0a00_3207     // 10.0.50.7

func testRoutingTableLongestPrefix() {
    R.enter("RoutingTable longest-prefix match")
    let t = RoutingTable([
        ("mpi", [RoutePrefix.parse("10.15.0.0/16")!]),
        ("eth", [RoutePrefix.parse("129.132.0.0/16")!]),
        ("def", [RoutePrefix.parse("0.0.0.0/0")!]),
    ])
    R.assertEqual(t.upstreamID(forDest: IPv4.toUInt32("10.15.0.7")!),    "mpi", "10.15.0.7 → mpi")
    R.assertEqual(t.upstreamID(forDest: IPv4.toUInt32("129.132.250.5")!), "eth", "corp DNS → eth")
    R.assertEqual(t.upstreamID(forDest: IPv4.toUInt32("8.8.8.8")!),       "def", "public → default (0/0)")

    let noDefault = RoutingTable([("mpi", [RoutePrefix.parse("10.15.0.0/16")!])])
    R.assertTrue(noDefault.upstreamID(forDest: IPv4.toUInt32("8.8.8.8")!) == nil,
                 "no default → unmatched returns nil (drop)")
    R.assertEqual(noDefault.upstreamID(forDest: IPv4.toUInt32("10.15.9.9")!), "mpi", "still matches its own /16")
}

func testRoutingTableNestedAndTieBreak() {
    R.enter("RoutingTable nested + tie-break")
    let nested = RoutingTable([
        ("wide",   [RoutePrefix.parse("10.0.0.0/8")!]),
        ("narrow", [RoutePrefix.parse("10.15.0.0/16")!]),
    ])
    R.assertEqual(nested.upstreamID(forDest: IPv4.toUInt32("10.15.0.7")!), "narrow", "more-specific /16 wins")
    R.assertEqual(nested.upstreamID(forDest: IPv4.toUInt32("10.1.2.3")!),  "wide",   "falls back to /8")

    // Identical prefixes on two upstreams → earlier registration wins, deterministically.
    let tie = RoutingTable([
        ("a", [RoutePrefix.parse("10.0.0.0/8")!]),
        ("b", [RoutePrefix.parse("10.0.0.0/8")!]),
    ])
    R.assertEqual(tie.upstreamID(forDest: IPv4.toUInt32("10.1.2.3")!), "a", "overlapping CIDR → first registered")
}

func testRoutePrefixParse() {
    R.enter("RoutePrefix parse")
    R.assertTrue(RoutePrefix.parse("10.15.0.0/16")?.contains(IPv4.toUInt32("10.15.255.1")!) == true, "/16 contains in-range")
    R.assertTrue(RoutePrefix.parse("10.15.0.0/16")?.contains(IPv4.toUInt32("10.16.0.1")!) == false, "/16 excludes out-of-range")
    R.assertTrue(RoutePrefix.parse("1.2.3.4")?.prefix == 32, "bare IP → /32")
    R.assertTrue(RoutePrefix.parse("0.0.0.0/0")?.contains(IPv4.toUInt32("203.0.113.9")!) == true, "/0 contains everything")
    R.assertTrue(RoutePrefix.parse("garbage")  == nil, "garbage → nil")
    R.assertTrue(RoutePrefix.parse("10.0.0.0/33") == nil, "prefix > 32 → nil")
}

func testRouterOutboundDemuxAndSourceNAT() async {
    R.enter("Router outbound: demux + source-NAT")
    let pf = StubPacketFlow()
    let r = UnifiedRouter(utunInnerIP: U0, packetFlow: pf)
    let mpi = StubUpstream("mpi", ip: MPI_IP, ["10.15.0.0/16"])
    let eth = StubUpstream("eth", ip: ETH_IP, ["129.132.0.0/16"])
    r.add(mpi); r.add(eth)

    await r.handleOutbound(tcp(src: U0, dst: IPv4.toUInt32("10.15.0.7")!))
    R.assertEqual(mpi.written.count, 1, "mpi got the 10.15 packet")
    R.assertEqual(eth.written.count, 0, "eth got nothing")
    if let p = mpi.written.first {
        R.assertEqual(srcOf(p), MPI_IP, "src rewritten U0 → mpi assigned IP")
        R.assertEqual(dstOf(p), IPv4.toUInt32("10.15.0.7")!, "dst unchanged")
    }

    await r.handleOutbound(tcp(src: U0, dst: IPv4.toUInt32("129.132.250.5")!))
    R.assertEqual(eth.written.count, 1, "eth got the corp-DNS packet")
    R.assertEqual(srcOf(eth.written[0]), ETH_IP, "src rewritten to eth assigned IP")
}

func testRouterOutboundDropsUnmatchedAndIPv6() async {
    R.enter("Router outbound: drop unmatched / IPv6")
    let pf = StubPacketFlow()
    let r = UnifiedRouter(utunInnerIP: U0, packetFlow: pf)
    let mpi = StubUpstream("mpi", ip: MPI_IP, ["10.15.0.0/16"])
    r.add(mpi)

    await r.handleOutbound(tcp(src: U0, dst: IPv4.toUInt32("8.8.8.8")!))
    R.assertEqual(mpi.written.count, 0, "no default upstream → unmatched dropped (fail-closed)")

    await r.handleOutbound(v6tcp(src: "2001:2::1", dst: "2606:4700::1111"))
    R.assertEqual(mpi.written.count, 0, "IPv6 dropped when no upstream carries v6")
}

func testRouterIPv6DemuxAndSourceNAT() async {
    R.enter("Router outbound v6: demux + source-NAT")
    let pf = StubPacketFlow()
    let r = UnifiedRouter(utunInnerIP: U0, utunInnerIP6: U0_6, packetFlow: pf)
    let corp = StubUpstream("corp", ip: MPI_IP, ["10.15.0.0/16"],
                            ip6: "2001:db8:c::1000", cidrs6: ["2001:db8:c::/48"])
    let v4only = StubUpstream("v4only", ip: ETH_IP, ["0.0.0.0/0"])
    r.add(corp)
    r.add(v4only)

    await r.handleOutbound(v6tcp(src: U0_6.string, dst: "2001:db8:c::5"))
    R.assertEqual(corp.written.count, 1, "v6 inside the corp prefix goes to the v6-capable upstream")
    if let p = corp.written.first {
        R.assertEqual(IPv6Addr(bytes: [UInt8](p), at: 8), corp.assignedIP6, "src NAT'd U0_6 → A_u6")
        R.assertEqual(IPv6Addr(bytes: [UInt8](p), at: 24)?.string, "2001:db8:c::5", "dst untouched")
    }

    await r.handleOutbound(v6tcp(src: U0_6.string, dst: "2606:4700::1111"))
    R.assertEqual(v4only.written.count, 0, "a v4-only default upstream never receives v6")
    R.assertEqual(corp.written.count, 1, "and it isn't misrouted to the corp upstream either")

    // Link-local and multicast are host-side noise a 1:1 NAT can't map.
    await r.handleOutbound(v6tcp(src: U0_6.string, dst: "fe80::1"))
    await r.handleOutbound(v6tcp(src: U0_6.string, dst: "ff02::1"))
    R.assertEqual(corp.written.count, 1, "link-local + multicast dropped")
}

func testRouterIPv6InboundDestNAT() async {
    R.enter("Router inbound v6: dest-NAT to U0_6")
    let pf = StubPacketFlow()
    let r = UnifiedRouter(utunInnerIP: U0, utunInnerIP6: U0_6, packetFlow: pf)
    let corp = StubUpstream("corp", ip: MPI_IP, ["10.15.0.0/16"],
                            ip6: "2001:db8:c::1000", cidrs6: ["2001:db8:c::/48"])
    r.add(corp)

    await r.handleInbound(v6tcp(src: "2001:db8:c::5", dst: "2001:db8:c::1000"), from: corp)
    R.assertEqual(pf.outbound.count, 1, "reply delivered to the utun")
    if let p = pf.outbound.first {
        R.assertEqual(IPv6Addr(bytes: [UInt8](p), at: 24), U0_6, "dst rewritten A_u6 → U0_6")
        R.assertEqual(IPv6Addr(bytes: [UInt8](p), at: 8)?.string, "2001:db8:c::5", "corp source preserved")
    }

    // Anything not addressed to our assigned v6 is noise.
    await r.handleInbound(v6tcp(src: "2001:db8:c::5", dst: "2001:db8:c::9999"), from: corp)
    R.assertEqual(pf.outbound.count, 1, "packet for another address dropped")
}

func testRouterIgnoresUpstreamWithoutAssignedIPv4() async {
    R.enter("Router: no assigned v4 address → no v4 routes")
    let pf = StubPacketFlow()
    let r = UnifiedRouter(utunInnerIP: U0, utunInnerIP6: U0_6, packetFlow: pf)
    let noV4 = StubUpstream("nov4", ip: 0, ["0.0.0.0/0"])
    r.add(noV4)

    await r.handleOutbound(tcp(src: U0, dst: IPv4.toUInt32("8.8.8.8")!))
    R.assertEqual(noV4.written.count, 0, "v4 dropped rather than NAT'd to 0.0.0.0")

    // …and it must not shadow a healthy upstream registered afterwards.
    let good = StubUpstream("good", ip: ETH_IP, ["0.0.0.0/0"])
    r.add(good)
    await r.handleOutbound(tcp(src: U0, dst: IPv4.toUInt32("8.8.8.8")!))
    R.assertEqual(good.written.count, 1, "healthy upstream still wins the default route")
    R.assertEqual(noV4.written.count, 0, "broken upstream still receives nothing")
}

func testRouterIPv6IgnoredWhenUpstreamHasNoV6Address() async {
    R.enter("Router v6: routes ignored without an assigned v6 address")
    let pf = StubPacketFlow()
    let r = UnifiedRouter(utunInnerIP: U0, utunInnerIP6: U0_6, packetFlow: pf)
    let broken = StubUpstream("broken", ip: MPI_IP, ["10.15.0.0/16"], ip6: nil, cidrs6: ["::/0"])
    r.add(broken)

    R.assertTrue(!r.carriesIPv6, "no v6 address → upstream contributes no v6 routes")
    await r.handleOutbound(v6tcp(src: U0_6.string, dst: "2606:4700::1111"))
    R.assertEqual(broken.written.count, 0, "v6 dropped rather than NAT'd to ::")
}

func testRouterInboundDestNAT() async {
    R.enter("Router inbound: dest-NAT to U0")
    let pf = StubPacketFlow()
    let r = UnifiedRouter(utunInnerIP: U0, packetFlow: pf)
    let mpi = StubUpstream("mpi", ip: MPI_IP, ["10.15.0.0/16"])
    r.add(mpi)

    // Corp host 10.15.0.7 replying to our assigned IP.
    await r.handleInbound(tcp(src: IPv4.toUInt32("10.15.0.7")!, dst: MPI_IP), from: mpi)
    R.assertEqual(pf.outbound.count, 1, "inbound packet delivered to utun")
    if let p = pf.outbound.first {
        R.assertEqual(dstOf(p), U0, "dst rewritten mpi assigned IP → U0")
        R.assertEqual(srcOf(p), IPv4.toUInt32("10.15.0.7")!, "corp source preserved")
    }

    // A packet not addressed to our assigned IP is dropped.
    await r.handleInbound(tcp(src: IPv4.toUInt32("10.15.0.7")!, dst: IPv4.toUInt32("10.3.0.50")!), from: mpi)
    R.assertEqual(pf.outbound.count, 1, "packet to a non-assigned dst dropped")
}

func testRouterUpdateRoutesHotSwitch() async {
    R.enter("Router updateRoutes hot-switch")
    let pf = StubPacketFlow()
    let r = UnifiedRouter(utunInnerIP: U0, packetFlow: pf)
    let mpi = StubUpstream("mpi", ip: MPI_IP, ["10.15.0.0/16"])
    r.add(mpi)

    await r.handleOutbound(tcp(src: U0, dst: IPv4.toUInt32("10.15.0.7")!))
    R.assertEqual(mpi.written.count, 1, "before switch: 10.15 routed to mpi")

    // Hot-switch the route set (e.g. partialManual edit) — no reader churn.
    r.updateRoutes(profileID: "mpi", prefixes: [RoutePrefix.parse("10.20.0.0/16")!])
    await r.handleOutbound(tcp(src: U0, dst: IPv4.toUInt32("10.15.0.7")!))
    R.assertEqual(mpi.written.count, 1, "after switch: old 10.15 no longer routed (dropped)")
    await r.handleOutbound(tcp(src: U0, dst: IPv4.toUInt32("10.20.0.9")!))
    R.assertEqual(mpi.written.count, 2, "after switch: new 10.20 routed to mpi")

    // updateRoutes for an unknown upstream is a no-op (doesn't crash).
    r.updateRoutes(profileID: "ghost", prefixes: [RoutePrefix.parse("0.0.0.0/0")!])
    await r.handleOutbound(tcp(src: U0, dst: IPv4.toUInt32("8.8.8.8")!))
    R.assertEqual(mpi.written.count, 2, "unknown-upstream updateRoutes added no catch-all route")
}
