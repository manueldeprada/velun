import Foundation

private func connectResponse(_ headers: [String]) -> String {
    (["HTTP/1.1 200 OK"] + headers).joined(separator: "\r\n") + "\r\n\r\n"
}

func testCSTPRequestsIPv4First() {
    R.enter("CSTP: address-type preference order")
    let req = CSTPTunnel.buildConnectRequest(host: "vpn.example.com", cookie: "c", reconnect: false)
    R.assertTrue(req.contains("X-CSTP-Address-Type: IPv4,IPv6\r\n"),
                 "IPv4 listed first — the ASA honors the order and velun needs a v4 address")
}

func testCSTPParsesDualStackResponse() throws {
    R.enter("CSTP: dual-stack response")
    let cfg = try CSTPTunnel.parseCSTPHeaders(connectResponse([
        "X-CSTP-Address: 10.1.18.134",
        "X-CSTP-Netmask: 255.255.255.0",
        "X-CSTP-Address-IP6: 2001:67c:10ec:574f:8000::54/64",
        "X-CSTP-Split-Include-IP6: 2001:67c:10ec::/48",
        "X-CSTP-DNS: 129.132.250.5",
        "X-CSTP-MTU: 1406",
    ]))
    R.assertEqual(cfg.ipAddress, "10.1.18.134", "v4 address")
    R.assertEqual(cfg.ipv6Address, "2001:67c:10ec:574f:8000::54", "v6 address, prefix stripped")
    R.assertEqual(cfg.ipv6PrefixLength, 64, "v6 prefix length")
    R.assertEqual(cfg.ipv6SplitIncludes, ["2001:67c:10ec::/48"], "v6 split-include")
    R.assertEqual(cfg.dnsServers, ["129.132.250.5"], "v4 resolver kept")
}

func testCSTPRejectsIPv6OnlySession() {
    R.enter("CSTP: v6-primary session is refused, not half-configured")
    // Exactly what ETH returned: the v6 address in the legacy field, no v4.
    let response = connectResponse([
        "X-CSTP-Address: 2001:67c:10ec:574f:8000::54",
        "X-CSTP-MTU: 1406",
    ])
    do {
        let cfg = try CSTPTunnel.parseCSTPHeaders(response)
        R.assertTrue(false, "must throw, got ipAddress=\(cfg.ipAddress)")
    } catch {
        R.assertTrue("\(error)".contains("IPv6-only"), "error names the v6-only session: \(error)")
    }
}

func testCSTPClassifiesLegacyAddressByFamily() throws {
    R.enter("CSTP: legacy X-CSTP-Address classified by family")
    let cfg = try CSTPTunnel.parseCSTPHeaders(connectResponse([
        "X-CSTP-Address: 2001:67c:10ec:574f:8000::54",
        "X-CSTP-Address: 10.1.18.134",
        "X-CSTP-Netmask: 255.255.255.0",
    ]))
    R.assertEqual(cfg.ipAddress, "10.1.18.134", "v4 address taken from the v4-shaped value")
    R.assertEqual(cfg.ipv6Address, "2001:67c:10ec:574f:8000::54", "v6-shaped value routed to the v6 slot")

    // An explicit X-CSTP-Address-IP6 wins over a v6 in the legacy field.
    let cfg2 = try CSTPTunnel.parseCSTPHeaders(connectResponse([
        "X-CSTP-Address: 10.1.18.134",
        "X-CSTP-Address-IP6: 2001:db8::99/64",
    ]))
    R.assertEqual(cfg2.ipv6Address, "2001:db8::99", "explicit v6 header used")
}

func testCSTPMalformedIPv6IsDropped() throws {
    R.enter("CSTP: unparseable v6 leaves the upstream v4-only")
    let cfg = try CSTPTunnel.parseCSTPHeaders(connectResponse([
        "X-CSTP-Address: 10.1.18.134",
        "X-CSTP-Address-IP6: 2001:db8::zz::1/64",
        "X-CSTP-Split-Include-IP6: 2001:db8::/48",
    ]))
    R.assertEqual(cfg.ipAddress, "10.1.18.134", "v4 unaffected")
    R.assertEqual(cfg.ipv6Address, "", "garbage v6 dropped rather than half-applied")
    R.assertEqual(cfg.ipv6SplitIncludes, [], "and its routes dropped with it")
}

func testCSTPFiltersIPv6Resolvers() throws {
    R.enter("CSTP: v6 resolvers filtered out of dnsServers")
    let cfg = try CSTPTunnel.parseCSTPHeaders(connectResponse([
        "X-CSTP-Address: 10.1.18.134",
        "X-CSTP-DNS: 129.132.250.5",
        "X-CSTP-DNS: 2001:620:0:ff::5",
    ]))
    R.assertEqual(cfg.dnsServers, ["129.132.250.5"], "only the v4 resolver survives")
}
