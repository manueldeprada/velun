import Foundation

func testDomainRouteHostnameParsing() {
    R.enter("DomainRouteResolver hostname parsing")

    // The motivating real-world case: a pasted portal URL with path+fragment.
    R.assertEqual(DomainRouteResolver.hostnames(from: "https://sbportal.sap.mpg.de/irj/portal#Shell-home"),
                  ["sbportal.sap.mpg.de"], "pasted URL → bare hostname")

    // Separators: spaces, commas, newlines, and mixes thereof.
    R.assertEqual(DomainRouteResolver.hostnames(from: "a.example.com b.example.com"),
                  ["a.example.com", "b.example.com"], "space-separated")
    R.assertEqual(DomainRouteResolver.hostnames(from: "a.example.com, b.example.com,c.example.com"),
                  ["a.example.com", "b.example.com", "c.example.com"], "comma-separated")
    R.assertEqual(DomainRouteResolver.hostnames(from: " a.example.com \n b.example.com "),
                  ["a.example.com", "b.example.com"], "newlines + padding")

    // URL debris: scheme, port, path, query, userinfo, trailing root dot.
    R.assertEqual(DomainRouteResolver.hostnames(from: "http://portal.corp:8443/login?next=/x"),
                  ["portal.corp"], "scheme + port + path + query stripped")
    R.assertEqual(DomainRouteResolver.hostnames(from: "user@host.example.com"),
                  ["host.example.com"], "userinfo stripped")
    R.assertEqual(DomainRouteResolver.hostnames(from: "host.example.com."),
                  ["host.example.com"], "trailing root dot stripped")

    // Dedup is case-insensitive and order-preserving.
    R.assertEqual(DomainRouteResolver.hostnames(from: "B.example.com a.example.com b.EXAMPLE.com"),
                  ["b.example.com", "a.example.com"], "case-insensitive dedup, order kept")

    // Degenerate input.
    R.assertEqual(DomainRouteResolver.hostnames(from: ""), [], "empty input")
    R.assertEqual(DomainRouteResolver.hostnames(from: "  , ,\n"), [], "separators only")
    R.assertEqual(DomainRouteResolver.hostnames(from: "https:// , ."), [], "debris-only tokens dropped")
}

func testDomainRouteNormalizedList() {
    R.enter("DomainRouteResolver field normalization")

    R.assertEqual(DomainRouteResolver.normalizedList(from: "https://sbportal.sap.mpg.de/index.html"),
                  "sbportal.sap.mpg.de", "pasted URL → bare hostname")
    R.assertEqual(DomainRouteResolver.normalizedList(from: "sbportal.sap.mpg.de/index.html"),
                  "sbportal.sap.mpg.de", "schemeless URL → bare hostname")
    R.assertEqual(DomainRouteResolver.normalizedList(
                      from: "https://portal.example.org/a  mail.example.org:993"),
                  "portal.example.org, mail.example.org", "mixed list → comma-separated")
    R.assertEqual(DomainRouteResolver.normalizedList(from: ""), "", "blank stays blank")
    R.assertEqual(DomainRouteResolver.normalizedList(from: "   "), "", "whitespace-only → blank")

    // Idempotence: the save path reapplies this to already-clean values.
    let once = DomainRouteResolver.normalizedList(from: "HTTPS://A.example.com/x, b.example.com.")
    R.assertEqual(once, "a.example.com, b.example.com", "canonical form")
    R.assertEqual(DomainRouteResolver.normalizedList(from: once), once, "idempotent")
}

func testRouteListNormalization() {
    R.enter("RouteList bare-address expansion")

    R.assertEqual(RouteList.normalized(from: "10.15.0.5"), "10.15.0.5/32", "bare IP → /32")
    R.assertEqual(RouteList.normalized(from: "192.168.1.50"), "192.168.1.50/32",
                  "RFC1918 host not widened to the LAN's /24")
    R.assertEqual(RouteList.normalized(from: "10.15.0.0"), "10.15.0.0/32",
                  "a network-looking address is still just an address")

    // Already-prefixed entries are the user's word on the matter.
    R.assertEqual(RouteList.normalized(from: "129.132.0.0/16"), "129.132.0.0/16", "/len kept as typed")
    R.assertEqual(RouteList.normalized(from: "10.0.0.0/8"), "10.0.0.0/8", "/8 not narrowed")

    // Mixed lists and separators.
    R.assertEqual(RouteList.normalized(from: "10.15.0.5 129.132.0.0/16"),
                  "10.15.0.5/32, 129.132.0.0/16", "mixed list")
    R.assertEqual(RouteList.normalized(from: "10.15.0.5, 10.15.0.7"),
                  "10.15.0.5/32, 10.15.0.7/32", "two hosts stay two entries")
    R.assertEqual(RouteList.normalized(from: "10.15.0.5, 10.15.0.5"),
                  "10.15.0.5/32", "exact repeat deduped")
    R.assertEqual(RouteList.normalized(from: " 10.1.2.3 \n 10.9.9.9 "),
                  "10.1.2.3/32, 10.9.9.9/32", "newlines + padding, order kept")

    R.assertEqual(RouteList.normalized(from: "10.15.0"), "10.15.0", "3 octets left alone")
    R.assertEqual(RouteList.normalized(from: "10.15.0.5.6"), "10.15.0.5.6", "5 octets left alone")
    R.assertEqual(RouteList.normalized(from: "10.15.0.999"), "10.15.0.999", "octet out of range")
    R.assertEqual(RouteList.normalized(from: "10.15.0.010"), "10.15.0.010", "leading zero not reinterpreted")
    R.assertEqual(RouteList.normalized(from: "fd00::1"), "fd00::1", "IPv6 untouched")
    R.assertEqual(RouteList.normalized(from: "fd00::/8"), "fd00::/8", "IPv6 prefix untouched")
    R.assertEqual(RouteList.normalized(from: "corp.example.com"), "corp.example.com",
                  "hostname untouched (wrong field, but not ours to mangle)")
    R.assertEqual(RouteList.normalized(from: ""), "", "blank stays blank")
    R.assertEqual(RouteList.normalized(from: "  ,\n "), "", "separators only → blank")

    // Idempotence: the save path reapplies this to already-canonical values.
    let once = RouteList.normalized(from: "10.15.0.5, 192.168.1.50")
    R.assertEqual(once, "10.15.0.5/32, 192.168.1.50/32", "canonical form")
    R.assertEqual(RouteList.normalized(from: once), once, "idempotent")
}

func testDomainRouteCIDRs() {
    R.enter("DomainRouteResolver /32 formatting")

    let table: [String: [String]] = [
        "portal.corp":  ["194.15.137.55"],
        "multi.corp":   ["10.0.0.2", "10.0.0.1"],
        "shared.corp":  ["194.15.137.55"],          // same IP as portal.corp
    ]
    let r = DomainRouteResolver { table[$0] ?? [] }

    R.assertEqual(r.cidrs(from: "portal.corp"), ["194.15.137.55/32"], "single host → /32")
    R.assertEqual(r.cidrs(from: "multi.corp"), ["10.0.0.1/32", "10.0.0.2/32"],
                  "multi-A host → all /32s, sorted")
    R.assertEqual(r.cidrs(from: "portal.corp shared.corp"), ["194.15.137.55/32"],
                  "two hosts on one IP → dedup")
    R.assertEqual(r.cidrs(from: "portal.corp gone.corp"), ["194.15.137.55/32"],
                  "unresolvable host skipped, not fatal")
    R.assertEqual(r.cidrs(from: "gone.corp"), [], "nothing resolvable → empty")
    R.assertEqual(r.cidrs(from: ""), [], "empty list → empty")

    R.assertEqual(r.cidrs(from: "multi.corp portal.corp"),
                  r.cidrs(from: "portal.corp multi.corp"),
                  "output independent of listing order")
}
