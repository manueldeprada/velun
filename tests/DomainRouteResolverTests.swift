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
