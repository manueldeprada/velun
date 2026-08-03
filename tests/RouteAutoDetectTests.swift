import Foundation

func testRouteAutoDetect() {
    R.enter("RouteAutoDetect")

    // Helper to build a minimal TunnelNetworkConfig
    func cfg(dns: [String] = [], domains: [String] = [],
             splitIncludes: [String] = []) -> TunnelNetworkConfig {
        TunnelNetworkConfig(
            ipAddress: "10.0.0.5", netmask: "255.255.255.255",
            gateway: "10.0.0.1", dnsServers: dns,
            searchDomains: domains, mtu: 1400,
            splitIncludes: splitIncludes, splitExcludes: []
        )
    }

    // Stub resolver: deterministic by domain.
    let stub: RouteAutoDetect.Resolver = { domain in
        switch domain {
        case "ethz.ch":      return ["129.132.19.7"]
        case "corp.acme":    return ["10.50.1.1"]              // private only
        case "example.com":  return ["93.184.216.34"]          // public
        case "":             return []
        default:             return []
        }
    }

    // 1. Public DNS server → /16 derived
    R.assertEqual(
        RouteAutoDetect.detect(for: cfg(dns: ["129.132.250.5"]), resolver: stub),
        ["129.132.0.0/16"],
        "single public DNS → /16"
    )

    // 2. Multiple DNS servers in the same /16 collapse to one entry
    R.assertEqual(
        RouteAutoDetect.detect(for: cfg(dns: ["129.132.250.5", "129.132.250.6"]),
                               resolver: stub),
        ["129.132.0.0/16"],
        "duplicate /16 collapses"
    )

    R.assertEqual(
        RouteAutoDetect.detect(for: cfg(dns: ["129.132.250.5", "10.0.0.1"]),
                               resolver: stub),
        ["129.132.0.0/16"],
        "mixed public+private DNS uses only public"
    )

    R.assertEqual(
        RouteAutoDetect.detect(for: cfg(dns: ["10.50.1.1", "172.16.0.1"]),
                               resolver: stub),
        ["10.50.0.0/16", "172.16.0.0/16"],
        "all-private DNS still produces routes"
    )

    // 5. Search-domain forward resolution adds /16 of the resolved A record.
    R.assertEqual(
        RouteAutoDetect.detect(for: cfg(dns: ["8.8.8.8"], domains: ["ethz.ch"]),
                               resolver: stub),
        ["8.8.0.0/16", "129.132.0.0/16"],
        "search domain resolves to /16"
    )

    R.assertEqual(
        RouteAutoDetect.detect(for: cfg(dns: ["129.132.250.5"], domains: ["corp.acme"]),
                               resolver: stub),
        ["129.132.0.0/16"],
        "private resolved domain skipped when public DNS present"
    )

    // 7. Invalid DNS strings are skipped silently
    R.assertEqual(
        RouteAutoDetect.detect(for: cfg(dns: ["not.an.ip", "129.132.250.5", "::1"]),
                               resolver: stub),
        ["129.132.0.0/16"],
        "garbage DNS entries skipped"
    )

    // 8. CGNAT 100.64.0.0/10 counts as private (per RFC6598)
    R.assertTrue(RouteAutoDetect.isPrivate("100.65.0.1"), "CGNAT detected")
    R.assertTrue(!RouteAutoDetect.isPrivate("100.63.0.1"), "100.63 not in CGNAT range")

    // 9. RFC1918 boundaries
    R.assertTrue(RouteAutoDetect.isPrivate("172.16.0.1"),  "172.16 lower boundary")
    R.assertTrue(RouteAutoDetect.isPrivate("172.31.255.255"), "172.31 upper boundary")
    R.assertTrue(!RouteAutoDetect.isPrivate("172.15.0.1"), "172.15 not RFC1918")
    R.assertTrue(!RouteAutoDetect.isPrivate("172.32.0.1"), "172.32 not RFC1918")

    // 10. CIDR construction is /16, not /24
    R.assertEqual(RouteAutoDetect.cidr16(of: "129.132.250.5") ?? "",
                  "129.132.0.0/16",
                  "cidr16 of public IP")

    // 11. Empty DNS + empty domains → empty result (caller falls back to full)
    R.assertEqual(
        RouteAutoDetect.detect(for: cfg(), resolver: stub),
        [],
        "no hints → empty list"
    )
}
