import Foundation

func testDnsSuffixParentZone() {
    R.enter("DnsSuffixAutoDetect.parentZone")
    R.assertEqual(DnsSuffixAutoDetect.parentZone(of: "cserv2.localnet"),
                  "localnet", "two-label → drop first")
    R.assertEqual(DnsSuffixAutoDetect.parentZone(of: "dns01.cluster.is.localnet"),
                  "cluster.is.localnet", "four-label → drop first")
    R.assertEqual(DnsSuffixAutoDetect.parentZone(of: "cserv2.localnet."),
                  "localnet", "trailing dot stripped")
    R.assertEqual(DnsSuffixAutoDetect.parentZone(of: "cserv2.localnet.."),
                  "localnet", "multiple trailing dots stripped")
    R.assertEqual(DnsSuffixAutoDetect.parentZone(of: "single"),
                  "", "single label has no parent → empty")
    R.assertEqual(DnsSuffixAutoDetect.parentZone(of: ""),
                  "", "empty input → empty")
}

func testDnsSuffixUniqueTargets() {
    R.enter("DnsSuffixAutoDetect.uniqueTargets")
    let cfg = TunnelNetworkConfig(
        ipAddress: "10.1.16.150", netmask: "255.255.248.0",
        gateway: "10.1.16.1", dnsServers: ["10.3.7.82", "10.3.7.181"],
        searchDomains: [], mtu: 1400, splitIncludes: [], splitExcludes: []
    )
    let targets = DnsSuffixAutoDetect.uniqueTargets(for: cfg)
    R.assertEqual(targets, ["10.3.7.82", "10.3.7.181", "10.1.16.150", "10.1.16.1"],
                  "dns servers + assigned IP + gateway, in order")

    // Duplicates collapsed (gateway == assigned IP in some GP configs).
    let cfgDup = TunnelNetworkConfig(
        ipAddress: "10.1.16.150", netmask: "255.255.248.0",
        gateway: "10.1.16.150", dnsServers: ["10.3.7.82", "10.3.7.82"],
        searchDomains: [], mtu: 1400, splitIncludes: [], splitExcludes: []
    )
    R.assertEqual(DnsSuffixAutoDetect.uniqueTargets(for: cfgDup),
                  ["10.3.7.82", "10.1.16.150"], "duplicates collapsed")

    // Invalid / empty entries filtered.
    let cfgJunk = TunnelNetworkConfig(
        ipAddress: "", netmask: "", gateway: "not-an-ip",
        dnsServers: ["10.3.7.82", "", "999.999.999.999"],
        searchDomains: [], mtu: 1400, splitIncludes: [], splitExcludes: []
    )
    R.assertEqual(DnsSuffixAutoDetect.uniqueTargets(for: cfgJunk),
                  ["10.3.7.82"], "invalid IPs dropped")
}

func testDnsSuffixDetectMPI() async {
    R.enter("DnsSuffixAutoDetect.detect (MPI shape)")
    let cfg = TunnelNetworkConfig(
        ipAddress: "10.1.16.150", netmask: "255.255.248.0",
        gateway: "10.1.16.1", dnsServers: ["10.3.7.82", "10.3.7.181"],
        searchDomains: [], mtu: 1400, splitIncludes: [], splitExcludes: []
    )
    let stub: DnsSuffixAutoDetect.PTRLookup = { target, _, _ in
        switch target {
        case "10.3.7.82":  return "cserv2.localnet"
        case "10.3.7.181": return "dnsi.local"            // deny-listed
        default:           return nil
        }
    }
    let suffixes = await DnsSuffixAutoDetect.detect(for: cfg, timeout: 2.0, lookup: stub)
    R.assertEqual(suffixes, ["localnet"],
                  "MPI shape: localnet survives, local deny-listed, nils skipped")
}

func testDnsSuffixDetectDenyList() async {
    R.enter("DnsSuffixAutoDetect.detect (deny-list)")
    let cfg = TunnelNetworkConfig(
        ipAddress: "10.0.0.5", netmask: "255.0.0.0",
        gateway: "10.0.0.1", dnsServers: ["10.0.0.53"],
        searchDomains: [], mtu: 1400, splitIncludes: [], splitExcludes: []
    )
    // Every answer's parent is on the deny-list — result should be empty.
    let stub: DnsSuffixAutoDetect.PTRLookup = { target, _, _ in
        switch target {
        case "10.0.0.53": return "ns.local"
        case "10.0.0.5":  return "host.arpa"
        case "10.0.0.1":  return "gw.localhost"
        default:          return nil
        }
    }
    let suffixes = await DnsSuffixAutoDetect.detect(for: cfg, timeout: 2.0, lookup: stub)
    R.assertEqual(suffixes, [],
                  "every parent on deny-list → empty result")
}

func testDnsSuffixDetectMultipleZones() async {
    R.enter("DnsSuffixAutoDetect.detect (multiple distinct zones)")
    let cfg = TunnelNetworkConfig(
        ipAddress: "10.1.16.150", netmask: "255.255.248.0",
        gateway: "10.1.16.1", dnsServers: ["10.3.7.82", "10.3.7.181"],
        searchDomains: [], mtu: 1400, splitIncludes: [], splitExcludes: []
    )
    let stub: DnsSuffixAutoDetect.PTRLookup = { target, _, _ in
        switch target {
        case "10.3.7.82":  return "ns1.corp.example.com"
        case "10.3.7.181": return "ns2.eng.example.com"
        case "10.1.16.150": return "vpn-pool-150.corp.example.com"
        case "10.1.16.1":  return "vpn-gw.corp.example.com"
        default: return nil
        }
    }
    let suffixes = await DnsSuffixAutoDetect.detect(for: cfg, timeout: 2.0, lookup: stub)
    R.assertEqual(Set(suffixes), Set(["corp.example.com", "eng.example.com"]),
                  "two zones from four targets, deduped")
    R.assertEqual(suffixes.count, 2, "no duplicates")
}

func testDnsSuffixDetectCaseFolding() async {
    R.enter("DnsSuffixAutoDetect.detect (case folding)")
    let cfg = TunnelNetworkConfig(
        ipAddress: "10.1.16.150", netmask: "255.255.248.0",
        gateway: "10.1.16.1", dnsServers: ["10.3.7.82"],
        searchDomains: [], mtu: 1400, splitIncludes: [], splitExcludes: []
    )
    let stub: DnsSuffixAutoDetect.PTRLookup = { _, _, _ in "CSERV2.LocalNet" }
    let suffixes = await DnsSuffixAutoDetect.detect(for: cfg, timeout: 2.0, lookup: stub)
    R.assertEqual(suffixes, ["localnet"], "mixed-case PTR → lowercased suffix")
}

func testDnsSuffixDetectNoDNSServer() async {
    R.enter("DnsSuffixAutoDetect.detect (no DNS server)")
    let cfg = TunnelNetworkConfig(
        ipAddress: "10.1.16.150", netmask: "255.255.248.0",
        gateway: "10.1.16.1", dnsServers: [],
        searchDomains: [], mtu: 1400, splitIncludes: [], splitExcludes: []
    )
    let stub: DnsSuffixAutoDetect.PTRLookup = { _, _, _ in "unreachable.example.com" }
    let suffixes = await DnsSuffixAutoDetect.detect(for: cfg, timeout: 2.0, lookup: stub)
    R.assertEqual(suffixes, [], "no DNS server → skip probe, return empty")
}

// MARK: – DNS wire format

func testDnsSuffixBuildPTRQuery() {
    R.enter("DnsSuffixAutoDetect.buildDNSQuery (PTR)")
    guard let qname = DnsSuffixAutoDetect.ptrQName(for: "10.3.7.82") else {
        R.assertTrue(false, "qname construction failed")
        return
    }
    R.assertEqual(qname, ["82", "7", "3", "10", "in-addr", "arpa"],
                  "in-addr.arpa labels reversed")

    let q = DnsSuffixAutoDetect.buildDNSQuery(txnID: 0x1234, qname: qname, qtype: 12)
    // Header: 0x1234 0x0100 0x0001 0x0000 0x0000 0x0000
    let expectedHeader: [UInt8] = [
        0x12, 0x34,    // txn ID
        0x01, 0x00,    // flags: standard query, RD=1
        0x00, 0x01,    // QDCOUNT
        0x00, 0x00,    // ANCOUNT
        0x00, 0x00,    // NSCOUNT
        0x00, 0x00,    // ARCOUNT
    ]
    R.assertEqual([UInt8](q.prefix(12)), expectedHeader, "DNS header bytes match")

    let expectedQNAME: [UInt8] = [
        0x02, 0x38, 0x32,                            // "82"
        0x01, 0x37,                                  // "7"
        0x01, 0x33,                                  // "3"
        0x02, 0x31, 0x30,                            // "10"
        0x07, 0x69, 0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72,   // "in-addr"
        0x04, 0x61, 0x72, 0x70, 0x61,                // "arpa"
        0x00,                                        // root
    ]
    R.assertEqual([UInt8](q.dropFirst(12).prefix(24)), expectedQNAME, "QNAME encoded")

    // Trailer: QTYPE=0x000c (PTR) QCLASS=0x0001 (IN)
    let trailer: [UInt8] = [0x00, 0x0c, 0x00, 0x01]
    R.assertEqual([UInt8](q.suffix(4)), trailer, "QTYPE + QCLASS")
    R.assertEqual(q.count, 12 + 24 + 4, "total query length")
}

func testDnsSuffixParsePTRResponse() {
    R.enter("DnsSuffixAutoDetect.parseFirstPTR")
    var pkt: [UInt8] = []
    // Header
    pkt += [0x12, 0x34, 0x81, 0x80,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
    // Question section (qname + qtype + qclass)
    pkt += [0x02, 0x38, 0x32,
            0x01, 0x37,
            0x01, 0x33,
            0x02, 0x31, 0x30,
            0x07, 0x69, 0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72,
            0x04, 0x61, 0x72, 0x70, 0x61,
            0x00,
            0x00, 0x0c, 0x00, 0x01]
    // Answer NAME = compression pointer to question (offset 12 = start of qname)
    pkt += [0xc0, 0x0c]
    // TYPE=PTR (12), CLASS=IN (1), TTL=86400 (0x00015180)
    pkt += [0x00, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x51, 0x80]
    // RDLENGTH (2 bytes) + RDATA (cserv2.localnet with root terminator)
    let rdata: [UInt8] = [
        0x06, 0x63, 0x73, 0x65, 0x72, 0x76, 0x32,     // "cserv2"
        0x08, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x6e, 0x65, 0x74,  // "localnet"
        0x00,
    ]
    pkt += [UInt8(rdata.count >> 8), UInt8(rdata.count & 0xff)]
    pkt += rdata

    let data = Data(pkt)
    let parsed = DnsSuffixAutoDetect.parseFirstPTR(data, expectedTxnID: 0x1234)
    R.assertEqual(parsed, "cserv2.localnet", "PTR answer decoded")

    // Transaction-ID mismatch → nil
    let wrongID = DnsSuffixAutoDetect.parseFirstPTR(data, expectedTxnID: 0x0001)
    R.assertEqual(wrongID, nil, "wrong txn ID rejected")
}

func testDnsSuffixParsePTRResponseTruncated() {
    R.enter("DnsSuffixAutoDetect.parseFirstPTR (malformed)")
    R.assertEqual(DnsSuffixAutoDetect.parseFirstPTR(Data(), expectedTxnID: 0),
                  nil, "empty input → nil")
    R.assertEqual(DnsSuffixAutoDetect.parseFirstPTR(Data([0, 0, 0, 0, 0]), expectedTxnID: 0),
                  nil, "truncated header → nil")

    // Header says ANCOUNT=0 → nil
    let noAnswers: [UInt8] = [
        0x00, 0x01, 0x81, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
    R.assertEqual(DnsSuffixAutoDetect.parseFirstPTR(Data(noAnswers), expectedTxnID: 0x0001),
                  nil, "ANCOUNT=0 → nil")
}
