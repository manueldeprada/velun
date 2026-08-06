import Foundation

func testDNSProxyQueryName() {
    R.enter("UnifiedDNSProxy.queryName")
    // Reuse DnsSuffixAutoDetect's encoder to build a well-formed query.
    let q = DnsSuffixAutoDetect.buildDNSQuery(
        txnID: 0x1234, qname: ["login1", "cluster", "is", "localnet"], qtype: 1)
    R.assertEqual(UnifiedDNSProxy.queryName(from: q), "login1.cluster.is.localnet",
                  "parses + lowercases the question name")

    let upper = DnsSuffixAutoDetect.buildDNSQuery(txnID: 1, qname: ["WWW", "ETHZ", "CH"], qtype: 1)
    R.assertEqual(UnifiedDNSProxy.queryName(from: upper), "www.ethz.ch", "case-folds")

    R.assertTrue(UnifiedDNSProxy.queryName(from: Data([0, 1, 2])) == nil, "too-short → nil")
    // A header claiming a question but with a compression pointer in it → nil.
    let badPtr = Data([0,1, 0x01,0x00, 0,1, 0,0, 0,0, 0,0, 0xc0, 0x0c])
    R.assertTrue(UnifiedDNSProxy.queryName(from: badPtr) == nil, "compressed question rejected")
}

func testDNSProxyRoute() {
    R.enter("UnifiedDNSProxy.route")
    let suffixes = [
        (id: "mpi", suffixes: ["localnet"]),
        (id: "eth", suffixes: ["ethz.ch"]),
    ]
    R.assertEqual(UnifiedDNSProxy.route(qname: "login1.cluster.is.localnet",
                                        suffixes: suffixes, defaultID: "eth"),
                  "mpi", "corp suffix → owning upstream")
    R.assertEqual(UnifiedDNSProxy.route(qname: "www.ethz.ch", suffixes: suffixes, defaultID: "eth"),
                  "eth", "eth suffix → eth")
    R.assertEqual(UnifiedDNSProxy.route(qname: "www.google.com", suffixes: suffixes, defaultID: "eth"),
                  "eth", "no match → default (full upstream)")
    R.assertTrue(UnifiedDNSProxy.route(qname: "www.google.com", suffixes: suffixes, defaultID: nil) == nil,
                 "no match + no default → drop")

    // Exact-suffix match (qname == suffix), and most-specific wins.
    R.assertEqual(UnifiedDNSProxy.route(qname: "localnet", suffixes: suffixes, defaultID: nil),
                  "mpi", "qname equal to suffix matches")
    let nested = [
        (id: "wide",   suffixes: ["corp.example"]),
        (id: "narrow", suffixes: ["eng.corp.example"]),
    ]
    R.assertEqual(UnifiedDNSProxy.route(qname: "host.eng.corp.example", suffixes: nested, defaultID: nil),
                  "narrow", "longest matching suffix wins")
    R.assertEqual(UnifiedDNSProxy.route(qname: "host.corp.example", suffixes: nested, defaultID: nil),
                  "wide", "shorter suffix when the longer doesn't match")

    // A bare-domain match shouldn't fire on a partial label ("evil-localnet").
    R.assertEqual(UnifiedDNSProxy.route(qname: "evil-localnet", suffixes: suffixes, defaultID: "eth"),
                  "eth", "suffix match is label-boundary aware, not substring")
}

func testDNSProxyServfail() {
    R.enter("UnifiedDNSProxy.servfailResponse")
    let q = DnsSuffixAutoDetect.buildDNSQuery(
        txnID: 0xBEEF, qname: ["wpad", "localnet"], qtype: 1)
    guard let r = UnifiedDNSProxy.servfailResponse(for: q) else {
        R.assertTrue(false, "well-formed query → response"); return
    }
    R.assertEqual(Int(r[0]) << 8 | Int(r[1]), 0xBEEF, "transaction ID echoed")
    R.assertTrue(r[2] & 0x80 != 0, "QR bit set (response)")
    R.assertEqual(r[2] & 0x78, q[2] & 0x78, "opcode preserved")
    R.assertEqual(r[2] & 0x01, q[2] & 0x01, "RD preserved")
    R.assertTrue(r[3] & 0x80 != 0, "RA set")
    R.assertEqual(r[3] & 0x0f, 2, "RCODE = SERVFAIL")
    R.assertEqual(r.count, q.count, "question section echoed verbatim")
    R.assertEqual(UnifiedDNSProxy.queryName(from: r), "wpad.localnet",
                  "question still parseable from the response")

    // Slice with non-zero start index must not trap or mis-index.
    var padded = Data([0xAA, 0xBB]); padded.append(q)
    let slice = padded[2...]
    R.assertTrue(UnifiedDNSProxy.servfailResponse(for: slice) != nil, "slice input handled")

    R.assertTrue(UnifiedDNSProxy.servfailResponse(for: Data([0, 1, 2])) == nil, "too-short → nil")
}

// MARK: – DNS-learned routes (A-answer parse + /24 coalescing)

private func makeDNSResponse(qname: [String], answers: [(type: UInt16, rdata: [UInt8])],
                             rcode: UInt8 = 0, literalName: Bool = false) -> Data {
    var r = Data()
    r.append(contentsOf: [0x12, 0x34, 0x81, 0x80 | rcode])          // id, QR+RD+RA, rcode
    r.append(contentsOf: [0, 1, UInt8(answers.count >> 8), UInt8(answers.count & 0xff), 0, 0, 0, 0])
    for label in qname {                                             // question
        r.append(UInt8(label.utf8.count)); r.append(contentsOf: Array(label.utf8))
    }
    r.append(contentsOf: [0, 0, 1, 0, 1])                            // root, A, IN
    for a in answers {
        if literalName {
            for label in qname { r.append(UInt8(label.utf8.count)); r.append(contentsOf: Array(label.utf8)) }
            r.append(0)
        } else {
            r.append(contentsOf: [0xc0, 0x0c])                       // pointer to qname
        }
        r.append(contentsOf: [UInt8(a.type >> 8), UInt8(a.type & 0xff), 0, 1])   // type, IN
        r.append(contentsOf: [0, 0, 0, 60])                          // ttl
        r.append(contentsOf: [UInt8(a.rdata.count >> 8), UInt8(a.rdata.count & 0xff)])
        r.append(contentsOf: a.rdata)
    }
    return r
}

func testDNSProxyARecordIPs() {
    R.enter("UnifiedDNSProxy.aRecordIPs")
    let q = ["login1", "cluster", "is", "localnet"]

    let single = makeDNSResponse(qname: q, answers: [(type: 1, rdata: [10, 15, 1, 40])])
    R.assertEqual(UnifiedDNSProxy.aRecordIPs(from: single), [0x0A0F_0128], "single A answer")

    let chain = makeDNSResponse(qname: q, answers: [
        (type: 5, rdata: [0xc0, 0x0c]),
        (type: 1, rdata: [10, 15, 1, 40]),
        (type: 1, rdata: [10, 15, 2, 7]),
    ])
    R.assertEqual(UnifiedDNSProxy.aRecordIPs(from: chain), [0x0A0F_0128, 0x0A0F_0207],
                  "CNAME skipped, both As collected")

    // AAAA (type 28, 16-byte rdata) must not be misread as v4.
    let v6 = makeDNSResponse(qname: q, answers: [(type: 28, rdata: Array(repeating: 0x20, count: 16))])
    R.assertEqual(UnifiedDNSProxy.aRecordIPs(from: v6), [], "AAAA ignored")

    // Literal (uncompressed) answer names parse too.
    let literal = makeDNSResponse(qname: q, answers: [(type: 1, rdata: [10, 15, 1, 40])], literalName: true)
    R.assertEqual(UnifiedDNSProxy.aRecordIPs(from: literal), [0x0A0F_0128], "literal answer name")

    // NXDOMAIN → nothing learned even if a stray answer is present.
    let nx = makeDNSResponse(qname: q, answers: [(type: 1, rdata: [10, 15, 1, 40])], rcode: 3)
    R.assertEqual(UnifiedDNSProxy.aRecordIPs(from: nx), [], "non-zero RCODE ignored")

    // A query (QR=0) never yields answers.
    let query = DnsSuffixAutoDetect.buildDNSQuery(txnID: 1, qname: q, qtype: 1)
    R.assertEqual(UnifiedDNSProxy.aRecordIPs(from: query), [], "query (QR=0) ignored")

    // Truncated rdata: parser stops without trapping, keeps what it had.
    var trunc = makeDNSResponse(qname: q, answers: [
        (type: 1, rdata: [10, 15, 1, 40]),
        (type: 1, rdata: [10, 15, 2, 7]),
    ])
    trunc.removeLast(2)
    R.assertEqual(UnifiedDNSProxy.aRecordIPs(from: trunc), [0x0A0F_0128], "truncated second answer dropped")
}

func testDNSProxyLearnableIP() {
    R.enter("UnifiedDNSProxy.isLearnableIP")
    R.assertTrue(UnifiedDNSProxy.isLearnableIP(0x0A0F_0128), "10.15.1.40 learnable")
    R.assertTrue(UnifiedDNSProxy.isLearnableIP(0xC20F_8937), "194.15.137.55 learnable")
    R.assertTrue(!UnifiedDNSProxy.isLearnableIP(0x0000_0000), "0.0.0.0 (blocklist answer) rejected")
    R.assertTrue(!UnifiedDNSProxy.isLearnableIP(0x7F00_0001), "127.0.0.1 rejected")
    R.assertTrue(!UnifiedDNSProxy.isLearnableIP(0xA9FE_0001), "169.254.0.1 rejected")
    R.assertTrue(!UnifiedDNSProxy.isLearnableIP(0xE000_00FB), "224.0.0.251 (multicast) rejected")
    R.assertTrue(!UnifiedDNSProxy.isLearnableIP(0xFFFF_FFFF), "broadcast rejected")
}

func testDNSProxyCoalesceLearnedRoutes() {
    R.enter("UnifiedDNSProxy.coalesceLearnedRoutes")
    R.assertEqual(UnifiedDNSProxy.coalesceLearnedRoutes([]), [], "empty set")
    R.assertEqual(UnifiedDNSProxy.coalesceLearnedRoutes([0x0A0F_0128]),
                  ["10.15.1.40/32"], "single IP stays /32")
    R.assertEqual(UnifiedDNSProxy.coalesceLearnedRoutes([0x0A0F_0128, 0x0A0F_0107]),
                  ["10.15.1.0/24"], "two IPs in one /24 merge")
    R.assertEqual(UnifiedDNSProxy.coalesceLearnedRoutes([0x0A0F_0128, 0x0A0F_0207, 0xC20F_8937]),
                  ["10.15.1.40/32", "10.15.2.7/32", "194.15.137.55/32"],
                  "different /24s stay /32s, sorted")
    R.assertEqual(UnifiedDNSProxy.coalesceLearnedRoutes([0x0A0F_0128, 0x0A0F_0107, 0x0A0F_01FE, 0xC20F_8937]),
                  ["10.15.1.0/24", "194.15.137.55/32"], "three in one /24 still one /24")
}
