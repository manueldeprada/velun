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
