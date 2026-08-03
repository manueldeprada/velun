import Foundation

func testSharedTunnelConfigCodable() throws {
    R.enter("SharedTunnelConfig Codable")

    var c = SharedTunnelConfig()
    c.providerType = "globalprotect"
    c.host         = "vpn.example.com"
    c.port         = 4443
    c.username     = "alice"
    c.password     = "p@ss\nword"   // includes special chars
    c.group        = "engineering"
    c.totpSecret   = "base32:JBSWY3DPEHPK3PXP"
    c.userAgent    = "PAN GlobalProtect"
    c.partialMode  = .partialAuto
    c.manualRoutes = ""

    let data = try JSONEncoder().encode(c)
    let back = try JSONDecoder().decode(SharedTunnelConfig.self, from: data)
    R.assertEqual(back, c, "config round-trips through JSON intact")

    // Default-init produces .full + empty manual routes
    let dflt = SharedTunnelConfig()
    R.assertEqual(dflt.partialMode, .full,  "default partialMode is .full")
    R.assertEqual(dflt.manualRoutes, "",   "default manualRoutes empty")

    let oldStyleJSON = """
    {"providerType":"anyconnect","host":"x","port":443,"username":"u",
     "password":"","group":"","totpSecret":"","userAgent":"AnyConnect",
     "wgConf":""}
    """.data(using: .utf8)!
    do {
        _ = try JSONDecoder().decode(SharedTunnelConfig.self, from: oldStyleJSON)
        R.assertTrue(false, "expected decoder to require partialMode")
    } catch {
        // Expected — tests document that the field is currently required.
        R.assertTrue(true, "old-style JSON without partialMode is rejected")
    }
}

func testAppliedRoutesReportCodable() throws {
    R.enter("AppliedRoutesReport Codable")

    let r = AppliedRoutesReport(
        source: .auto,
        routes: ["129.132.0.0/16", "10.0.0.0/16"],
        explanation: "Auto-detected from VPN DNS / search domains"
    )
    let data = try JSONEncoder().encode(r)
    let back = try JSONDecoder().decode(AppliedRoutesReport.self, from: data)
    R.assertEqual(back, r, "applied-routes report round-trips")

    var withHosts = r
    withHosts.resolvedHostRoutes = ["194.15.137.55/32"]
    let hData = try JSONEncoder().encode(withHosts)
    let hBack = try JSONDecoder().decode(AppliedRoutesReport.self, from: hData)
    R.assertEqual(hBack, withHosts, "resolvedHostRoutes round-trips")

    // Each Source case must round-trip its rawValue.
    for s in [AppliedRoutesReport.Source.full,
              .server, .auto, .manual] {
        let rep = AppliedRoutesReport(source: s, routes: [], explanation: "x")
        let data = try JSONEncoder().encode(rep)
        let back = try JSONDecoder().decode(AppliedRoutesReport.self, from: data)
        R.assertEqual(back.source, s, "source rawValue '\(s.rawValue)' round-trips")
    }
}

func testPartialTunnelModeRawValues() {
    R.enter("PartialTunnelMode rawValues")
    R.assertEqual(PartialTunnelMode.full.rawValue,          "full",          "full raw")
    R.assertEqual(PartialTunnelMode.partialAuto.rawValue,   "partialAuto",   "partialAuto raw")
    R.assertEqual(PartialTunnelMode.partialManual.rawValue, "partialManual", "partialManual raw")
}

func testUnifiedIPCCodable() throws {
    R.enter("UnifiedIPC Codable + action contract")

    // Action names are a wire contract; pin them so a rename is caught.
    R.assertEqual(UnifiedIPC.Action.addUpstream,    "u.addUpstream",    "addUpstream action stable")
    R.assertEqual(UnifiedIPC.Action.removeUpstream, "u.removeUpstream", "removeUpstream action stable")
    R.assertEqual(UnifiedIPC.Action.setRouting,     "u.setRouting",     "setRouting action stable")
    R.assertEqual(UnifiedIPC.Action.setDomainRoutes, "u.setDomainRoutes", "setDomainRoutes action stable")
    R.assertEqual(UnifiedIPC.Action.status,         "u.status",         "status action stable")
    R.assertEqual(UnifiedIPC.Action.appliedRoutes,  "u.appliedRoutes",  "appliedRoutes action stable")
    R.assertEqual(UnifiedIPC.Action.lastError,      "u.lastError",      "lastError action stable")

    // addUpstream carries a full SharedTunnelConfig and round-trips.
    var cfg = SharedTunnelConfig()
    cfg.profileID = "E1A2-MPI"; cfg.host = "vpn.mpi.example"; cfg.providerType = "anyconnect"
    cfg.partialMode = .partialManual; cfg.manualRoutes = "10.15.0.0/16"
    let add = UnifiedIPC.AddUpstream(config: cfg)
    let addData = try JSONEncoder().encode(add)
    R.assertEqual(UnifiedIPC.action(in: addData), UnifiedIPC.Action.addUpstream,
                  "action(in:) peeks addUpstream without full decode")
    let addBack = try JSONDecoder().decode(UnifiedIPC.AddUpstream.self, from: addData)
    R.assertEqual(addBack, add, "AddUpstream round-trips")

    // ByProfile shapes (remove / appliedRoutes / lastError).
    for built in [UnifiedIPC.removeUpstream("P"), UnifiedIPC.appliedRoutes("P"), UnifiedIPC.lastError("P")] {
        let d = try JSONEncoder().encode(built)
        R.assertEqual(UnifiedIPC.action(in: d), built.action, "ByProfile action(\(built.action)) survives")
        let pBack = try JSONDecoder().decode(UnifiedIPC.ByProfile.self, from: d)
        R.assertEqual(pBack, built, "ByProfile round-trips")
    }

    // setRouting
    let sr = UnifiedIPC.SetRouting(profileID: "P", partialMode: PartialTunnelMode.full.rawValue, manualRoutes: "")
    let srData = try JSONEncoder().encode(sr)
    let srBack = try JSONDecoder().decode(UnifiedIPC.SetRouting.self, from: srData)
    R.assertEqual(srBack, sr, "SetRouting round-trips")

    // setDomainRoutes (host-resolved hostname /32s)
    let sdr = UnifiedIPC.SetDomainRoutes(profileID: "P", cidrs: ["194.15.137.55/32"])
    let sdrData = try JSONEncoder().encode(sdr)
    R.assertEqual(UnifiedIPC.action(in: sdrData), UnifiedIPC.Action.setDomainRoutes,
                  "action(in:) peeks setDomainRoutes")
    let sdrBack = try JSONDecoder().decode(UnifiedIPC.SetDomainRoutes.self, from: sdrData)
    R.assertEqual(sdrBack, sdr, "SetDomainRoutes round-trips")

    // status reply map
    let reply = UnifiedIPC.StatusReply(statuses: ["A": "connected", "B": "connecting", "C": "failed"])
    let rData = try JSONEncoder().encode(reply)
    let replyBack = try JSONDecoder().decode(UnifiedIPC.StatusReply.self, from: rData)
    R.assertEqual(replyBack, reply, "StatusReply round-trips")

    // stats reply map (profileID → [sent, rcvd])
    let stats = UnifiedIPC.StatsReply(stats: ["A": [12345, 67890], "B": [0, 0]])
    let stData = try JSONEncoder().encode(stats)
    let stBack = try JSONDecoder().decode(UnifiedIPC.StatsReply.self, from: stData)
    R.assertEqual(stBack, stats, "StatsReply round-trips")

    // UpstreamState rawValues are also a wire contract.
    R.assertEqual(UnifiedIPC.UpstreamState.connected.rawValue,    "connected",    "state connected raw")
    R.assertEqual(UnifiedIPC.UpstreamState.connecting.rawValue,   "connecting",   "state connecting raw")
    R.assertEqual(UnifiedIPC.UpstreamState.disconnected.rawValue, "disconnected", "state disconnected raw")
    R.assertEqual(UnifiedIPC.UpstreamState.failed.rawValue,       "failed",       "state failed raw")
}
