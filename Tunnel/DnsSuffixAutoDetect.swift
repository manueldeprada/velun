import Foundation
import OSLog

private let log = Logger(subsystem: "com.manueldeprada.velun.PacketTunnel",
                         category: "DnsAutoDetect")

enum DnsSuffixAutoDetect {

    typealias PTRLookup = @Sendable (_ target: String, _ dnsServer: String, _ timeout: TimeInterval) async -> String?

    static let denyList: Set<String> = [
        "local",
        "arpa",
        "localhost",
        "invalid",
        "example",
        "test",
        "home",
        "lan",
        "",
    ]

    static func detect(for cfg: TunnelNetworkConfig,
                       timeout: TimeInterval = 1.0,
                       lookup: @escaping PTRLookup = systemLookup) async -> [String] {
        let targets = uniqueTargets(for: cfg)
        guard let dnsServer = cfg.dnsServers.first(where: { isValidIPv4($0) }) else {
            log.info("dns-suffix probe: no DNS server, skipping")
            return []
        }
        guard !targets.isEmpty else {
            log.info("dns-suffix probe: no probe targets, skipping")
            return []
        }
        log.info("dns-suffix probe: dns=\(dnsServer, privacy: .public) targets=\(targets.joined(separator: ","), privacy: .public) timeout=\(timeout)s")

        let probeTimeout = timeout
        let answers: [String?] = await withTaskGroup(of: String?.self) { group in
            for target in targets {
                group.addTask {
                    await lookup(target, dnsServer, probeTimeout)
                }
            }
            var out: [String?] = []
            for await ans in group { out.append(ans) }
            return out
        }

        var suffixes: [String] = []
        var seen = Set<String>()
        for case let .some(fqdn) in answers {
            let parent = parentZone(of: fqdn)
            let lower = parent.lowercased()
            if denyList.contains(lower) { continue }
            if seen.insert(lower).inserted { suffixes.append(lower) }
        }
        log.info("dns-suffix probe: derived=\(suffixes.joined(separator: ","), privacy: .public)")
        return suffixes
    }

    /// Build the dedup list of IPs to PTR-probe.
    static func uniqueTargets(for cfg: TunnelNetworkConfig) -> [String] {
        var out: [String] = []
        var seen = Set<String>()
        let candidates = cfg.dnsServers + [cfg.ipAddress, cfg.gateway]
        for raw in candidates {
            let s = raw.trimmingCharacters(in: .whitespaces)
            guard !s.isEmpty, isValidIPv4(s), seen.insert(s).inserted else { continue }
            out.append(s)
        }
        return out
    }

    static func parentZone(of fqdn: String) -> String {
        var s = fqdn
        while s.hasSuffix(".") { s.removeLast() }
        let labels = s.split(separator: ".").map(String.init)
        guard labels.count >= 2 else { return "" }
        return labels.dropFirst().joined(separator: ".")
    }

    static func isValidIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".").compactMap { Int($0) }
        return parts.count == 4 && parts.allSatisfy { $0 >= 0 && $0 <= 255 }
    }

    // MARK: - Test lookup (stub)

    static let systemLookup: PTRLookup = { _, _, _ in nil }

    // MARK: - Production probe via tunnel adapter

    static func detectViaTunnel(for cfg: TunnelNetworkConfig,
                                tunnel: SSLVPNFamilyTunnel,
                                timeout: TimeInterval = 1.5) async -> [String] {
        let targets = uniqueTargets(for: cfg)
        guard let dnsServer = cfg.dnsServers.first(where: { isValidIPv4($0) }) else {
            log.info("dns-suffix probe: no DNS server, skipping")
            return []
        }
        guard !targets.isEmpty, isValidIPv4(cfg.ipAddress) else {
            log.info("dns-suffix probe: no targets / invalid source IP, skipping")
            return []
        }
        log.info("dns-suffix probe via tunnel: dns=\(dnsServer, privacy: .public) src=\(cfg.ipAddress, privacy: .public) targets=\(targets.joined(separator: ","), privacy: .public) timeout=\(timeout)s")

        // Build queries keyed by src ephemeral port.
        struct Probe { let target: String; let txnID: UInt16 }
        var queries: [UInt16: Probe] = [:]
        var packets: [Data] = []
        for (i, target) in targets.enumerated() {
            guard let qname = ptrQName(for: target) else { continue }
            let txnID  = UInt16.random(in: 1...0xfffe)
            let srcPort = UInt16(51000 + i)
            let dns    = buildDNSQuery(txnID: txnID, qname: qname, qtype: 12)
            let packet = buildIPv4UDPPacket(srcIP: cfg.ipAddress, dstIP: dnsServer,
                                            srcPort: srcPort, dstPort: 53,
                                            payload: dns, ipID: UInt16(0x1000 + i))
            if !packet.isEmpty {
                queries[srcPort] = Probe(target: target, txnID: txnID)
                packets.append(packet)
            }
        }
        guard !queries.isEmpty else { return [] }

        // Send all queries.
        for pkt in packets {
            try? await tunnel.writeDataPacket(pkt)
        }

        let wakePort: UInt16 = 51999
        let wakeTask = Task {
            try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            guard let wqname = ptrQName(for: cfg.ipAddress) else { return }
            let wdns = buildDNSQuery(txnID: 0xdead, qname: wqname, qtype: 12)
            let wpkt = buildIPv4UDPPacket(srcIP: cfg.ipAddress, dstIP: dnsServer,
                                          srcPort: wakePort, dstPort: 53,
                                          payload: wdns, ipID: 0xdead)
            try? await tunnel.writeDataPacket(wpkt)
        }

        // Read responses.
        var answers: [String: String] = [:]
        var seen = Set<UInt16>()
        let deadline = Date().addingTimeInterval(timeout + 0.5)   // small grace past wake
    readLoop:
        while seen.count < queries.count, Date() < deadline {
            let pkt: Data?
            do { pkt = try await tunnel.readDataPacket() } catch {
                log.error("dns-suffix probe: read failed: \(error.localizedDescription, privacy: .public)")
                break readLoop
            }
            guard let pkt, let (srcPort, dstPort, payload) = parseUDPInIPv4(pkt) else { continue }
            if srcPort != 53 { continue }
            if dstPort == wakePort {
                // Wake response arrived — exit if past timeout, else continue.
                if Date() >= deadline - 0.5 { break readLoop }
                continue
            }
            guard let q = queries[dstPort], !seen.contains(dstPort) else { continue }
            seen.insert(dstPort)
            if let fqdn = parseFirstPTR(payload, expectedTxnID: q.txnID) {
                answers[q.target] = fqdn
                log.info("dns-suffix probe: target=\(q.target, privacy: .public) → \(fqdn, privacy: .public)")
            } else {
                log.info("dns-suffix probe: target=\(q.target, privacy: .public) → (no PTR)")
            }
        }
        wakeTask.cancel()

        // Apply parent-zone + deny-list to derive suffixes.
        var suffixes: [String] = []
        var seenSuffix = Set<String>()
        for fqdn in answers.values {
            let parent = parentZone(of: fqdn).lowercased()
            if denyList.contains(parent) { continue }
            if seenSuffix.insert(parent).inserted { suffixes.append(parent) }
        }
        log.info("dns-suffix probe via tunnel: derived=\(suffixes.joined(separator: ","), privacy: .public)")
        return suffixes
    }

    // MARK: - Raw IPv4+UDP packet construction

    static func buildIPv4UDPPacket(srcIP: String, dstIP: String,
                                   srcPort: UInt16, dstPort: UInt16,
                                   payload: Data, ipID: UInt16) -> Data {
        guard let s = ipv4ToUInt32(srcIP), let d = ipv4ToUInt32(dstIP) else { return Data() }
        let udpLen = UInt16(8 + payload.count)
        var udp = [UInt8]()
        udp.append(UInt8(srcPort >> 8)); udp.append(UInt8(srcPort & 0xff))
        udp.append(UInt8(dstPort >> 8)); udp.append(UInt8(dstPort & 0xff))
        udp.append(UInt8(udpLen  >> 8)); udp.append(UInt8(udpLen  & 0xff))
        udp.append(0); udp.append(0)                       // checksum=0 (optional)
        let udpData = Data(udp) + payload

        let totalLen = UInt16(20 + udpData.count)
        var ip = [UInt8]()
        ip.append(0x45)                                    // version 4, IHL 5
        ip.append(0x00)                                    // TOS
        ip.append(UInt8(totalLen >> 8)); ip.append(UInt8(totalLen & 0xff))
        ip.append(UInt8(ipID >> 8)); ip.append(UInt8(ipID & 0xff))
        ip.append(0x40); ip.append(0x00)                   // DF, no fragment
        ip.append(64)                                      // TTL
        ip.append(17)                                      // proto = UDP
        ip.append(0); ip.append(0)                         // header checksum placeholder
        ip.append(UInt8((s >> 24) & 0xff)); ip.append(UInt8((s >> 16) & 0xff))
        ip.append(UInt8((s >>  8) & 0xff)); ip.append(UInt8( s        & 0xff))
        ip.append(UInt8((d >> 24) & 0xff)); ip.append(UInt8((d >> 16) & 0xff))
        ip.append(UInt8((d >>  8) & 0xff)); ip.append(UInt8( d        & 0xff))
        let cs = onesComplementChecksum(Data(ip))
        ip[10] = UInt8(cs >> 8); ip[11] = UInt8(cs & 0xff)
        return Data(ip) + udpData
    }

    static func parseUDPInIPv4(_ data: Data) -> (UInt16, UInt16, Data)? {
        guard data.count >= 28 else { return nil }
        let b = [UInt8](data)
        guard (b[0] >> 4) == 4 else { return nil }      // IPv4
        let ihl = Int(b[0] & 0x0f) * 4
        guard ihl >= 20, data.count >= ihl + 8 else { return nil }
        guard b[9] == 17 else { return nil }            // UDP
        let u = ihl
        let srcPort = (UInt16(b[u]) << 8)     | UInt16(b[u + 1])
        let dstPort = (UInt16(b[u + 2]) << 8) | UInt16(b[u + 3])
        let udpLen  = Int((UInt16(b[u + 4]) << 8) | UInt16(b[u + 5]))
        guard udpLen >= 8, ihl + udpLen <= data.count else { return nil }
        let payloadStart = data.startIndex + ihl + 8
        let payloadEnd   = data.startIndex + ihl + udpLen
        return (srcPort, dstPort, data.subdata(in: payloadStart..<payloadEnd))
    }

    /// "10.3.7.82" → 0x0A030752.
    private static func ipv4ToUInt32(_ s: String) -> UInt32? {
        let parts = s.split(separator: ".").compactMap { UInt32($0) }
        guard parts.count == 4, parts.allSatisfy({ $0 <= 255 }) else { return nil }
        return parts.reduce(UInt32(0)) { ($0 << 8) | $1 }
    }

    /// 16-bit one's-complement Internet checksum (RFC 1071).
    private static func onesComplementChecksum(_ data: Data) -> UInt16 {
        var sum: UInt32 = 0
        var i = data.startIndex
        while i + 1 < data.endIndex {
            sum &+= UInt32(data[i]) << 8 | UInt32(data[i + 1])
            i += 2
        }
        if i < data.endIndex { sum &+= UInt32(data[i]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return ~UInt16(sum & 0xffff)
    }

    static func ptrQName(for ipv4: String) -> [String]? {
        let parts = ipv4.split(separator: ".").map(String.init)
        guard parts.count == 4 else { return nil }
        return parts.reversed() + ["in-addr", "arpa"]
    }

    static func buildDNSQuery(txnID: UInt16, qname: [String], qtype: UInt16) -> Data {
        var d = Data()
        // header
        d.append(UInt8(txnID >> 8)); d.append(UInt8(txnID & 0xff))
        d.append(0x01); d.append(0x00)              // flags: standard query, RD=1
        d.append(0x00); d.append(0x01)              // QDCOUNT = 1
        d.append(0x00); d.append(0x00)              // ANCOUNT
        d.append(0x00); d.append(0x00)              // NSCOUNT
        d.append(0x00); d.append(0x00)              // ARCOUNT
        // qname: length-prefixed labels, null-terminated
        for label in qname {
            let bytes = Array(label.utf8)
            guard bytes.count <= 63 else { return Data() }
            d.append(UInt8(bytes.count))
            d.append(contentsOf: bytes)
        }
        d.append(0x00)                              // root label terminator
        d.append(UInt8(qtype >> 8)); d.append(UInt8(qtype & 0xff)) // QTYPE
        d.append(0x00); d.append(0x01)              // QCLASS = IN
        return d
    }

    static func parseFirstPTR(_ data: Data, expectedTxnID: UInt16) -> String? {
        let b = [UInt8](data)
        guard b.count >= 12 else { return nil }
        let txnID = UInt16(b[0]) << 8 | UInt16(b[1])
        guard txnID == expectedTxnID else { return nil }
        let flags = UInt16(b[2]) << 8 | UInt16(b[3])
        guard (flags & 0x8000) != 0 else { return nil }       // QR must be 1
        let rcode = flags & 0x000f
        guard rcode == 0 else { return nil }                  // NOERROR
        let qdcount = Int(UInt16(b[4]) << 8 | UInt16(b[5]))
        let ancount = Int(UInt16(b[6]) << 8 | UInt16(b[7]))
        guard ancount > 0 else { return nil }

        // Skip question section.
        var off = 12
        for _ in 0..<qdcount {
            guard let next = skipName(b, off) else { return nil }
            off = next + 4    // QTYPE(2) + QCLASS(2)
            guard off <= b.count else { return nil }
        }

        // Walk answers; return the first PTR.
        for _ in 0..<ancount {
            guard let afterName = skipName(b, off) else { return nil }
            // type(2) class(2) ttl(4) rdlength(2) rdata(rdlength)
            guard afterName + 10 <= b.count else { return nil }
            let atype = UInt16(b[afterName]) << 8 | UInt16(b[afterName + 1])
            let rdlen = Int(UInt16(b[afterName + 8]) << 8 | UInt16(b[afterName + 9]))
            let rdataStart = afterName + 10
            guard rdataStart + rdlen <= b.count else { return nil }
            if atype == 12 {  // PTR
                if let (name, _) = readName(b, rdataStart) {
                    return name
                }
            }
            off = rdataStart + rdlen
        }
        return nil
    }

    private static func skipName(_ b: [UInt8], _ start: Int) -> Int? {
        var i = start
        while i < b.count {
            let len = b[i]
            if len == 0 { return i + 1 }
            if (len & 0xc0) == 0xc0 {        // compression pointer: 2 bytes total
                guard i + 1 < b.count else { return nil }
                return i + 2
            }
            i += Int(len) + 1
        }
        return nil
    }

    private static func readName(_ b: [UInt8], _ start: Int) -> (String, Int)? {
        var labels: [String] = []
        var i = start
        var hops = 0
        var endOfInline: Int? = nil
        while i < b.count {
            let len = b[i]
            if len == 0 {
                if endOfInline == nil { endOfInline = i + 1 }
                break
            }
            if (len & 0xc0) == 0xc0 {        // pointer
                guard i + 1 < b.count else { return nil }
                if endOfInline == nil { endOfInline = i + 2 }
                let ptr = Int(UInt16(len & 0x3f) << 8 | UInt16(b[i + 1]))
                guard ptr < b.count else { return nil }
                i = ptr
                hops += 1
                if hops > 16 { return nil }
                continue
            }
            let labelStart = i + 1
            let labelEnd = labelStart + Int(len)
            guard labelEnd <= b.count else { return nil }
            if let label = String(bytes: b[labelStart..<labelEnd], encoding: .utf8) {
                labels.append(label)
            } else {
                return nil
            }
            i = labelEnd
        }
        return (labels.joined(separator: "."), endOfInline ?? i)
    }
}

