import Foundation

enum UnifiedDNSProxy {

    static let proxyIPString = "198.18.0.53"
    static let proxyIP: UInt32 = 0xC612_0035   // 198.18.0.53

    static func queryName(from dns: Data) -> String? {
        let b = [UInt8](dns)
        guard b.count >= 12 else { return nil }
        let qdcount = Int(b[4]) << 8 | Int(b[5])
        guard qdcount >= 1 else { return nil }
        var i = 12
        var labels: [String] = []
        while i < b.count {
            let len = Int(b[i])
            if len == 0 { break }
            if (len & 0xc0) == 0xc0 { return nil }       // no compression in a question
            let start = i + 1, end = start + len
            guard end <= b.count else { return nil }
            guard let label = String(bytes: b[start..<end], encoding: .utf8) else { return nil }
            labels.append(label)
            i = end
        }
        guard !labels.isEmpty else { return nil }
        return labels.joined(separator: ".").lowercased()
    }

    static func route(qname: String,
                      suffixes: [(id: String, suffixes: [String])],
                      defaultID: String?) -> String? {
        let q = qname.lowercased()
        var bestID: String?
        var bestLen = -1
        for (id, sufs) in suffixes {
            for raw in sufs {
                let suf = raw.lowercased()
                guard !suf.isEmpty else { continue }
                guard q == suf || q.hasSuffix("." + suf) else { continue }
                if suf.count > bestLen { bestLen = suf.count; bestID = id }
            }
        }
        return bestID ?? defaultID
    }

    static func servfailResponse(for query: Data) -> Data? {
        guard query.count >= 12 else { return nil }
        var r = Data(query)                 // re-base slice indices to 0
        r[2] |= 0x80                        // QR = response, opcode/RD kept
        r[3] = (r[3] & 0x70) | 0x82         // RA set, Z/AD/CD kept, RCODE = 2
        return r
    }

    static func aRecordIPs(from dns: Data) -> [UInt32] {
        let b = [UInt8](dns)
        guard b.count >= 12 else { return [] }
        guard b[2] & 0x80 != 0 else { return [] }        // QR = response
        guard b[3] & 0x0f == 0 else { return [] }        // RCODE = NoError
        let qdcount = Int(b[4]) << 8 | Int(b[5])
        let ancount = Int(b[6]) << 8 | Int(b[7])
        guard ancount > 0 else { return [] }
        var i = 12
        for _ in 0..<qdcount {                           // question: name + type + class
            guard let end = skipName(b, at: i), end + 4 <= b.count else { return [] }
            i = end + 4
        }
        var out: [UInt32] = []
        for _ in 0..<ancount {
            guard let end = skipName(b, at: i), end + 10 <= b.count else { return out }
            let type  = Int(b[end]) << 8 | Int(b[end + 1])
            let klass = Int(b[end + 2]) << 8 | Int(b[end + 3])
            let rdlen = Int(b[end + 8]) << 8 | Int(b[end + 9])
            let rdata = end + 10
            guard rdata + rdlen <= b.count else { return out }
            if type == 1, klass == 1, rdlen == 4 {
                out.append(UInt32(b[rdata]) << 24 | UInt32(b[rdata + 1]) << 16
                         | UInt32(b[rdata + 2]) << 8 | UInt32(b[rdata + 3]))
            }
            i = rdata + rdlen
        }
        return out
    }

    private static func skipName(_ b: [UInt8], at start: Int) -> Int? {
        var i = start
        while i < b.count {
            let len = Int(b[i])
            if len == 0 { return i + 1 }
            if (len & 0xc0) == 0xc0 { return i + 2 <= b.count ? i + 2 : nil }
            i += 1 + len
        }
        return nil
    }

    static func isLearnableIP(_ ip: UInt32) -> Bool {
        if ip >> 24 == 0 || ip >> 24 == 127 { return false }   // 0/8, 127/8
        if ip >> 16 == 0xA9FE { return false }                 // 169.254/16
        if ip >> 28 >= 0xE { return false }                    // 224/4 + 240/4
        if ip == 0xFFFF_FFFF { return false }
        return true
    }

    static func coalesceLearnedRoutes(_ ips: Set<UInt32>) -> [String] {
        var by24: [UInt32: [UInt32]] = [:]
        for ip in ips { by24[ip >> 8, default: []].append(ip) }
        return by24.map { net, members in
            members.count >= 2 ? "\(IPv4.toString(net << 8))/24"
                               : "\(IPv4.toString(members[0]))/32"
        }.sorted()
    }
}
