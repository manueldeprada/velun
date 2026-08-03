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
}
