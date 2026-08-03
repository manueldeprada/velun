import Foundation

struct DomainRouteResolver {

    var resolve: (String) -> [String]

    static func hostnames(from raw: String) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        let separators = CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: ","))
        for token in raw.components(separatedBy: separators) {
            var t = token.trimmingCharacters(in: .whitespaces).lowercased()
            guard !t.isEmpty else { continue }
            if let r = t.range(of: "://") { t = String(t[r.upperBound...]) }   // scheme
            if let i = t.firstIndex(where: { "/?#".contains($0) }) { t = String(t[..<i]) }  // path/query/fragment
            if let at = t.lastIndex(of: "@") { t = String(t[t.index(after: at)...]) }       // userinfo
            if let colon = t.firstIndex(of: ":") { t = String(t[..<colon]) }                // port
            while t.hasSuffix(".") { t.removeLast() }   // trailing root dot
            guard !t.isEmpty else { continue }
            if seen.insert(t).inserted { out.append(t) }
        }
        return out
    }

    func cidrs(from raw: String) -> [String] {
        var out = Set<String>()
        for host in Self.hostnames(from: raw) {
            for ip in resolve(host) { out.insert("\(ip)/32") }
        }
        return out.sorted()
    }

    static let system = DomainRouteResolver { host in
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return [] }
        defer { freeaddrinfo(first) }
        var seen = Set<String>()
        var ips: [String] = []
        var p: UnsafeMutablePointer<addrinfo>? = first
        while let ai = p {
            if ai.pointee.ai_family == AF_INET, let sa = ai.pointee.ai_addr {
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                let ok = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin -> Bool in
                    var addr = sin.pointee.sin_addr
                    return inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil
                }
                if ok {
                    let ip = String(cString: buf)
                    if seen.insert(ip).inserted { ips.append(ip) }
                }
            }
            p = ai.pointee.ai_next
        }
        return ips
    }
}
