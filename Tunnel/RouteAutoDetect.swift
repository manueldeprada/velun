import Foundation
import Darwin

enum RouteAutoDetect {
    /// Resolver type lets tests swap in a deterministic stub.
    typealias Resolver = (String) -> [String]

    static let systemResolver: Resolver = { host in
        var hints = addrinfo(ai_flags: 0, ai_family: AF_INET, ai_socktype: SOCK_STREAM,
                             ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil,
                             ai_addr: nil, ai_next: nil)
        var info: UnsafeMutablePointer<addrinfo>? = nil
        guard getaddrinfo(host, nil, &hints, &info) == 0, let head = info else { return [] }
        defer { freeaddrinfo(head) }
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        var out: [String] = []
        var ai: UnsafeMutablePointer<addrinfo>? = head
        while let cur = ai {
            if let sa = cur.pointee.ai_addr {
                sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    var addr = sin.pointee.sin_addr
                    inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN))
                }
                if let s = String(validatingUTF8: buf), !s.isEmpty { out.append(s) }
            }
            ai = cur.pointee.ai_next
        }
        return out
    }

    static func detect(for cfg: TunnelNetworkConfig,
                       resolver: Resolver = systemResolver) -> [String] {
        var dnsCidrs: [String] = []
        var resolvedCidrs: [String] = []

        let dnsIPs = cfg.dnsServers.filter { isValidIPv4($0) }
        let allDNSPrivate = !dnsIPs.isEmpty && dnsIPs.allSatisfy(isPrivate)

        for ip in dnsIPs {
            if !allDNSPrivate && isPrivate(ip) { continue }
            if let cidr = cidr16(of: ip) { dnsCidrs.append(cidr) }
        }

        for domain in cfg.searchDomains {
            for ip in resolver(domain) {
                if !allDNSPrivate && isPrivate(ip) { continue }
                if let cidr = cidr16(of: ip) { resolvedCidrs.append(cidr) }
            }
        }

        var seen = Set<String>()
        return (dnsCidrs + resolvedCidrs).filter { seen.insert($0).inserted }
    }

    static func cidr16(of ipv4: String) -> String? {
        let parts = ipv4.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4, parts.allSatisfy({ $0 >= 0 && $0 <= 255 }) else { return nil }
        return "\(parts[0]).\(parts[1]).0.0/16"
    }

    static func isValidIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".").compactMap { Int($0) }
        return parts.count == 4 && parts.allSatisfy { $0 >= 0 && $0 <= 255 }
    }

    /// True for RFC1918 + RFC6598 (CGNAT).
    static func isPrivate(_ ipv4: String) -> Bool {
        let parts = ipv4.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4 else { return false }
        if parts[0] == 10 { return true }
        if parts[0] == 172 && (16...31).contains(parts[1]) { return true }
        if parts[0] == 192 && parts[1] == 168 { return true }
        if parts[0] == 100 && (64...127).contains(parts[1]) { return true } // CGNAT
        return false
    }
}
