import Foundation
import Darwin

// MARK: – Address

struct IPv6Addr: Hashable, Comparable {
    var hi: UInt64
    var lo: UInt64

    static let zero = IPv6Addr(hi: 0, lo: 0)

    init(hi: UInt64, lo: UInt64) { self.hi = hi; self.lo = lo }

    init?(_ string: String) {
        let trimmed = string.trimmingCharacters(in: .whitespaces)
        let bare = trimmed.split(separator: "%", maxSplits: 1).first.map(String.init) ?? trimmed
        guard !bare.isEmpty else { return nil }
        var addr = in6_addr()
        guard bare.withCString({ inet_pton(AF_INET6, $0, &addr) }) == 1 else { return nil }
        var bytes = [UInt8](repeating: 0, count: 16)
        withUnsafeBytes(of: &addr) { raw in
            for i in 0..<16 { bytes[i] = raw[i] }
        }
        self.init(bytes: bytes, at: 0)!
    }

    /// Big-endian bytes at `offset`. Returns nil if fewer than 16 remain.
    init?(bytes b: [UInt8], at offset: Int) {
        guard offset >= 0, b.count >= offset + 16 else { return nil }
        var h: UInt64 = 0
        var l: UInt64 = 0
        for i in 0..<8 { h = (h << 8) | UInt64(b[offset + i]) }
        for i in 8..<16 { l = (l << 8) | UInt64(b[offset + i]) }
        self.init(hi: h, lo: l)
    }

    var bytes: [UInt8] {
        var out = [UInt8](repeating: 0, count: 16)
        for i in 0..<8 { out[i] = UInt8((hi >> (56 - 8 * UInt64(i))) & 0xff) }
        for i in 0..<8 { out[8 + i] = UInt8((lo >> (56 - 8 * UInt64(i))) & 0xff) }
        return out
    }

    /// RFC 5952 canonical text, via `inet_ntop`.
    var string: String {
        var addr = in6_addr()
        let b = bytes
        withUnsafeMutableBytes(of: &addr) { raw in
            for i in 0..<16 { raw[i] = b[i] }
        }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &addr, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil else { return "::" }
        return String(cString: buf)
    }

    var words: [UInt16] {
        var out: [UInt16] = []
        out.reserveCapacity(8)
        for i in 0..<4 { out.append(UInt16((hi >> (48 - 16 * UInt64(i))) & 0xffff)) }
        for i in 0..<4 { out.append(UInt16((lo >> (48 - 16 * UInt64(i))) & 0xffff)) }
        return out
    }

    var isZero: Bool { hi == 0 && lo == 0 }

    var isLinkLocal: Bool { (hi >> 54) == 0x3fa }   // top 10 bits == 1111111010

    /// Multicast `ff00::/8` — inbound noise the 1:1 NAT can't map.
    var isMulticast: Bool { (hi >> 56) == 0xff }

    static func < (a: IPv6Addr, b: IPv6Addr) -> Bool {
        a.hi == b.hi ? a.lo < b.lo : a.hi < b.hi
    }
}

// MARK: – Prefix + table

struct RoutePrefix6: Equatable {
    let network: IPv6Addr   // already masked to `prefix` bits
    let prefix: Int         // 0...128

    init(network: IPv6Addr, prefix: Int) {
        let p = max(0, min(128, prefix))
        self.prefix = p
        self.network = RoutePrefix6.mask(network, p)
    }

    static func mask(_ a: IPv6Addr, _ prefix: Int) -> IPv6Addr {
        if prefix >= 128 { return a }
        if prefix <= 0 { return .zero }
        if prefix >= 64 {
            let bits = prefix - 64
            let m: UInt64 = bits == 0 ? 0 : ~UInt64(0) << (64 - bits)
            return IPv6Addr(hi: a.hi, lo: a.lo & m)
        }
        return IPv6Addr(hi: a.hi & (~UInt64(0) << (64 - prefix)), lo: 0)
    }

    func contains(_ addr: IPv6Addr) -> Bool {
        RoutePrefix6.mask(addr, prefix) == network
    }

    /// Parse "2001:db8::/32", or a bare address (treated as /128).
    static func parse(_ cidr: String) -> RoutePrefix6? {
        let parts = cidr.split(separator: "/", maxSplits: 1).map(String.init)
        guard let net = IPv6Addr(parts[0]) else { return nil }
        guard parts.count == 2 else { return RoutePrefix6(network: net, prefix: 128) }
        guard let p = Int(parts[1].trimmingCharacters(in: .whitespaces)), p >= 0, p <= 128 else { return nil }
        return RoutePrefix6(network: net, prefix: p)
    }
}

struct RoutingTable6 {
    private struct Entry { let prefix: RoutePrefix6; let id: String }
    private let entries: [Entry]

    init(_ upstreams: [(id: String, prefixes: [RoutePrefix6])]) {
        var es: [(Entry, Int)] = []
        var order = 0
        for (id, prefixes) in upstreams {
            for p in prefixes { es.append((Entry(prefix: p, id: id), order)) }
            order += 1
        }
        entries = es.sorted {
            $0.0.prefix.prefix != $1.0.prefix.prefix
                ? $0.0.prefix.prefix > $1.0.prefix.prefix
                : $0.1 < $1.1
        }.map { $0.0 }
    }

    func upstreamID(forDest dest: IPv6Addr) -> String? {
        for e in entries where e.prefix.contains(dest) { return e.id }
        return nil
    }

    var isEmpty: Bool { entries.isEmpty }
}

// MARK: – Header

struct IPv6Header: Equatable {
    var payloadLength: UInt16
    var nextHeader: UInt8
    var hopLimit: UInt8
    var source: IPv6Addr
    var destination: IPv6Addr

    static let length = 40

    static func parse(_ data: Data) -> IPv6Header? {
        guard data.count >= length else { return nil }
        let b = [UInt8](data.prefix(length))
        guard b[0] >> 4 == 6 else { return nil }
        guard let src = IPv6Addr(bytes: b, at: 8), let dst = IPv6Addr(bytes: b, at: 24) else { return nil }
        return IPv6Header(payloadLength: UInt16(b[4]) << 8 | UInt16(b[5]),
                          nextHeader: b[6],
                          hopLimit: b[7],
                          source: src,
                          destination: dst)
    }
}

enum IPv6ExtensionHeader {
    static let hopByHop: UInt8   = 0
    static let routing: UInt8    = 43
    static let fragment: UInt8   = 44
    static let esp: UInt8        = 50
    static let auth: UInt8       = 51
    static let noNext: UInt8     = 59
    static let destOpts: UInt8   = 60
    static let mobility: UInt8   = 135

    static let tcp: UInt8    = 6
    static let udp: UInt8    = 17
    static let icmpv6: UInt8 = 58

    static func transportHeader(_ b: [UInt8]) -> (proto: UInt8, offset: Int)? {
        guard b.count >= IPv6Header.length else { return nil }
        var next = b[6]
        var off = IPv6Header.length
        for _ in 0..<8 {
            switch next {
            case tcp, udp, icmpv6:
                return (next, off)
            case hopByHop, routing, destOpts, mobility:
                guard b.count >= off + 2 else { return nil }
                let len = (Int(b[off + 1]) + 1) * 8
                next = b[off]
                off += len
            case auth:
                // RFC 4302: length is in 4-byte units, minus 2.
                guard b.count >= off + 2 else { return nil }
                let len = (Int(b[off + 1]) + 2) * 4
                next = b[off]
                off += len
            case fragment:
                guard b.count >= off + 8 else { return nil }
                let fragOffset = (UInt16(b[off + 2]) << 8 | UInt16(b[off + 3])) >> 3
                guard fragOffset == 0 else { return nil }
                next = b[off]
                off += 8
            default:
                // esp / noNext / anything unrecognized: stop, don't guess.
                return nil
            }
            guard off <= b.count else { return nil }
        }
        return nil
    }
}
