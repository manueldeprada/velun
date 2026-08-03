import Foundation

// MARK: – Server-address parsing

struct ServerAddress: Equatable {
    var host: String
    var port: Int?
    var group: String

    static func parse(_ raw: String) -> ServerAddress {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)

        // 1. Strip a leading URL scheme (`https://`, `anyconnect://`, …).
        if let r = s.range(of: "://") {
            s = String(s[r.upperBound...])
        }

        var group = ""
        if let slash = s.firstIndex(of: "/") {
            let firstSegment = s[s.index(after: slash)...]
                .prefix { $0 != "/" && $0 != "?" && $0 != "#" }
            group = String(firstSegment)
            s = String(s[..<slash])
        }

        // 3. IPv6 bracket literal: `[::1]` or `[::1]:443`.
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") {
            let inner = String(s[s.index(after: s.startIndex)..<close])
            let after = s[s.index(after: close)...]
            var port: Int? = nil
            if after.hasPrefix(":"), let p = Int(after.dropFirst()), (1...65535).contains(p) {
                port = p
            }
            return ServerAddress(host: inner, port: port, group: group)
        }

        if let colon = s.lastIndex(of: ":"), !s[..<colon].contains(":") {
            let head = String(s[..<colon])
            let tail = s[s.index(after: colon)...]
            if let p = Int(tail), (1...65535).contains(p) {
                return ServerAddress(host: head, port: p, group: group)
            }
        }

        return ServerAddress(host: s, port: nil, group: group)
    }
}
