import Foundation

enum RouteFieldMerge {

    struct Prefix: Hashable {
        let network: UInt32   // host-order, masked to `len` bits
        let len: Int          // 0...32

        init(network: UInt32, len: Int) {
            self.len = len
            self.network = len == 0 ? 0 : network & (~UInt32(0) << (32 - len))
        }

        func covers(_ other: Prefix) -> Bool {
            guard len <= other.len else { return false }
            if len == 0 { return true }
            let mask = ~UInt32(0) << (32 - len)
            return (other.network & mask) == network
        }

        var string: String { "\(IPv4.toString(network))/\(len)" }

        static func parse(_ s: String) -> Prefix? {
            let parts = s.split(separator: "/", maxSplits: 1).map(String.init)
            guard let net = IPv4.toUInt32(parts[0].trimmingCharacters(in: .whitespaces)) else { return nil }
            if parts.count == 2 {
                guard let len = Int(parts[1].trimmingCharacters(in: .whitespaces)),
                      (0...32).contains(len) else { return nil }
                return Prefix(network: net, len: len)
            }
            return Prefix(network: net, len: 32)
        }
    }

    static func merge(field: String, learned: [String]) -> String? {
        let tokens = field
            .components(separatedBy: CharacterSet(charactersIn: " ,\n"))
            .filter { !$0.isEmpty }
        let existing: [(raw: String, prefix: Prefix?)] = tokens.map { ($0, Prefix.parse($0)) }
        let existingPrefixes = existing.compactMap(\.prefix)

        // Learned entries not already covered by the field.
        let fresh = learned.compactMap(Prefix.parse)
            .filter { l in !existingPrefixes.contains { $0.covers(l) } }
        guard !fresh.isEmpty else { return nil }

        let existing32s = existingPrefixes.filter { $0.len == 32 }
        let fresh32Buckets = Set(fresh.filter { $0.len == 32 }.map { $0.network >> 8 })
        var bucketCounts: [UInt32: Int] = [:]
        for p in Set(existing32s + fresh.filter { $0.len == 32 }) {
            bucketCounts[p.network >> 8, default: 0] += 1
        }
        let synthesized = bucketCounts
            .filter { $0.value >= 2 && fresh32Buckets.contains($0.key) }
            .map { Prefix(network: $0.key << 8, len: 24) }

        var additions = synthesized
        additions += fresh.filter { f in !synthesized.contains { $0.covers(f) } }
        additions = Array(Set(additions)).filter { a in
            !additions.contains { $0 != a && $0.covers(a) }
        }

        let kept = existing.filter { tok in
            guard let p = tok.prefix else { return true }
            return !additions.contains { $0.covers(p) }
        }.map(\.raw)

        return (kept + additions.map(\.string).sorted()).joined(separator: " ")
    }
}
