import Foundation

enum PacketNAT {

    @discardableResult
    static func rewriteSource(_ packet: inout Data, to newIP: UInt32) -> Bool {
        rewrite(&packet, isSource: true, to: newIP)
    }

    /// Rewrite the IPv4 **destination** address. See `rewriteSource`.
    @discardableResult
    static func rewriteDestination(_ packet: inout Data, to newIP: UInt32) -> Bool {
        rewrite(&packet, isSource: false, to: newIP)
    }

    private static func rewrite(_ packet: inout Data, isSource: Bool, to newIP: UInt32) -> Bool {
        var b = [UInt8](packet)
        guard rewriteBytes(&b, isSource: isSource, to: newIP) else { return false }
        packet = Data(b)
        return true
    }

    private static func rewriteBytes(_ b: inout [UInt8], isSource: Bool, to newIP: UInt32) -> Bool {
        guard b.count >= 20 else { return false }
        guard b[0] >> 4 == 4 else { return false }            // IPv4 only
        let ihl = Int(b[0] & 0x0f)
        guard ihl >= 5 else { return false }
        let headerLen = ihl * 4
        guard b.count >= headerLen else { return false }

        let addrOff = isSource ? 12 : 16
        let oldHi = UInt16(b[addrOff])     << 8 | UInt16(b[addrOff + 1])
        let oldLo = UInt16(b[addrOff + 2]) << 8 | UInt16(b[addrOff + 3])
        let newHi = UInt16((newIP >> 16) & 0xffff)
        let newLo = UInt16(newIP & 0xffff)
        if oldHi == newHi && oldLo == newLo { return true }   // unchanged

        let changes: [(UInt16, UInt16)] = [(oldHi, newHi), (oldLo, newLo)]

        // IP header checksum (bytes 10..11).
        patchChecksum(&b, at: 10, changes: changes)

        // Write the new address.
        b[addrOff]     = UInt8((newIP >> 24) & 0xff)
        b[addrOff + 1] = UInt8((newIP >> 16) & 0xff)
        b[addrOff + 2] = UInt8((newIP >>  8) & 0xff)
        b[addrOff + 3] = UInt8( newIP        & 0xff)

        // Transport checksum lives only in the first fragment.
        let fragOffset = (UInt16(b[6]) << 8 | UInt16(b[7])) & 0x1fff
        guard fragOffset == 0 else { return true }

        switch b[9] {                                          // IP protocol
        case 6:                                                // TCP
            let off = headerLen + 16
            guard b.count >= off + 2 else { return true }
            patchChecksum(&b, at: off, changes: changes)
        case 17:                                               // UDP
            let off = headerLen + 6
            guard b.count >= off + 2 else { return true }
            if !(b[off] == 0 && b[off + 1] == 0) {
                patchChecksum(&b, at: off, changes: changes)
                if b[off] == 0 && b[off + 1] == 0 { b[off] = 0xff; b[off + 1] = 0xff }
            }
        default:
            break                                              // ICMP / other: IP checksum only
        }
        return true
    }

    // MARK: – IPv6

    @discardableResult
    static func rewriteSource6(_ packet: inout Data, to newIP: IPv6Addr) -> Bool {
        rewrite6(&packet, isSource: true, to: newIP)
    }

    /// Rewrite the IPv6 **destination** address. See `rewriteSource6`.
    @discardableResult
    static func rewriteDestination6(_ packet: inout Data, to newIP: IPv6Addr) -> Bool {
        rewrite6(&packet, isSource: false, to: newIP)
    }

    private static func rewrite6(_ packet: inout Data, isSource: Bool, to newIP: IPv6Addr) -> Bool {
        var b = [UInt8](packet)
        guard rewriteBytes6(&b, isSource: isSource, to: newIP) else { return false }
        packet = Data(b)
        return true
    }

    private static func rewriteBytes6(_ b: inout [UInt8], isSource: Bool, to newIP: IPv6Addr) -> Bool {
        guard b.count >= IPv6Header.length else { return false }
        guard b[0] >> 4 == 6 else { return false }

        let addrOff = isSource ? 8 : 24
        guard let old = IPv6Addr(bytes: b, at: addrOff) else { return false }
        if old == newIP { return true }

        let oldWords = old.words
        let newWords = newIP.words
        let changes: [(UInt16, UInt16)] = (0..<8).map { (oldWords[$0], newWords[$0]) }

        let newBytes = newIP.bytes
        for i in 0..<16 { b[addrOff + i] = newBytes[i] }

        guard let (proto, off) = IPv6ExtensionHeader.transportHeader(b) else { return true }
        let cksumOff: Int
        switch proto {
        case IPv6ExtensionHeader.tcp:    cksumOff = off + 16
        case IPv6ExtensionHeader.udp:    cksumOff = off + 6
        case IPv6ExtensionHeader.icmpv6: cksumOff = off + 2
        default: return true
        }
        guard b.count >= cksumOff + 2 else { return true }
        patchChecksum(&b, at: cksumOff, changes: changes)
        if proto == IPv6ExtensionHeader.udp, b[cksumOff] == 0, b[cksumOff + 1] == 0 {
            b[cksumOff] = 0xff; b[cksumOff + 1] = 0xff
        }
        return true
    }

    private static func patchChecksum(_ b: inout [UInt8], at off: Int,
                                      changes: [(old: UInt16, new: UInt16)]) {
        let current = UInt16(b[off]) << 8 | UInt16(b[off + 1])
        let updated = incrementalChecksum(current: current, changes: changes)
        b[off]     = UInt8(updated >> 8)
        b[off + 1] = UInt8(updated & 0xff)
    }

    static func incrementalChecksum(current: UInt16,
                                    changes: [(old: UInt16, new: UInt16)]) -> UInt16 {
        var sum = UInt32(~current & 0xffff)
        for (old, new) in changes {
            sum += UInt32(~old & 0xffff)
            sum += UInt32(new)
        }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return ~UInt16(sum & 0xffff)
    }
}
