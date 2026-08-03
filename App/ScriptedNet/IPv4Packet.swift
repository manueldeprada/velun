import Foundation

enum IPProtocol: UInt8 {
    case icmp = 1
    case tcp  = 6
    case udp  = 17
}

struct IPv4Header: Equatable {
    var version: UInt8           // always 4
    var ihl: UInt8               // header length in 32-bit words (5 = no options)
    var tos: UInt8
    var totalLength: UInt16      // entire IP packet length, header + payload
    var identification: UInt16
    var flagsAndFragOffset: UInt16
    var ttl: UInt8
    var proto: UInt8
    var headerChecksum: UInt16
    var sourceAddress: UInt32      // network byte order treated as host UInt32
    var destinationAddress: UInt32

    static let minLength = 20

    static func parse(_ data: Data) -> IPv4Header? {
        guard data.count >= minLength else { return nil }
        let b = [UInt8](data.prefix(minLength))
        let versionIHL = b[0]
        let version = versionIHL >> 4
        let ihl = versionIHL & 0x0f
        guard version == 4, ihl >= 5 else { return nil }
        let headerLen = Int(ihl) * 4
        guard data.count >= headerLen else { return nil }
        return IPv4Header(
            version: version,
            ihl: ihl,
            tos: b[1],
            totalLength: UInt16(b[2]) << 8 | UInt16(b[3]),
            identification: UInt16(b[4]) << 8 | UInt16(b[5]),
            flagsAndFragOffset: UInt16(b[6]) << 8 | UInt16(b[7]),
            ttl: b[8],
            proto: b[9],
            headerChecksum: UInt16(b[10]) << 8 | UInt16(b[11]),
            sourceAddress: UInt32(b[12]) << 24 | UInt32(b[13]) << 16 | UInt32(b[14]) << 8 | UInt32(b[15]),
            destinationAddress: UInt32(b[16]) << 24 | UInt32(b[17]) << 16 | UInt32(b[18]) << 8 | UInt32(b[19])
        )
    }

    var headerLength: Int { Int(ihl) * 4 }
}

struct TCPFlags: OptionSet, Equatable {
    let rawValue: UInt8
    static let fin = TCPFlags(rawValue: 1 << 0)
    static let syn = TCPFlags(rawValue: 1 << 1)
    static let rst = TCPFlags(rawValue: 1 << 2)
    static let psh = TCPFlags(rawValue: 1 << 3)
    static let ack = TCPFlags(rawValue: 1 << 4)
    static let urg = TCPFlags(rawValue: 1 << 5)
}

struct TCPSegment: Equatable {
    var sourcePort: UInt16
    var destinationPort: UInt16
    var sequenceNumber: UInt32
    var ackNumber: UInt32
    var dataOffset: UInt8        // header length in 32-bit words (5 = no options)
    var flags: TCPFlags
    var window: UInt16
    var checksum: UInt16
    var urgentPointer: UInt16
    var payload: Data
    /// MSS option, if present in a SYN. We honor it for our send path.
    var mss: UInt16?

    static let minLength = 20

    static func parse(_ data: Data) -> TCPSegment? {
        guard data.count >= minLength else { return nil }
        let b = [UInt8](data)
        let dataOffset = b[12] >> 4
        let headerLen = Int(dataOffset) * 4
        guard data.count >= headerLen, headerLen >= minLength else { return nil }

        var mss: UInt16? = nil
        var i = minLength
        while i < headerLen {
            let kind = b[i]
            if kind == 0 { break }
            if kind == 1 { i += 1; continue }
            guard i + 1 < headerLen else { return nil }
            let len = Int(b[i + 1])
            guard len >= 2, i + len <= headerLen else { return nil }
            if kind == 2, len == 4, i + 3 < headerLen {
                mss = UInt16(b[i + 2]) << 8 | UInt16(b[i + 3])
            }
            i += len
        }

        return TCPSegment(
            sourcePort: UInt16(b[0]) << 8 | UInt16(b[1]),
            destinationPort: UInt16(b[2]) << 8 | UInt16(b[3]),
            sequenceNumber: UInt32(b[4]) << 24 | UInt32(b[5]) << 16 | UInt32(b[6]) << 8 | UInt32(b[7]),
            ackNumber: UInt32(b[8]) << 24 | UInt32(b[9]) << 16 | UInt32(b[10]) << 8 | UInt32(b[11]),
            dataOffset: dataOffset,
            flags: TCPFlags(rawValue: b[13]),
            window: UInt16(b[14]) << 8 | UInt16(b[15]),
            checksum: UInt16(b[16]) << 8 | UInt16(b[17]),
            urgentPointer: UInt16(b[18]) << 8 | UInt16(b[19]),
            payload: Data(b[headerLen...]),
            mss: mss
        )
    }

    var headerLength: Int { Int(dataOffset) * 4 }
}

struct PacketBuilder {
    static func ipv4TCP(srcIP: UInt32, dstIP: UInt32,
                        srcPort: UInt16, dstPort: UInt16,
                        seq: UInt32, ack: UInt32,
                        flags: TCPFlags, window: UInt16,
                        payload: Data,
                        mss: UInt16? = nil,
                        ipID: UInt16 = 0) -> Data {
        // TCP header (with optional MSS option, 4 bytes — pads naturally).
        var tcp = [UInt8]()
        tcp.append(UInt8(srcPort >> 8)); tcp.append(UInt8(srcPort & 0xff))
        tcp.append(UInt8(dstPort >> 8)); tcp.append(UInt8(dstPort & 0xff))
        tcp.append(UInt8((seq >> 24) & 0xff)); tcp.append(UInt8((seq >> 16) & 0xff))
        tcp.append(UInt8((seq >>  8) & 0xff)); tcp.append(UInt8(seq        & 0xff))
        tcp.append(UInt8((ack >> 24) & 0xff)); tcp.append(UInt8((ack >> 16) & 0xff))
        tcp.append(UInt8((ack >>  8) & 0xff)); tcp.append(UInt8(ack        & 0xff))

        let includeMSS = flags.contains(.syn) && mss != nil
        let dataOffset: UInt8 = includeMSS ? 6 : 5
        tcp.append(dataOffset << 4)
        tcp.append(flags.rawValue)
        tcp.append(UInt8(window >> 8)); tcp.append(UInt8(window & 0xff))
        tcp.append(0); tcp.append(0)               // checksum placeholder
        tcp.append(0); tcp.append(0)               // urgent pointer

        if includeMSS, let mss {
            tcp.append(2); tcp.append(4)
            tcp.append(UInt8(mss >> 8)); tcp.append(UInt8(mss & 0xff))
        }

        var tcpData = Data(tcp) + payload

        let tcpLen = UInt16(tcpData.count)
        let cs = tcpChecksum(srcIP: srcIP, dstIP: dstIP, segment: tcpData, length: tcpLen)
        tcpData[16] = UInt8(cs >> 8)
        tcpData[17] = UInt8(cs & 0xff)

        // IPv4 header.
        let totalLen = UInt16(20 + tcpData.count)
        var ip = [UInt8]()
        ip.append(0x45)                            // version 4, IHL 5
        ip.append(0x00)                            // TOS
        ip.append(UInt8(totalLen >> 8)); ip.append(UInt8(totalLen & 0xff))
        ip.append(UInt8(ipID >> 8)); ip.append(UInt8(ipID & 0xff))
        ip.append(0x40); ip.append(0x00)           // DF set, no fragment
        ip.append(64)                              // TTL
        ip.append(IPProtocol.tcp.rawValue)
        ip.append(0); ip.append(0)                 // checksum placeholder
        ip.append(UInt8((srcIP >> 24) & 0xff)); ip.append(UInt8((srcIP >> 16) & 0xff))
        ip.append(UInt8((srcIP >>  8) & 0xff)); ip.append(UInt8(srcIP        & 0xff))
        ip.append(UInt8((dstIP >> 24) & 0xff)); ip.append(UInt8((dstIP >> 16) & 0xff))
        ip.append(UInt8((dstIP >>  8) & 0xff)); ip.append(UInt8(dstIP        & 0xff))

        let ipCS = ipChecksum(Data(ip))
        ip[10] = UInt8(ipCS >> 8)
        ip[11] = UInt8(ipCS & 0xff)

        return Data(ip) + tcpData
    }
}

// Standard 16-bit one's-complement Internet checksum over `data`.
func ipChecksum(_ data: Data) -> UInt16 {
    var sum: UInt32 = 0
    var i = data.startIndex
    while i + 1 < data.endIndex {
        sum &+= UInt32(data[i]) << 8 | UInt32(data[i + 1])
        i += 2
    }
    if i < data.endIndex {                          // odd byte
        sum &+= UInt32(data[i]) << 8
    }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
    return ~UInt16(sum & 0xffff)
}

func tcpChecksum(srcIP: UInt32, dstIP: UInt32, segment: Data, length: UInt16) -> UInt16 {
    var pseudo = Data()
    pseudo.append(UInt8((srcIP >> 24) & 0xff)); pseudo.append(UInt8((srcIP >> 16) & 0xff))
    pseudo.append(UInt8((srcIP >>  8) & 0xff)); pseudo.append(UInt8(srcIP        & 0xff))
    pseudo.append(UInt8((dstIP >> 24) & 0xff)); pseudo.append(UInt8((dstIP >> 16) & 0xff))
    pseudo.append(UInt8((dstIP >>  8) & 0xff)); pseudo.append(UInt8(dstIP        & 0xff))
    pseudo.append(0)
    pseudo.append(IPProtocol.tcp.rawValue)
    pseudo.append(UInt8(length >> 8)); pseudo.append(UInt8(length & 0xff))
    return ipChecksum(pseudo + segment)
}

enum IPv4 {
    static func toUInt32(_ s: String) -> UInt32? {
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return nil }
        var out: UInt32 = 0
        for p in parts {
            guard let n = UInt32(p), n <= 255 else { return nil }
            out = (out << 8) | n
        }
        return out
    }

    static func toString(_ ip: UInt32) -> String {
        "\((ip >> 24) & 0xff).\((ip >> 16) & 0xff).\((ip >> 8) & 0xff).\(ip & 0xff)"
    }
}
