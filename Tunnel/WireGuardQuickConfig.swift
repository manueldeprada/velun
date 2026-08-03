import Foundation
#if canImport(WireGuardKit)
import WireGuardKit

enum WireGuardQuickError: LocalizedError {
    case missingInterface
    case invalidPrivateKey
    case missingPublicKey(peerIndex: Int)
    case invalidValue(field: String, value: String)

    var errorDescription: String? {
        switch self {
        case .missingInterface:                return "Config has no [Interface] section"
        case .invalidPrivateKey:               return "[Interface] PrivateKey is missing or invalid"
        case .missingPublicKey(let i):         return "[Peer #\(i + 1)] is missing a PublicKey"
        case .invalidValue(let f, let v):      return "Invalid value for \(f): \(v)"
        }
    }
}

enum WireGuardQuickConfig {
    static func parse(_ text: String, name: String? = nil) throws -> TunnelConfiguration {
        var section: String? = nil
        var iface: [String: String] = [:]
        var peers: [[String: String]] = []
        var currentPeer: [String: String] = [:]

        for raw in text.components(separatedBy: .newlines) {
            let line = raw.split(separator: "#", maxSplits: 1).first.map(String.init)?
                .trimmingCharacters(in: .whitespaces) ?? ""
            if line.isEmpty { continue }

            if line.hasPrefix("[") && line.hasSuffix("]") {
                if section?.lowercased() == "peer" {
                    peers.append(currentPeer)
                    currentPeer = [:]
                }
                section = String(line.dropFirst().dropLast())
                continue
            }

            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let val = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)

            switch section?.lowercased() {
            case "interface": iface[key] = val
            case "peer":      currentPeer[key] = val
            default:          continue
            }
        }
        if section?.lowercased() == "peer" {
            peers.append(currentPeer)
        }

        guard !iface.isEmpty else { throw WireGuardQuickError.missingInterface }

        // Interface
        guard let pkB64 = iface["privatekey"],
              let priv = PrivateKey(base64Key: pkB64) else {
            throw WireGuardQuickError.invalidPrivateKey
        }
        var interface = InterfaceConfiguration(privateKey: priv)
        interface.addresses = splitList(iface["address"]).compactMap { IPAddressRange(from: $0) }
        var dnsServers:  [DNSServer] = []
        var dnsSearch:   [String]    = []
        for entry in splitList(iface["dns"]) {
            if let server = DNSServer(from: entry) {
                dnsServers.append(server)
            } else {
                dnsSearch.append(entry)
            }
        }
        interface.dns       = dnsServers
        interface.dnsSearch = dnsSearch
        if let mtuStr = iface["mtu"] {
            guard let mtu = UInt16(mtuStr) else {
                throw WireGuardQuickError.invalidValue(field: "MTU", value: mtuStr)
            }
            interface.mtu = mtu
        }
        if let portStr = iface["listenport"] {
            guard let port = UInt16(portStr) else {
                throw WireGuardQuickError.invalidValue(field: "ListenPort", value: portStr)
            }
            interface.listenPort = port
        }

        // Peers
        var parsedPeers: [PeerConfiguration] = []
        for (i, peerDict) in peers.enumerated() {
            guard let pubB64 = peerDict["publickey"],
                  let pub = PublicKey(base64Key: pubB64) else {
                throw WireGuardQuickError.missingPublicKey(peerIndex: i)
            }
            var p = PeerConfiguration(publicKey: pub)
            if let psk = peerDict["presharedkey"], let key = PreSharedKey(base64Key: psk) {
                p.preSharedKey = key
            }
            p.allowedIPs = splitList(peerDict["allowedips"]).compactMap { IPAddressRange(from: $0) }
            if let ep = peerDict["endpoint"], let endpoint = Endpoint(from: ep) {
                p.endpoint = endpoint
            }
            if let kaStr = peerDict["persistentkeepalive"], let ka = UInt16(kaStr) {
                p.persistentKeepAlive = ka
            }
            parsedPeers.append(p)
        }

        return TunnelConfiguration(name: name, interface: interface, peers: parsedPeers)
    }

    private static func splitList(_ s: String?) -> [String] {
        guard let s, !s.isEmpty else { return [] }
        return s.components(separatedBy: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }
}
#endif
