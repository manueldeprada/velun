import Foundation
import OSLog

private let logger = Logger(subsystem: "com.manueldeprada.velun", category: "SystemImport")

// MARK: – Best-effort recovery of connection details already on this Mac

enum SystemProfileImporter {
    private static let profileDirs = [
        "/opt/cisco/secureclient/vpn/profile",
        "/opt/cisco/anyconnect/profile",
    ]

    struct Candidate: Equatable {
        var name:  String   // admin-chosen display name (HostName); falls back to host
        var host:  String   // HostAddress with any port/path/scheme stripped off
        var port:  Int      // port parsed out of the HostAddress, else 443
        var group: String   // UserGroup, else the HostAddress URL-path hint
    }

    static func scan() -> [Candidate] {
        let fm = FileManager.default
        var out: [Candidate] = []
        var seen = Set<String>()
        for dir in profileDirs {
            guard let names = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for name in names.sorted() where name.lowercased().hasSuffix(".xml") {
                let path = (dir as NSString).appendingPathComponent(name)
                guard let xml = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
                for c in HostEntryParser.parse(xml) {
                    guard !c.host.isEmpty else { continue }
                    guard seen.insert(dedupKey(host: c.host, group: c.group)).inserted else { continue }
                    out.append(c)
                }
            }
        }
        logger.info("system VPN profile scan found \(out.count, privacy: .public) candidate(s)")
        return out
    }

    static func profiles(from candidates: [Candidate],
                         excluding existing: [VPNProfile]) -> [VPNProfile] {
        let taken = Set(existing.compactMap { p -> String? in
            guard p.provider == .anyConnect, let oc = p.config.sslVPN else { return nil }
            return dedupKey(host: oc.host, group: oc.group)
        })
        return candidates.compactMap { c in
            guard !taken.contains(dedupKey(host: c.host, group: c.group)) else { return nil }
            var oc = SSLVPNFamilyConfig()
            oc.host  = c.host
            oc.port  = c.port
            oc.group = c.group
            var p = VPNProfile()
            p.name     = c.name.isEmpty ? c.host : c.name
            p.provider = .anyConnect
            p.config   = .sslVPN(oc)
            return p
        }
    }

    static func discoverProfiles(excluding existing: [VPNProfile]) -> [VPNProfile] {
        profiles(from: scan(), excluding: existing)
    }

    private static func dedupKey(host: String, group: String) -> String {
        "\(host.lowercased())|\(group.lowercased())"
    }
}

// MARK: – <HostEntry> parser

private final class HostEntryParser: NSObject, XMLParserDelegate {
    static func parse(_ xml: String) -> [SystemProfileImporter.Candidate] {
        guard let data = xml.data(using: .utf8) else { return [] }
        let p = HostEntryParser()
        let parser = XMLParser(data: data)
        parser.delegate = p
        parser.parse()
        return p.candidates
    }

    private var candidates: [SystemProfileImporter.Candidate] = []
    private var inEntry = false
    private var current = ""
    private var hostName = "", hostAddress = "", userGroup = ""

    func parser(_ parser: XMLParser, didStartElement name: String,
                namespaceURI: String?, qualifiedName: String?,
                attributes: [String: String] = [:]) {
        if localName(name) == "HostEntry" {
            inEntry = true
            hostName = ""; hostAddress = ""; userGroup = ""
        }
        current = ""
    }

    func parser(_ parser: XMLParser, foundCharacters s: String) { current += s }

    func parser(_ parser: XMLParser, didEndElement name: String,
                namespaceURI: String?, qualifiedName: String?) {
        let text = current.trimmingCharacters(in: .whitespacesAndNewlines)
        switch localName(name) {
        case "HostName"    where inEntry: hostName    = text
        case "HostAddress" where inEntry: hostAddress = text
        case "UserGroup"   where inEntry: userGroup   = text
        case "HostEntry":
            inEntry = false
            let parsed = ServerAddress.parse(hostAddress)
            if !parsed.host.isEmpty {
                let group = userGroup.isEmpty ? parsed.group : userGroup
                candidates.append(.init(name:  hostName.isEmpty ? parsed.host : hostName,
                                        host:  parsed.host,
                                        port:  parsed.port ?? 443,
                                        group: group))
            }
        default:
            break
        }
        current = ""
    }

    private func localName(_ name: String) -> String {
        name.split(separator: ":").last.map(String.init) ?? name
    }
}
