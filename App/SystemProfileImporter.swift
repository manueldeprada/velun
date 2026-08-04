import Foundation
import OSLog

private let logger = Logger(subsystem: "com.manueldeprada.velun", category: "SystemImport")

// MARK: – Best-effort recovery of connection details already on this Mac

enum SystemProfileImporter {
    private static let profileDirs = [
        "/opt/cisco/secureclient/vpn/profile",
        "/opt/cisco/anyconnect/profile",
    ]

    private static var preferenceFiles: [String] {
        let home = NSHomeDirectory()
        return [
            "\(home)/.anyconnect",
            "\(home)/.cisco/secureclient/vpn/preferences.xml",
            "\(home)/.cisco/anyconnect/preferences.xml",
            "/opt/cisco/secureclient/vpn/.anyconnect_global",
            "/opt/cisco/anyconnect/.anyconnect_global",
        ]
    }

    private static let clientMarkers = [
        "/opt/cisco/secureclient",
        "/opt/cisco/anyconnect",
        "/Applications/Cisco/Cisco Secure Client.app",
        "/Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app",
    ]

    struct Candidate: Equatable {
        var name:  String   // admin-chosen display name (HostName); falls back to host
        var host:  String   // HostAddress with any port/path/scheme stripped off
        var port:  Int      // port parsed out of the HostAddress, else 443
        var group: String   // UserGroup, else the HostAddress URL-path hint
        var username: String = ""   // only the preference files carry one
    }

    /// What happened at one path the scan looked at.
    struct PathOutcome: Equatable {
        enum Kind: Equatable {
            case notPresent
            /// POSIX permissions (`EACCES`): readable only by an administrator.
            case deniedByFilePermissions
            /// Privacy policy (`EPERM`): what Full Disk Access grants.
            case deniedByPrivacy
            /// Other read failure, carrying the errno.
            case unreadable(Int32)
            /// Readable, but nothing usable in it.
            case nothingUsable
            case found(Int)
        }
        var path: String
        var kind: Kind

        var describedOutcome: String {
            switch kind {
            case .notPresent:               return "not present"
            case .deniedByFilePermissions:  return "permission denied (administrator only)"
            case .deniedByPrivacy:          return "blocked by privacy settings"
            case .unreadable(let e):        return "unreadable (\(String(cString: strerror(e))))"
            case .nothingUsable:            return "readable, no connection in it"
            case .found(let n):             return "found \(n)"
            }
        }
    }

    struct ScanReport {
        var candidates: [Candidate] = []
        var outcomes: [PathOutcome] = []
        /// A supported client is installed, so an empty result is surprising.
        var clientInstalled = false
        /// The user cancelled the administrator prompt (elevated scan only).
        var adminCancelled = false

        var blockedByFilePermissions: Bool {
            outcomes.contains { $0.kind == .deniedByFilePermissions }
        }
        /// Blocked by privacy policy, which Full Disk Access does fix.
        var blockedByPrivacy: Bool {
            outcomes.contains { $0.kind == .deniedByPrivacy }
        }

        /// One line per path looked at, for the alert's detail text and the log.
        var detail: String {
            outcomes.map { "\($0.path): \($0.describedOutcome)" }
                    .joined(separator: "\n")
        }
    }

    // MARK: – Scanning

    static func scan() -> ScanReport {
        var report = ScanReport()
        var seen = Set<String>()
        report.clientInstalled = clientMarkers.contains { FileManager.default.fileExists(atPath: $0) }

        for dir in profileDirs {
            let (found, outcome) = scanProfileDir(dir)
            report.outcomes.append(outcome)
            for c in found where seen.insert(dedupKey(host: c.host, group: c.group)).inserted {
                report.candidates.append(c)
            }
        }
        for path in preferenceFiles {
            let (found, outcome) = scanPreferenceFile(path)
            report.outcomes.append(outcome)
            for c in found {
                let key = dedupKey(host: c.host, group: c.group)
                if seen.insert(key).inserted {
                    report.candidates.append(c)
                } else if !c.username.isEmpty,
                          let i = report.candidates.firstIndex(where: {
                              dedupKey(host: $0.host, group: $0.group) == key && $0.username.isEmpty
                          }) {
                    report.candidates[i].username = c.username
                }
            }
        }

        logger.info("""
            scan: \(report.candidates.count, privacy: .public) candidate(s), \
            clientInstalled=\(report.clientInstalled, privacy: .public)
            \(report.detail, privacy: .public)
            """)
        return report
    }

    static func scanAsAdministrator() -> ScanReport {
        let fm = FileManager.default
        let staging = fm.temporaryDirectory
            .appendingPathComponent("velun-sysimport-\(UUID().uuidString)", isDirectory: true)
        do {
            try fm.createDirectory(at: staging, withIntermediateDirectories: true,
                                   attributes: [.posixPermissions: 0o700])
        } catch {
            logger.error("staging dir failed: \(error.localizedDescription, privacy: .public)")
            return scan()
        }
        defer { try? fm.removeItem(at: staging) }

        let copies = profileDirs.map { "/bin/cp -f \(shq($0))/*.xml \(shq(staging.path)) 2>/dev/null" }
        let script = (copies + ["/usr/sbin/chown -R \(getuid()) \(shq(staging.path))"])
            .joined(separator: "; ")

        var report = ScanReport()
        report.clientInstalled = clientMarkers.contains { fm.fileExists(atPath: $0) }
        switch runAsAdministrator(script) {
        case .cancelled:
            report.adminCancelled = true
            logger.info("elevated system import cancelled by the user")
            return report
        case .failed(let msg):
            logger.error("elevated system import failed: \(msg, privacy: .public)")
            report.outcomes.append(.init(path: profileDirs.joined(separator: ", "),
                                         kind: .unreadable(EPERM)))
            return report
        case .ok:
            break
        }

        let (found, outcome) = scanProfileDir(staging.path)
        // Report against the real paths, not the throwaway staging one.
        report.outcomes.append(.init(path: profileDirs.joined(separator: ", "), kind: outcome.kind))
        var seen = Set<String>()
        for c in found where seen.insert(dedupKey(host: c.host, group: c.group)).inserted {
            report.candidates.append(c)
        }
        logger.info("elevated scan: \(report.candidates.count, privacy: .public) candidate(s)")
        return report
    }

    private static func scanProfileDir(_ dir: String) -> ([Candidate], PathOutcome) {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: dir, isDirectory: &isDir), isDir.boolValue else {
            return ([], .init(path: dir, kind: .notPresent))
        }
        let names: [String]
        do { names = try fm.contentsOfDirectory(atPath: dir) }
        catch { return ([], .init(path: dir, kind: kind(for: error))) }

        var out: [Candidate] = []
        var readFailure: PathOutcome.Kind?
        for name in names.sorted() where name.lowercased().hasSuffix(".xml") {
            let path = (dir as NSString).appendingPathComponent(name)
            do {
                let xml = try String(contentsOfFile: path, encoding: .utf8)
                out.append(contentsOf: HostEntryParser.parse(xml).filter { !$0.host.isEmpty })
            } catch {
                readFailure = readFailure ?? kind(for: error)
            }
        }
        if out.isEmpty, let readFailure { return ([], .init(path: dir, kind: readFailure)) }
        return (out, .init(path: dir, kind: out.isEmpty ? .nothingUsable : .found(out.count)))
    }

    private static func scanPreferenceFile(_ path: String) -> ([Candidate], PathOutcome) {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else {
            return ([], .init(path: path, kind: .notPresent))
        }
        let text: String
        do { text = try String(contentsOfFile: path, encoding: .utf8) }
        catch { return ([], .init(path: path, kind: kind(for: error))) }

        let prefs = PreferencesParser.parse(text)
        let raw = prefs["DefaultHostName"]?.nonBlank ?? prefs["DefaultHostAddress"]?.nonBlank ?? ""
        guard !raw.isEmpty else { return ([], .init(path: path, kind: .nothingUsable)) }
        let parsed = ServerAddress.parse(raw)
        guard !parsed.host.isEmpty else { return ([], .init(path: path, kind: .nothingUsable)) }
        let group = prefs["DefaultGroup"]?.nonBlank ?? prefs["DefaultUserGroup"]?.nonBlank ?? parsed.group
        let c = Candidate(name: parsed.host,
                          host: parsed.host,
                          port: parsed.port ?? 443,
                          group: group,
                          username: prefs["DefaultUser"]?.nonBlank ?? "")
        return ([c], .init(path: path, kind: .found(1)))
    }

    private static func kind(for error: Error) -> PathOutcome.Kind {
        let ns = error as NSError
        let code: Int32
        if ns.domain == NSPOSIXErrorDomain {
            code = Int32(ns.code)
        } else if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? NSError,
                  underlying.domain == NSPOSIXErrorDomain {
            code = Int32(underlying.code)
        } else if ns.domain == NSCocoaErrorDomain && ns.code == NSFileReadNoPermissionError {
            code = EACCES
        } else {
            code = 0
        }
        switch code {
        case EACCES: return .deniedByFilePermissions
        case EPERM:  return .deniedByPrivacy
        default:     return .unreadable(code)
        }
    }

    // MARK: – Mapping to velun profiles

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
            oc.username = c.username
            var p = VPNProfile()
            p.name     = c.name.isEmpty ? c.host : c.name
            p.provider = .anyConnect
            p.config   = .sslVPN(oc)
            return p
        }
    }

    static func discoverProfiles(excluding existing: [VPNProfile]) -> [VPNProfile] {
        profiles(from: scan().candidates, excluding: existing)
    }

    private static func dedupKey(host: String, group: String) -> String {
        "\(host.lowercased())|\(group.lowercased())"
    }

    // MARK: – Running a command as administrator

    private enum AdminResult { case ok, cancelled, failed(String) }

    private static func runAsAdministrator(_ shellScript: String) -> AdminResult {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        p.arguments = ["-e", "do shell script \(appleScriptQuoted(shellScript)) with administrator privileges"]
        let err = Pipe()
        p.standardOutput = FileHandle.nullDevice
        p.standardError = err
        do { try p.run() } catch { return .failed(error.localizedDescription) }
        let stderr = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        p.waitUntilExit()
        if p.terminationStatus == 0 { return .ok }
        // -128 is the AppleScript "user cancelled" error.
        if stderr.contains("-128") || stderr.lowercased().contains("user canceled") {
            return .cancelled
        }
        return .failed(stderr.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Quote for `/bin/sh`, run by `do shell script`.
    private static func shq(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// Quote as an AppleScript string literal.
    private static func appleScriptQuoted(_ s: String) -> String {
        "\"" + s.replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}

private extension String {
    var nonBlank: String? {
        let t = trimmingCharacters(in: .whitespacesAndNewlines)
        return t.isEmpty ? nil : t
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

// MARK: – Preferences parser

private final class PreferencesParser: NSObject, XMLParserDelegate {
    static func parse(_ xml: String) -> [String: String] {
        guard let data = xml.data(using: .utf8) else { return [:] }
        let p = PreferencesParser()
        let parser = XMLParser(data: data)
        parser.delegate = p
        parser.parse()
        return p.values
    }

    private var values: [String: String] = [:]
    private var current = ""

    func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?,
                qualifiedName: String?, attributes: [String: String] = [:]) {
        current = ""
    }

    func parser(_ parser: XMLParser, foundCharacters s: String) { current += s }

    func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?,
                qualifiedName: String?) {
        let text = current.trimmingCharacters(in: .whitespacesAndNewlines)
        let key = name.split(separator: ":").last.map(String.init) ?? name
        if !text.isEmpty, values[key] == nil { values[key] = text }
        current = ""
    }
}
