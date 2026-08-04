import Foundation
import OSLog

private let log = Logger(subsystem: "com.manueldeprada.velun", category: "ManagedPolicy")

struct ManagedPolicyProbe: Sendable {
    /// nil when `profiles` didn't answer (missing, timed out, unparseable).
    var mdmEnrolled: Bool?
    var vpnCreationDisallowed = false
    var restrictions: [String] = []
    var managedDomains: [String] = []

    var isManaged: Bool { mdmEnrolled == true || !managedDomains.isEmpty }

    // MARK: – Probing

    static func probe() async -> ManagedPolicyProbe {
        var p = ManagedPolicyProbe()
        p.scanManagedPreferences()
        p.mdmEnrolled = await Self.enrollmentState()
        let mdm = p.mdmEnrolled.map { $0 ? "yes" : "no" } ?? "unknown"
        log.notice("""
            probe: mdm=\(mdm, privacy: .public) \
            domains=\(p.managedDomains.joined(separator: ","), privacy: .public) \
            restrictions=\(p.restrictions.joined(separator: "; "), privacy: .public)
            """)
        return p
    }

    private static let managedPreferencesRoot = "/Library/Managed Preferences"

    private mutating func scanManagedPreferences() {
        let fm = FileManager.default
        let dirs = [Self.managedPreferencesRoot,
                    "\(Self.managedPreferencesRoot)/\(NSUserName())"]
        for dir in dirs {
            let names = (try? fm.contentsOfDirectory(atPath: dir)) ?? []
            for name in names.sorted() where name.hasSuffix(".plist") {
                let domain = String(name.dropLast(6))
                if !managedDomains.contains(domain) { managedDomains.append(domain) }
                guard let data = fm.contents(atPath: "\(dir)/\(name)"),
                      let dict = try? PropertyListSerialization.propertyList(
                          from: data, format: nil) as? [String: Any]
                else { continue }
                for (key, value) in dict.sorted(by: { $0.key < $1.key }) {
                    guard let flag = value as? Bool,
                          Self.isRestrictive(domain: domain, key: key, flag) else { continue }
                    if key == "allowVPNCreation" && flag == false { vpnCreationDisallowed = true }
                    let entry = "\(domain) \(key) = \(flag)"
                    if !restrictions.contains(entry) { restrictions.append(entry) }
                }
            }
        }
    }

    private static func isRestrictive(domain: String, key: String, _ value: Bool) -> Bool {
        let k = key.lowercased()
        let scope = k + " " + domain.lowercased()
        let relevant = ["vpn", "extension", "network", "tunnel", "proxy"].contains { scope.contains($0) }
        guard relevant else { return false }
        if k.hasPrefix("allow") || k.hasPrefix("enable") { return value == false }
        if k.hasPrefix("deny") || k.hasPrefix("disallow") || k.hasPrefix("block")
            || k.hasPrefix("forbid") || k.hasPrefix("restrict") { return value == true }
        return false
    }

    private static func enrollmentState() async -> Bool? {
        guard let out = await runCommand("/usr/bin/profiles",
                                         ["status", "-type", "enrollment"],
                                         timeout: 3) else { return nil }
        for line in out.split(separator: "\n") where line.contains("MDM enrollment:") {
            let value = line.split(separator: ":", maxSplits: 1).last?
                .trimmingCharacters(in: .whitespaces).lowercased() ?? ""
            if value.hasPrefix("yes") { return true }
            if value.hasPrefix("no")  { return false }
        }
        return nil
    }

    private static func runCommand(_ path: String, _ args: [String],
                                   timeout: TimeInterval) async -> String? {
        await withCheckedContinuation { (cont: CheckedContinuation<String?, Never>) in
            DispatchQueue.global(qos: .userInitiated).async {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: path)
                p.arguments = args
                let pipe = Pipe()
                p.standardOutput = pipe
                p.standardError = FileHandle.nullDevice
                do { try p.run() } catch {
                    log.error("\(path, privacy: .public) failed to launch: \(error.localizedDescription, privacy: .public)")
                    cont.resume(returning: nil)
                    return
                }
                DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                    if p.isRunning { p.terminate() }
                }
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                cont.resume(returning: String(data: data, encoding: .utf8))
            }
        }
    }

    // MARK: – User-facing wording

    var attribution: String {
        if !restrictions.isEmpty {
            return "This Mac is under device management (MDM) and its profiles restrict: "
                + restrictions.joined(separator: ", ") + "."
        }
        if mdmEnrolled == true {
            return "This Mac is enrolled in device management (MDM). The exact restriction "
                + "is in a configuration profile velun can't read without admin rights, "
                + "so it can't name it here."
        }
        if !managedDomains.isEmpty {
            return "This Mac has managed configuration profiles installed ("
                + managedDomains.joined(separator: ", ") + ")."
        }
        if mdmEnrolled == false {
            return "This Mac is not enrolled in device management, so a cached earlier "
                + "denial is the more likely cause than an IT policy."
        }
        return "velun couldn't determine whether this Mac is centrally managed."
    }
}
