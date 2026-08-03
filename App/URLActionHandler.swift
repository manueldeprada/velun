import Foundation
import AppKit
import OSLog

private let log = Logger(subsystem: "com.manueldeprada.velun", category: "URLAction")

@MainActor
enum URLActionHandler {
    static func handle(_ url: URL) {
        log.info("Handling URL: \(url.absoluteString, privacy: .public)")
        let host = url.host?.lowercased() ?? url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let qs = Dictionary(uniqueKeysWithValues:
            (comps?.queryItems ?? []).map { ($0.name.lowercased(), $0.value ?? "") })

        switch host {
        case "connect":
            guard let name = qs["name"], !name.isEmpty,
                  let p = profile(named: name) else {
                log.error("connect: no matching profile for name='\(qs["name"] ?? "", privacy: .public)'")
                return
            }
            VPNManager.shared.connect(p)

        case "disconnect":
            guard let name = qs["name"], !name.isEmpty,
                  let p = profile(named: name) else {
                log.error("disconnect: no matching profile for name='\(qs["name"] ?? "", privacy: .public)'")
                return
            }
            VPNManager.shared.userDisconnect(p)

        case "disconnect-all":
            VPNManager.shared.disconnectAll()

        case "import":
            do {
                let p = try TunnelExport.decodeURL(url)
                let added = VPNManager.shared.adoptImported([p])
                log.info("Imported '\(p.name, privacy: .public)' (\(p.provider.rawValue, privacy: .public))")
                NotificationCenter.default.post(name: .velunDidImportProfile, object: nil)
                if qs["autoconnect"] == "true" {
                    for ap in added { VPNManager.shared.connect(ap) }
                }
            } catch {
                log.error("Import failed: \(error.localizedDescription, privacy: .public)")
            }

        case "activate":
            guard let blob = qs["license"], !blob.isEmpty else {
                log.error("activate: missing license param")
                return
            }
            Task { @MainActor in
                let result = await AboutScreenManager.shared.submitLicense(blob)
                let alert  = NSAlert()
                switch result {
                case .ok:
                    alert.messageText     = "License activated"
                    alert.informativeText = "Thanks for purchasing velun!"
                    alert.alertStyle      = .informational
                case .signatureInvalid:
                    alert.messageText     = "Invalid license signature"
                    alert.informativeText = "The license couldn't be verified. Please contact eu@manueldeprada.com with your order ID."
                    alert.alertStyle      = .warning
                case .expired:
                    alert.messageText     = "License expired"
                    alert.informativeText = "This license has expired. Please request a renewal."
                    alert.alertStyle      = .warning
                case .serverRejected:
                    alert.messageText     = "Too many devices"
                    alert.informativeText = "This license is already activated on the maximum number of devices. Contact eu@manueldeprada.com to reset."
                    alert.alertStyle      = .warning
                case .parseError(let m):
                    alert.messageText     = "Couldn't read license"
                    alert.informativeText = m
                    alert.alertStyle      = .warning
                }
                NSApp.activate(ignoringOtherApps: true)
                alert.runModal()
            }

        case "reload-status":
            // No-op: StatusBroadcaster auto-mirrors every published change.
            log.info("reload-status request acknowledged")

        default:
            log.error("Unknown URL action '\(host, privacy: .public)'")
        }
    }

    private static func profile(named name: String) -> VPNProfile? {
        let needle = name.lowercased()
        return VPNManager.shared.profiles.first { $0.name.lowercased() == needle }
    }
}
