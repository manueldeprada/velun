import Foundation
import OSLog
#if canImport(Sparkle)
import Sparkle
#endif

private let updaterLog = Logger(subsystem: "com.manueldeprada.velun", category: "Updater")

@MainActor
final class UpdaterManager: ObservableObject {
    @Published private(set) var automaticallyChecks: Bool = true

    #if canImport(Sparkle)
    private let controller: SPUStandardUpdaterController
    private let delegate = SparkleDelegate()

    init() {
        controller = SPUStandardUpdaterController(
            startingUpdater: true,
            updaterDelegate: delegate,
            userDriverDelegate: nil
        )
        controller.updater.automaticallyChecksForUpdates = true
        controller.updater.updateCheckInterval = 3600   // hourly
        automaticallyChecks = true
    }

    func checkForUpdates() {
        controller.checkForUpdates(nil)
    }

    func setAutomaticallyChecks(_ on: Bool) {
        controller.updater.automaticallyChecksForUpdates = on
        automaticallyChecks = on
    }
    #else
    init() { updaterLog.info("Sparkle not linked — auto-update disabled") }
    func checkForUpdates() {
        let alert = NSAlert()
        alert.messageText = "Updates not available"
        alert.informativeText = "This build was compiled without Sparkle. Visit the velun website to download the latest version manually."
        alert.runModal()
    }
    func setAutomaticallyChecks(_ on: Bool) { automaticallyChecks = on }
    #endif
}

#if canImport(Sparkle)
// NSObject subclass required by Sparkle's ObjC delegate protocol.
private final class SparkleDelegate: NSObject, SPUUpdaterDelegate {
    private static let iidKey = "velun.installationID"

    private static var installationID: String {
        if let v = UserDefaults.standard.string(forKey: iidKey) { return v }
        // Lowercase hex without dashes — looks like an opaque token, not a UUID.
        let new = UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: "")
        UserDefaults.standard.set(new, forKey: iidKey)
        return new
    }

    func feedParameters(for updater: SPUUpdater, sendingSystemProfile: Bool) -> [[String: String]] {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        let os = "\(v.majorVersion).\(v.minorVersion)"

        #if arch(arm64)
        let arch = "arm64"
        #else
        let arch = "x86_64"
        #endif

        let lang = Locale.preferredLanguages.first.flatMap {
            Locale(identifier: $0).language.languageCode?.identifier
        } ?? "und"

        return [
            ["key": "os",   "value": os],
            ["key": "arch", "value": arch],
            ["key": "lang", "value": lang],
            ["key": "iid",  "value": Self.installationID],
        ]
    }
}
#else
import AppKit
#endif
