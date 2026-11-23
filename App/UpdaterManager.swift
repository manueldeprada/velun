import AppKit
import Combine
import OSLog
#if canImport(Sparkle)
import Sparkle
#endif

private let updaterLog = Logger(subsystem: "com.manueldeprada.velun", category: "Updater")

@MainActor
final class UpdaterManager: ObservableObject {
    @Published private(set) var automaticallyChecks: Bool = true

    /// An update found by a scheduled check, shown as a row in the popover.
    struct PendingUpdate: Equatable {
        let version: String
        let downloaded: Bool
    }
    @Published private(set) var pendingUpdate: PendingUpdate? = nil

    var isPopoverShown: () -> Bool = { false }

    /// Sparkle's "install and relaunch now" for a staged update.
    private var installHandler: (() -> Void)?
    private var idleCheck: AnyCancellable?
    private var idleCheckTask: Task<Void, Never>?
    private static let idleInstallDelay: UInt64 = 5_000_000_000

    #if canImport(Sparkle)
    private let controller: SPUStandardUpdaterController
    private let delegate = SparkleDelegate()
    private let userDriverDelegate = SparkleUserDriverDelegate()

    init() {
        controller = SPUStandardUpdaterController(
            startingUpdater: false,
            updaterDelegate: delegate,
            userDriverDelegate: userDriverDelegate
        )
        delegate.manager = self
        userDriverDelegate.manager = self
        controller.startUpdater()
        controller.updater.automaticallyChecksForUpdates = true
        controller.updater.updateCheckInterval = 3600   // hourly
        automaticallyChecks = true
    }

    func checkForUpdates() {
        controller.checkForUpdates(nil)
    }

    /// The popover row's button.
    func installPendingUpdate() {
        if let installHandler {
            updaterLog.notice("installing the downloaded update at the user's request")
            installHandler()
        } else {
            controller.checkForUpdates(nil)
        }
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
    func installPendingUpdate() {}
    #endif

    fileprivate func updateStaged(version: String, install: @escaping () -> Void) {
        updaterLog.notice("update \(version, privacy: .public) downloaded; installing once no tunnel is up")
        installHandler = install
        pendingUpdate = PendingUpdate(version: version, downloaded: true)
        idleCheck = VPNManager.shared.objectWillChange
            .sink { [weak self] _ in self?.scheduleIdleInstallCheck() }
        scheduleIdleInstallCheck()
    }

    func scheduleIdleInstallCheck() {
        guard installHandler != nil else { return }
        idleCheckTask?.cancel()
        idleCheckTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: Self.idleInstallDelay)
            guard let self, !Task.isCancelled, let install = self.installHandler,
                  VPNManager.shared.isIdleForRelaunch, !self.isPopoverShown(),
                  NSApp.modalWindow == nil
            else { return }
            updaterLog.notice("installing the downloaded update: no tunnel is up")
            install()
        }
    }

    fileprivate func updateFound(version: String) {
        updaterLog.notice("update \(version, privacy: .public) available; showing it in the popover")
        if pendingUpdate?.downloaded != true {
            pendingUpdate = PendingUpdate(version: version, downloaded: false)
        }
    }

    fileprivate func updateSessionEnded() {
        if pendingUpdate?.downloaded == false { pendingUpdate = nil }
    }
}

#if canImport(Sparkle)
// NSObject subclass required by Sparkle's ObjC delegate protocol.
private final class SparkleDelegate: NSObject, SPUUpdaterDelegate {
    private static let iidKey = "velun.installationID"
    weak var manager: UpdaterManager?

    func updater(_ updater: SPUUpdater,
                 willInstallUpdateOnQuit item: SUAppcastItem,
                 immediateInstallationBlock immediateInstallHandler: @escaping () -> Void) -> Bool {
        let version = item.displayVersionString
        Task { @MainActor [weak manager] in
            manager?.updateStaged(version: version, install: immediateInstallHandler)
        }
        return true
    }

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

private final class SparkleUserDriverDelegate: NSObject, SPUStandardUserDriverDelegate {
    weak var manager: UpdaterManager?

    var supportsGentleScheduledUpdateReminders: Bool { true }

    func standardUserDriverShouldHandleShowingScheduledUpdate(
        _ update: SUAppcastItem, andInImmediateFocus immediateFocus: Bool
    ) -> Bool {
        immediateFocus
    }

    func standardUserDriverWillHandleShowingUpdate(
        _ handleShowingUpdate: Bool, forUpdate update: SUAppcastItem, state: SPUUserUpdateState
    ) {
        guard !handleShowingUpdate, !state.userInitiated else { return }
        let version = update.displayVersionString
        Task { @MainActor [weak manager] in manager?.updateFound(version: version) }
    }

    func standardUserDriverDidReceiveUserAttention(forUpdate update: SUAppcastItem) {
        Task { @MainActor [weak manager] in manager?.updateSessionEnded() }
    }

    func standardUserDriverWillFinishUpdateSession() {
        Task { @MainActor [weak manager] in manager?.updateSessionEnded() }
    }
}
#endif
