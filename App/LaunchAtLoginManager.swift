import Foundation
import ServiceManagement
import OSLog

private let log = Logger(subsystem: "com.manueldeprada.velun", category: "LaunchAtLogin")

@MainActor
final class LaunchAtLoginManager: ObservableObject {
    static let shared = LaunchAtLoginManager()

    @Published private(set) var isEnabled: Bool
    @Published private(set) var requiresApproval: Bool

    private init() {
        let s = SMAppService.mainApp.status
        isEnabled = (s == .enabled)
        requiresApproval = (s == .requiresApproval)
    }

    func setEnabled(_ on: Bool) {
        do {
            if on {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            log.error("SMAppService change failed: \(error.localizedDescription, privacy: .public)")
        }
        // Always re-read — the system is the source of truth.
        let s = SMAppService.mainApp.status
        isEnabled = (s == .enabled)
        requiresApproval = (s == .requiresApproval)
    }
}
