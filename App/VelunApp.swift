import SwiftUI

@main
struct VelunApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        Settings {
            ConfigurationView()
                .environmentObject(VPNManager.shared)
                .environmentObject(AboutScreenManager.shared)
                .environmentObject(UpdaterManager.shared)
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    private var menuBarManager: MenuBarManager?
    private var launchedFromURL = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)   // hide from Dock
        // Initialize managers on the main thread before the menu bar/UI reads them.
        _ = AboutScreenManager.shared
        _ = UpdaterManager.shared
        _ = LaunchAtLoginManager.shared
        menuBarManager = MenuBarManager()

        NSAppleEventManager.shared().setEventHandler(
            self,
            andSelector: #selector(handleGetURLEvent(_:withReplyEvent:)),
            forEventClass: AEEventClass(kInternetEventClass),
            andEventID:    AEEventID(kAEGetURL)
        )

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleDidImportProfile),
            name: .velunDidImportProfile,
            object: nil
        )
        StatusBroadcaster.shared.start()
        // Watch for SAML/SSO challenges and drive the WKWebView login window.
        SSOPresenter.shared.start(vpn: VPNManager.shared)
        ChangelogManager.shared.computePending()
        if AboutScreenManager.shared.isAccessGranted {
            VPNManager.shared.runAutoconnect()
        }
        VPNManager.shared.startNetworkPathWatcher()

        if !launchedFromURL {
            menuBarManager?.showPopover()
        }
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        launchedFromURL = true
        Task { @MainActor in
            for url in urls { URLActionHandler.handle(url) }
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication,
                                       hasVisibleWindows flag: Bool) -> Bool {
        menuBarManager?.showPopover()
        return false
    }

    @objc func handleDidImportProfile() {
        menuBarManager?.showPopover()
    }

    @objc func handleGetURLEvent(_ event: NSAppleEventDescriptor,
                                 withReplyEvent reply: NSAppleEventDescriptor) {
        guard let s = event.paramDescriptor(forKeyword: keyDirectObject)?.stringValue,
              let url = URL(string: s) else { return }
        Task { @MainActor in URLActionHandler.handle(url) }
    }

    func applicationWillTerminate(_ notification: Notification) {
        VPNManager.shared.snapshotConnectedForRestart()
        VPNManager.shared.disconnectAll()
        Thread.sleep(forTimeInterval: 0.1)
    }
}

extension Notification.Name {
    static let velunDidImportProfile = Notification.Name("velunDidImportProfile")
}

// Singletons so SwiftUI environment objects and AppKit code share one instance.
extension AboutScreenManager {
    @MainActor static let shared = AboutScreenManager()
}
extension UpdaterManager {
    @MainActor static let shared = UpdaterManager()
}
