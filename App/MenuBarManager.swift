import AppKit
import OSLog
import SwiftUI

private let log = Logger(subsystem: "com.manueldeprada.velun", category: "MenuBar")

extension Notification.Name {
    static let velunDismissPopover = Notification.Name("velun.dismissPopover")
}

class MenuBarManager {
    private var statusItem: NSStatusItem
    private var popover: NSPopover
    private var anchorMoveObserver: NSObjectProtocol?
    /// In-flight "wait for the slot, then show" task (see `showPopover`).
    private var pendingShowTask: Task<Void, Never>?
    /// Lazily created; see `fallbackAnchorView()`.
    private var fallbackAnchorWindow: NSWindow?

    private static let statusButtonWaitSeconds: TimeInterval = 3.0
    private static let statusButtonPollNanoseconds: UInt64 = 50_000_000
    private static let requiredStableSamples = 4

    init() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        popover    = NSPopover()
        popover.contentSize      = NSSize(width: 380, height: 480)
        popover.behavior         = .transient
        popover.contentViewController = NSHostingController(
            rootView: ConfigurationView()
                .environmentObject(VPNManager.shared)
                .environmentObject(AboutScreenManager.shared)
                .environmentObject(UpdaterManager.shared)
                .environmentObject(ChangelogManager.shared)
        )

        if let btn = statusItem.button {
            btn.image  = NSImage(systemSymbolName: "arrow.up.arrow.down.circle",
                                 accessibilityDescription: "VPN")
            btn.imageScaling = .scaleProportionallyDown
            btn.action = #selector(togglePopover)
            btn.target = self
        }

        Task { @MainActor [weak self] in
            for await statuses in VPNManager.shared.$statuses.values {
                self?.updateIcon(statuses)
            }
        }

        NotificationCenter.default.addObserver(
            forName: .velunDismissPopover, object: nil, queue: .main
        ) { [weak self] _ in
            self?.pendingShowTask?.cancel()
            self?.pendingShowTask = nil
            self?.popover.performClose(nil)
        }

        NotificationCenter.default.addObserver(
            forName: NSPopover.didCloseNotification, object: popover, queue: .main
        ) { [weak self] _ in
            self?.stopAnchorTracking()
        }
    }

    @objc private func togglePopover() {
        if popover.isShown {
            popover.performClose(nil)
        } else {
            presentPopover()
        }
    }

    func showPopover() {
        pendingShowTask?.cancel()
        pendingShowTask = Task { @MainActor [weak self] in
            await self?.waitForSettledStatusButton()
            guard !Task.isCancelled else { return }
            self?.presentPopover()
        }
    }

    @MainActor
    private func waitForSettledStatusButton() async {
        let deadline = Date().addingTimeInterval(Self.statusButtonWaitSeconds)
        var lastFrame: NSRect?
        var repeats = 0

        while Date() < deadline {
            let frame = statusButtonMenuBarFrame
            repeats = (frame != nil && frame == lastFrame) ? repeats + 1 : 0
            lastFrame = frame
            if repeats >= Self.requiredStableSamples { return }

            try? await Task.sleep(nanoseconds: Self.statusButtonPollNanoseconds)
            if Task.isCancelled { return }
        }
        log.warning("Status item never settled into a menu-bar slot (menu bar full?); using the fallback anchor. \(self.statusButtonGeometryDescription, privacy: .public)")
    }

    private var statusButtonMenuBarFrame: NSRect? {
        guard statusItem.isVisible,
              let button = statusItem.button, let window = button.window,
              button.bounds.width > 0, button.bounds.height > 0,
              window.frame.width > 0, window.frame.height > 0
        else { return nil }

        let frame = window.frame
        let inSomeMenuBar = NSScreen.screens.contains { screen in
            abs(frame.maxY - screen.frame.maxY) <= 2
                && frame.minX >= screen.frame.minX
                && frame.maxX <= screen.frame.maxX
        }
        return inSomeMenuBar ? frame : nil
    }

    private var statusButtonGeometryDescription: String {
        let window = statusItem.button?.window?.frame
        let screens = NSScreen.screens.map { "\($0.frame)" }.joined(separator: " ")
        return "window=\(window.map { "\($0)" } ?? "nil") screens=[\(screens)]"
    }

    private func presentPopover() {
        pendingShowTask?.cancel()
        pendingShowTask = nil
        guard !popover.isShown else { return }
        NSApp.activate(ignoringOtherApps: true)

        if statusButtonMenuBarFrame != nil, let btn = statusItem.button {
            popover.show(relativeTo: btn.bounds, of: btn, preferredEdge: .minY)
        } else if let anchor = fallbackAnchorView() {
            popover.show(relativeTo: anchor.bounds, of: anchor, preferredEdge: .minY)
        } else {
            log.error("No anchor available for the popover; not showing")
            return
        }
        startAnchorTracking()
    }

    private func fallbackAnchorView() -> NSView? {
        let mouse = NSEvent.mouseLocation
        let screen = NSScreen.screens.first { $0.frame.contains(mouse) }
            ?? NSScreen.main
            ?? NSScreen.screens.first
        guard let screen else { return nil }
        let origin = NSPoint(x: screen.visibleFrame.maxX - 24, y: screen.visibleFrame.maxY)
        let rect = NSRect(origin: origin, size: NSSize(width: 1, height: 1))

        let window: NSWindow
        if let existing = fallbackAnchorWindow {
            window = existing
        } else {
            window = NSWindow(contentRect: rect, styleMask: [.borderless],
                              backing: .buffered, defer: false)
            window.isOpaque = false
            window.backgroundColor = .clear
            window.hasShadow = false
            window.ignoresMouseEvents = true
            window.level = .statusBar
            fallbackAnchorWindow = window
        }
        window.setFrame(rect, display: false)
        window.orderFront(nil)
        return window.contentView
    }

    private func startAnchorTracking() {
        guard anchorMoveObserver == nil,
              let win = statusItem.button?.window else { return }
        anchorMoveObserver = NotificationCenter.default.addObserver(
            forName: NSWindow.didMoveNotification, object: win, queue: .main
        ) { [weak self] _ in
            guard let self, self.popover.isShown,
                  self.statusButtonMenuBarFrame != nil,
                  let btn = self.statusItem.button else { return }
            self.popover.show(relativeTo: btn.bounds, of: btn, preferredEdge: .minY)
        }
    }

    private func stopAnchorTracking() {
        if let o = anchorMoveObserver { NotificationCenter.default.removeObserver(o) }
        anchorMoveObserver = nil
    }

    private func updateIcon(_ statuses: [UUID: ConnectionStatus]) {
        let connected = statuses.values.filter { $0 == .connected }.count
        let transitional = statuses.values.contains {
            $0 == .connecting || $0 == .reconnecting || $0 == .disconnecting
        }
        let base: NSImage?
        if transitional {
            base = Self.templateIcon(named: "connecting") ?? symbolImage("ellipsis.circle")
        } else if connected > 0 {
            base = Self.templateIcon(named: "connected") ?? symbolImage("arrow.up.arrow.down.circle.fill")
        } else if statuses.values.contains(where: { if case .failed = $0 { return true }; return false }) {
            base = symbolImage("xmark.circle")
        } else {
            base = Self.templateIcon(named: "disconnected") ?? symbolImage("arrow.up.arrow.down.circle")
        }
        statusItem.button?.image = badgedImage(base: base, count: connected)
    }

    private func symbolImage(_ name: String) -> NSImage? {
        let cfg = NSImage.SymbolConfiguration(pointSize: 15, weight: .regular)
        return NSImage(systemSymbolName: name, accessibilityDescription: "VPN")?
            .withSymbolConfiguration(cfg)
    }

    private static func templateIcon(named name: String) -> NSImage? {
        guard let img = NSImage(named: name) ?? Bundle.main.image(forResource: name) else { return nil }
        let copy = img.copy() as! NSImage
        copy.size = NSSize(width: 18, height: 18)
        copy.isTemplate = true
        return copy
    }

    private func badgedImage(base: NSImage?, count: Int) -> NSImage? {
        guard let base else { return nil }
        guard count > 1 else { return base }

        let size = NSSize(width: 22, height: 22)
        let result = NSImage(size: size, flipped: false) { rect in
            let symSize  = base.size
            let symOrigin = NSPoint(x: (rect.width  - symSize.width)  / 2,
                                    y: (rect.height - symSize.height) / 2)
            base.draw(at: symOrigin, from: .zero, operation: .sourceOver, fraction: 1)

            let r: CGFloat = 5.5
            let cx = rect.maxX - r + 1
            let cy = rect.maxY - r + 1
            let badgeRect = NSRect(x: cx - r, y: cy - r, width: r * 2, height: r * 2)
            NSColor.black.setFill()
            NSBezierPath(ovalIn: badgeRect).fill()

            let str   = "\(count)" as NSString
            let attrs: [NSAttributedString.Key: Any] = [
                .font:            NSFont.boldSystemFont(ofSize: 7),
                .foregroundColor: NSColor.black,
            ]
            let sz = str.size(withAttributes: attrs)
            NSGraphicsContext.saveGraphicsState()
            NSGraphicsContext.current?.compositingOperation = .destinationOut
            str.draw(at: NSPoint(x: cx - sz.width / 2, y: cy - sz.height / 2),
                     withAttributes: attrs)
            NSGraphicsContext.restoreGraphicsState()
            return true
        }
        result.isTemplate = true
        return result
    }
}
