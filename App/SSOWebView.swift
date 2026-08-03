import AppKit
import WebKit
import Combine
import OSLog

private let log = Logger(subsystem: "com.manueldeprada.velun", category: "SSO")

// MARK: – Presenter

@MainActor
final class SSOPresenter {
    static let shared = SSOPresenter()

    private var controllers: [UUID: SSOWindowController] = [:]
    private var cancellable: AnyCancellable?
    private weak var vpn: VPNManager?

    private init() {}

    func start(vpn: VPNManager) {
        self.vpn = vpn
        cancellable = vpn.$ssoChallenges
            .receive(on: RunLoop.main)
            .sink { [weak self] challenges in self?.sync(challenges) }
    }

    private func sync(_ challenges: [UUID: SSOLoginRequest]) {
        guard let vpn else { return }
        // Open a window for each newly-pending challenge.
        for (id, req) in challenges where controllers[id] == nil {
            log.notice("opening SSO window for \(id, privacy: .public)")
            let wc = SSOWindowController(request: req) { [weak self] token in
                // Capture (or cancel) → answer the extension and drop the window.
                vpn.submitSSO(for: id, token: token)
                self?.controllers.removeValue(forKey: id)
                self?.updateActivationPolicy()
            }
            controllers[id] = wc
        }
        for (id, wc) in controllers where challenges[id] == nil {
            wc.closeSilently()
            controllers.removeValue(forKey: id)
        }
        updateActivationPolicy()
    }

    private func updateActivationPolicy() {
        if controllers.isEmpty {
            NSApp.setActivationPolicy(.accessory)
        } else {
            NSApp.setActivationPolicy(.regular)
            NSApp.activate(ignoringOtherApps: true)
        }
    }
}

// MARK: – Window

@MainActor
final class SSOWindowController: NSObject, NSWindowDelegate, WKNavigationDelegate, WKHTTPCookieStoreObserver {
    private let request: SSOLoginRequest
    private let onResult: (String?) -> Void
    private var window: NSWindow!
    private var webView: WKWebView!
    private var finished = false

    init(request: SSOLoginRequest, onResult: @escaping (String?) -> Void) {
        self.request = request
        self.onResult = onResult
        super.init()
        build()
    }

    private func build() {
        let config = WKWebViewConfiguration()
        let frame = NSRect(x: 0, y: 0, width: 500, height: 700)
        webView = WKWebView(frame: frame, configuration: config)
        webView.navigationDelegate = self
        webView.customUserAgent =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 " +
            "(KHTML, like Gecko) Version/17.0 Safari/605.1.15"
        webView.configuration.websiteDataStore.httpCookieStore.add(self)

        window = NSWindow(contentRect: frame,
                          styleMask: [.titled, .closable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "Sign in to your VPN"
        window.contentView = webView
        window.delegate = self
        window.isReleasedWhenClosed = false
        window.center()

        guard let url = URL(string: request.loginURL) else {
            log.error("SSO login URL is invalid: \(self.request.loginURL, privacy: .public)")
            finish(nil); return
        }
        webView.load(URLRequest(url: url))
        window.makeKeyAndOrderFront(nil)
    }

    // Look for the token (or error) cookie the gateway sets once SSO completes.
    private func checkCookies() {
        guard !finished else { return }
        webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { [weak self] cookies in
            guard let self, !self.finished else { return }
            for c in cookies {
                if c.name == self.request.tokenCookieName, !c.value.isEmpty {
                    log.notice("captured SSO token cookie '\(c.name, privacy: .public)' (len=\(c.value.count, privacy: .public))")
                    self.finish(c.value); return
                }
                if !self.request.errorCookieName.isEmpty,
                   c.name == self.request.errorCookieName, !c.value.isEmpty {
                    log.error("SSO error cookie set: \(c.value, privacy: .public)")
                    self.finish(nil); return
                }
            }
        }
    }

    // MARK: WKHTTPCookieStoreObserver
    nonisolated func cookiesDidChange(in cookieStore: WKHTTPCookieStore) {
        Task { @MainActor [weak self] in self?.checkCookies() }
    }

    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation!) { checkCookies() }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { checkCookies() }

    // MARK: NSWindowDelegate
    func windowWillClose(_ notification: Notification) {
        if !finished { finish(nil) }   // user closed the window → cancel
    }

    /// Resolve once: detach the observer, report the result, close the window.
    private func finish(_ token: String?) {
        guard !finished else { return }
        finished = true
        webView.configuration.websiteDataStore.httpCookieStore.remove(self)
        let cb = onResult
        window.delegate = nil
        window.close()
        cb(token)
    }

    func closeSilently() {
        guard !finished else { return }
        finished = true
        webView.configuration.websiteDataStore.httpCookieStore.remove(self)
        window.delegate = nil
        window.close()
    }
}
