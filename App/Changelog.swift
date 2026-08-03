import Foundation
import Combine
import SwiftUI

struct ChangelogEntry: Identifiable {
    let id = UUID()
    let version: String         // "0.0.8" — must match Info.plist CFBundleShortVersionString
    let date:    String         // ISO yyyy-mm-dd
    let title:   String         // short headline shown above the bullets
    let bullets: [String]
}

enum Changelog {
    /// Append new entries here when shipping a release. Most recent at the top.
    static let entries: [ChangelogEntry] = [
        ChangelogEntry(
            version: "0.3.6",
            date:    "2026-08-02",
            title:   "IPv6 supported",
            bullets: [
                "IPv6 now goes through the tunnel when the server offers it, and is blocked when it doesn't.",
                "New Kill switch setting for full tunnels.",
            ]
        ),
        ChangelogEntry(
            version: "0.3.5",
            date:    "2026-07-31",
            title:   "Popover positioning",
            bullets: [
                "Fixed the popover opening in a screen corner, or on the wrong display, at launch.",
                "With a full menu bar the popover now opens below the menu bar instead of the bottom-left corner.",
            ]
        ),
        ChangelogEntry(
            version: "0.3.4",
            date:    "2026-07-05",
            title:   "Fixes and improved failure detection",
            bullets: [
                "Fixed a crash when disconnecting a WireGuard tunnel with live traffic, which silently took down every connection.",
                "Connect and disconnect no longer hang in yellow after an extension failure; errors surface in seconds.",
                "Fixed reconnects hanging for minutes after wake when Auto Proxy Discovery (WPAD) is enabled.",
                "Lookups for a VPN's domains now fail fast while its tunnel is reconnecting, instead of hanging apps.",
                "SSH sessions that don't survive a reconnect now drop within seconds instead of hanging until the terminal is closed.",
            ]
        ),
        ChangelogEntry(
            version: "0.3.3",
            date:    "2026-07-02",
            title:   "UI fixes",
            bullets: [
                "Fixed a freeze in the connections list.",
                "The popover now follows the menu-bar icon when it shifts position.",
                "Fixed the menu-bar icon getting clipped on external displays.",
            ]
        ),
        ChangelogEntry(
            version: "0.3.2",
            date:    "2026-07-02",
            title:   "Tunnel specific hostnames",
            bullets: [
                "Added an \"also tunnel these hostnames\" field for split routing.",
                "Fixes services on IPs that auto-detect can't find.",
            ]
        ),
        ChangelogEntry(
            version: "0.3.1",
            date:    "2026-06-30",
            title:   "Connection fixes",
            bullets: [
                "Fixed sign-in to AnyConnect servers on a non-standard port.",
                "Connect no longer fails when the network briefly drops at startup.",
            ]
        ),
        ChangelogEntry(
            version: "0.3.0",
            date:    "2026-06-30",
            title:   "Single sign-on (SSO)",
            bullets: [
                "Added SAML single sign-on login for AnyConnect, in a browser window.",
                "Leave the TOTP field blank to be prompted for the 2FA code.",
            ]
        ),
        ChangelogEntry(
            version: "0.2.1",
            date:    "2026-06-30",
            title:   "Imported connection fix, Port field",
            bullets: [
                "Fixed imported connections that included a port or path in the URL.",
                "Added a Port field to the connection editor.",
                "Steadier two-factor prompts.",
            ]
        ),
        ChangelogEntry(
            version: "0.2.0",
            date:    "2026-06-29",
            title:   "Import saved connections, all-native engine",
            bullets: [
                "Imports VPN connections already saved on your Mac. Runs on first launch, or anytime via \"Import from system.\"",
                "All connections now use the built-in native engine. No command-line tools to install.",
                "First-time setup polish.",
                "Thanks to Breixo and Patrik for betatesting.",
            ]
        ),
        ChangelogEntry(
            version: "0.1.5",
            date:    "2026-06-28",
            title:   "Faster corporate VPNs, DTLS support, sturdier reconnects",
            bullets: [
                "Corporate VPN connection speeds optimized.",
                "DTLS data channel now supported, for better throughput on lossy networks. On by default, toggle in Advanced.",
                "Reconnect fixes: rapid disconnect/reconnect, overlapping attempts after sleep/wake, and a reconnect crash.",
            ]
        ),
        ChangelogEntry(
            version: "0.1.1",
            date:    "2026-06-11",
            title:   "Reliable reconnects, idle sessions stay alive",
            bullets: [
                "Detects a dead tunnel (e.g. after a Wi-Fi switch) and reconnects, instead of falsely reporting \"connected\".",
                "Keeps idle sessions like SSH warm across sleep where possible, otherwise drops them fast instead of hanging.",
                "Added a \"View Changelog…\" button in the About menu.",
            ]
        ),
        ChangelogEntry(
            version: "0.1.0",
            date:    "2026-06-06",
            title:   "One connection for all your VPNs + automatic kill switch",
            bullets: [
                "Multiple VPNs now share one connection and route side-by-side: a full-tunnel VPN and partial tunnels to other networks no longer break each other.",
                "Full-tunnel mode is now an automatic kill switch: every app is forced through the VPN, and traffic is blocked if the tunnel drops.",
                "Corporate DNS resolves correctly across several VPNs at once: each network's internal names go to the right gateway.",
                "WireGuard now runs alongside your other VPNs under the same routing.",
                "Per-VPN transfer stats.",
            ]
        ),
        ChangelogEntry(
            version: "0.0.9",
            date:    "2026-05-22",
            title:   "Partial DNS routes, improved auto-reconnect, UX improvements",
            bullets: [
                "Partial mode now auto-detects the corp DNS suffix, so internal hostnames resolve through the VPN, even with Tailscale or another VPN running.",
                "Reconnects automatically after sleep, Wi-Fi loss, or any passive drop. Toggle in Advanced → Startup.",
                "Cleaner applied-routes panel.",
                "Fixed: connecting two profiles at once (e.g. on launch) could fail.",
                "Fixed WireGuard VPNs.",
            ]
        ),
        ChangelogEntry(
            version: "0.0.8",
            date:    "2026-05-18",
            title:   "Better error visibility, commands through VPN",
            bullets: [
                "Errors now show inline on the connection card, with no more hunting through a tiny ⚠ button. The full technical log is still one click away under \"View logs.\"",
                "Connection drops that aren't your doing now show as a clear orange \"Connection lost\" banner with Reconnect / Dismiss buttons, rather than collapsing to a neutral grey.",
                "Fixed: if velun couldn't read your saved password from the system Keychain at startup (sometimes happens when launched at login before the keychain unlocks), the Connect button would silently grey out with no explanation. velun now shows a clear \"Saved credentials unavailable, relaunch velun\" note instead, and refuses to overwrite the real Keychain entry with the empty in-memory value.",
                "New \"Commands through VPN\" feature (preview): set up shell commands per profile (e.g. ssh into a corp host) that run through a one-shot tunnel: no utun, no admin prompt, no system-wide routing changes. Open the connection's edit form and click the Commands button to author a recipe. Once saved, a terminal icon appears next to Connect that lets you fire it. AnyConnect/Fortinet/GlobalProtect only for now; TCP only, so pass IP literals.",
            ]
        ),
    ]
}

@MainActor
final class ChangelogManager: ObservableObject {
    static let shared = ChangelogManager()
    private static let lastSeenKey = "velun.changelogLastSeenVersion"

    @Published var pending: [ChangelogEntry]? = nil

    private init() {}

    func computePending() {
        let current  = Self.currentVersion()
        let lastSeen = UserDefaults.standard.string(forKey: Self.lastSeenKey)
        let isFreshInstall = UserDefaults.standard.data(forKey: "velun.profiles.v3") == nil

        if lastSeen == nil {
            if isFreshInstall {
                UserDefaults.standard.set(current, forKey: Self.lastSeenKey)
                return
            }
            if !Changelog.entries.isEmpty { pending = Changelog.entries }
            return
        }
        if lastSeen == current { return }

        if let lastIdx = Changelog.entries.firstIndex(where: { $0.version == lastSeen }) {
            let slice = Changelog.entries.prefix(lastIdx)
            if !slice.isEmpty { pending = Array(slice) }
        } else {
            if !Changelog.entries.isEmpty { pending = Changelog.entries }
        }
    }

    func markCurrentSeen() {
        UserDefaults.standard.set(Self.currentVersion(), forKey: Self.lastSeenKey)
        pending = nil
    }

    func showAll() {
        if !Changelog.entries.isEmpty { pending = Changelog.entries }
    }

    private static func currentVersion() -> String {
        (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? "0.0.0"
    }
}

// MARK: – Sheet

struct WhatsNewSheet: View {
    let entries: [ChangelogEntry]
    let onDismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text("What's New").font(.title2).fontWeight(.semibold)
                Spacer()
                Text("velun \(entries.first?.version ?? "")")
                    .font(.caption).foregroundStyle(.secondary)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(entries) { entry in
                        VStack(alignment: .leading, spacing: 6) {
                            HStack(alignment: .firstTextBaseline) {
                                Text(entry.title).font(.headline)
                                Spacer()
                                Text("v\(entry.version) · \(entry.date)")
                                    .font(.caption2).foregroundStyle(.secondary)
                            }
                            ForEach(entry.bullets, id: \.self) { bullet in
                                HStack(alignment: .top, spacing: 6) {
                                    Text("•").foregroundStyle(.secondary)
                                    Text(bullet)
                                        .font(.callout)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                            }
                        }
                    }
                }
                .padding(.vertical, 4)
            }
            .frame(minHeight: 180, idealHeight: 280, maxHeight: 380)

            HStack {
                Spacer()
                Button("Got it", action: onDismiss)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 460)
    }
}

