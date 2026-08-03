import SwiftUI
import AppKit
import UniformTypeIdentifiers

// MARK: – Root view

struct ConfigurationView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var about: AboutScreenManager
    @EnvironmentObject var updater: UpdaterManager
    @EnvironmentObject var changelog: ChangelogManager
    @State private var showInfo     = false
    @State private var showAdvanced = false
    @State private var showLicense  = false
    @State private var importAlert:   ImportAlert?
    @State private var shareBlob:     String?    // non-nil → Share sheet shown
    @State private var showImport     = false

    struct ImportAlert: Identifiable {
        let id = UUID()
        let title: String
        let message: String
    }

    var body: some View {
        VStack(spacing: 0) {
            globalHeader
            Divider()
            if about.isAccessGranted {
                if vpn.profiles.isEmpty {
                    welcomeView
                } else {
                    if let count = vpn.systemImportNotice {
                        systemImportBanner(count)
                        Divider()
                    }
                    profileList
                }
                Divider()
                bottomBar
                if about.shouldShowTrialBanner {
                    Divider()
                    trialBanner
                }
            } else {
                AboutScreenGateView()
            }
        }
        .frame(width: 380)
        .alert(item: $importAlert) { a in
            Alert(title: Text(a.title), message: Text(a.message), dismissButton: .default(Text("OK")))
        }
        .sheet(item: Binding(
            get: { shareBlob.map { ShareBlob(text: $0) } },
            set: { shareBlob = $0?.text }
        )) { sb in
            ShareBlobSheet(blob: sb.text)
        }
        .sheet(isPresented: $showImport) {
            ImportBlobSheet { text in
                do {
                    let imported = try vpn.importBlob(text)
                    importAlert = ImportAlert(
                        title: "Imported",
                        message: "Added \(imported.count) connection\(imported.count == 1 ? "" : "s")."
                    )
                } catch {
                    importAlert = ImportAlert(title: "Import failed",
                                              message: error.localizedDescription)
                }
            }
        }
        .sheet(item: Binding(
            get: { changelog.pending.map { PendingChangelog(entries: $0) } },
            set: { _ in /* dismissal goes through markCurrentSeen */ }
        )) { pending in
            WhatsNewSheet(entries: pending.entries) {
                changelog.markCurrentSeen()
            }
        }
    }

    // MARK: – Global header

    private var globalHeader: some View {
        HStack {
            Image(systemName: vpn.anyConnected ? "arrow.up.arrow.down.circle.fill" : "arrow.up.arrow.down.circle")
                .foregroundStyle(vpn.anyConnected ? Color.green : Color.secondary)
                .font(.title2)
            VStack(alignment: .leading, spacing: 1) {
                Text("velun").font(.headline)
                Text(headerSubtitle).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button { showAdvanced.toggle() } label: {
                Image(systemName: "gearshape")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .help("Advanced settings")
            .popover(isPresented: $showAdvanced, arrowEdge: .bottom) {
                AdvancedPopover(showLicense: $showLicense)
                    .environmentObject(vpn)
                    .environmentObject(about)
                    .environmentObject(updater)
            }
            Button { showInfo.toggle() } label: {
                Image(systemName: "info.circle")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .popover(isPresented: $showInfo, arrowEdge: .bottom) {
                AboutPopover(onViewChangelog: {
                    showInfo = false
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { changelog.showAll() }
                })
                .environmentObject(about).environmentObject(updater)
            }
            Button { NSApplication.shared.terminate(nil) } label: {
                Image(systemName: "power")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .help("Quit velun")
        }
        .padding(.horizontal).padding(.vertical, 8)
        .background(.ultraThinMaterial)
        .sheet(isPresented: $showLicense) {
            AboutScreenEntrySheet().environmentObject(about)
        }
    }

    private var headerSubtitle: String {
        let active = vpn.statuses.values.filter { $0 == .connected }.count
        if active == 0 { return "No active connections" }
        return "\(active) connection\(active == 1 ? "" : "s") active"
    }

    // MARK: – Profile list

    private var profileList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(spacing: 6) {
                    ForEach(vpn.profiles) { profile in
                        ProfileCard(profile: profile)
                            .environmentObject(vpn)
                            .id(profile.id)
                    }
                }
                .padding(8)
            }
            .frame(maxHeight: 520)
            .onChange(of: vpn.newlyAddedProfileID) { id in
                guard let id else { return }
                withAnimation { proxy.scrollTo(id, anchor: .top) }
            }
            .onChange(of: vpn.newlyImportedProfileID) { id in
                guard let id else { return }
                withAnimation { proxy.scrollTo(id, anchor: .top) }
            }
        }
    }

    // MARK: – First-run system-import notice

    private func systemImportBanner(_ count: Int) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "sparkles")
                .font(.caption).foregroundStyle(.blue)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(count == 1
                     ? "Recovered a saved VPN connection on this Mac"
                     : "Recovered \(count) saved VPN connections on this Mac")
                    .font(.caption).fontWeight(.medium)
                Text("Server details were filled in for you. Add your username and password to connect.")
                    .font(.caption2).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 4)
            Button { vpn.systemImportNotice = nil } label: {
                Image(systemName: "xmark")
                    .font(.caption2).foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .help("Dismiss")
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(Color.blue.opacity(0.08))
    }

    // MARK: – Welcome / empty state

    private var welcomeView: some View {
        ScrollView {
            VStack(spacing: 14) {
                Image(nsImage: NSApplication.shared.applicationIconImage)
                    .resizable().aspectRatio(contentMode: .fit)
                    .frame(width: 88, height: 88)
                    .accessibilityLabel("velun")
                VStack(spacing: 2) {
                    Text("Welcome to velun")
                        .font(.title3).fontWeight(.semibold)
                    Text("A native macOS menu-bar VPN client")
                        .font(.caption).foregroundStyle(.secondary)
                }
                VStack(spacing: 10) {
                    welcomeBullet("plus.circle",
                        "Add a VPN connection to get started. You'll need your server address and sign-in details.")
                    welcomeBullet("menubar.dock.rectangle",
                        "velun lives in the menu bar. Click its icon up top to reopen this window anytime, including after you grant macOS permissions.")
                    welcomeBullet("qrcode.viewfinder",
                        "Two-factor login? Scan your authenticator's QR code once and velun fills in the 6-digit code for you on every connect.")
                    welcomeBullet("arrow.triangle.branch",
                        "Split tunneling: send only your work networks through the VPN and keep everything else on your normal connection, or route it all, with a built-in kill switch.")
                    welcomeBullet("person.2",
                        "Has a friend or your IT team already set up velun? Ask them to share the connection with you, then use \"Import from URL…\" below.")
                }
                HStack(spacing: 8) {
                    Button { _ = vpn.addProfile() } label: {
                        Label("Add Connection", systemImage: "plus")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    Button { importFromSystem() } label: {
                        Label("Import from system", systemImage: "square.and.arrow.down.on.square")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity)
        }
        .frame(maxHeight: 520)
    }

    private func welcomeBullet(_ icon: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: icon)
                .font(.caption).foregroundStyle(.secondary)
                .frame(width: 18)
            Text(text)
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: – Bottom bar

    private var bottomBar: some View {
        HStack(spacing: 8) {
            Button { _ = vpn.addProfile() } label: {
                Label("Add Connection", systemImage: "plus")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)

            Menu {
                Button("Share all…") { exportAll(includeCredentials: false) }
                Button("Export all (with credentials)…") { exportAll(includeCredentials: true) }
                Divider()
                Button("Import from URL…") { showImport = true }
                Button("Import from system") { importFromSystem() }
            } label: {
                Image(systemName: "square.and.arrow.up.on.square")
                    .frame(width: 28, height: 22)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .help("Export / Import tunnels")
        }
        .padding(8)
    }

    // MARK: – Trial banner

    private var trialBanner: some View {
        HStack(spacing: 6) {
            Image(systemName: "clock.arrow.circlepath")
                .font(.caption).foregroundStyle(.orange)
            Text(about.trialBannerText)
                .font(.caption2).foregroundStyle(.secondary)
            Spacer()
            Button("Enter License") { showLicense = true }
                .buttonStyle(.borderless)
                .controlSize(.small)
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
        .background(Color.orange.opacity(0.08))
    }

    private func exportAll(includeCredentials: Bool) {
        guard !vpn.profiles.isEmpty else {
            importAlert = ImportAlert(title: "Nothing to export",
                                      message: "Add a connection first.")
            return
        }
        shareBlob = vpn.exportBlob(includeCredentials: includeCredentials)
    }

    private func importFromSystem() {
        let r = vpn.importFromSystem()
        if !r.added.isEmpty {
            let n = r.added.count
            var msg = "Added \(n) connection\(n == 1 ? "" : "s") from this Mac. Enter your sign-in details on each, then connect."
            if r.alreadyPresent > 0 {
                msg += " (\(r.alreadyPresent) other\(r.alreadyPresent == 1 ? " was" : "s were") already in your list.)"
            }
            importAlert = ImportAlert(title: "Imported", message: msg)
        } else if r.found > 0 {
            // Found on disk, but every one is already a velun connection.
            importAlert = ImportAlert(
                title: "Already imported",
                message: r.found == 1
                    ? "The VPN connection saved on this Mac is already in your list."
                    : "All \(r.found) VPN connections saved on this Mac are already in your list.")
        } else {
            importAlert = ImportAlert(
                title: "Nothing found",
                message: "velun couldn’t find any VPN connections saved on this Mac. Add one manually, or use Import from URL.")
        }
    }
}

// `String` is not `Identifiable`, so wrap it for `.sheet(item:)`.
private struct ShareBlob: Identifiable {
    let text: String
    var id: String { text }
}

private struct PendingChangelog: Identifiable {
    let entries: [ChangelogEntry]
    var id: String { entries.first?.version ?? "" }
}

struct ShareBlobSheet: View {
    let blob: String
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Share these velun:// URLs. One line = one connection.")
                .font(.caption).foregroundStyle(.secondary)
            ScrollView {
                Text(blob)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
            }
            .background(Color(NSColor.textBackgroundColor))
            .overlay(RoundedRectangle(cornerRadius: 4)
                .strokeBorder(Color.secondary.opacity(0.3)))
            .frame(minHeight: 160, idealHeight: 220, maxHeight: 320)
            HStack {
                Button(copied ? "Copied" : "Copy") {
                    let pb = NSPasteboard.general
                    pb.clearContents()
                    pb.setString(blob, forType: .string)
                    copied = true
                }
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(16)
        .frame(width: 480)
    }
}

struct ImportBlobSheet: View {
    let onImport: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Paste velun:// URL(s). One per line.")
                .font(.caption).foregroundStyle(.secondary)
            TextEditor(text: $text)
                .font(.system(.caption, design: .monospaced))
                .frame(minHeight: 160, idealHeight: 220)
                .overlay(RoundedRectangle(cornerRadius: 4)
                    .strokeBorder(Color.secondary.opacity(0.3)))
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Import") {
                    onImport(text)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(16)
        .frame(width: 480)
    }
}

// MARK: – Advanced popover

struct AdvancedPopover: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var about: AboutScreenManager
    @EnvironmentObject var updater: UpdaterManager
    @ObservedObject var launchAtLogin = LaunchAtLoginManager.shared
    @Binding var showLicense: Bool

    private var killSwitchStateLabel: String {
        if vpn.killSwitchActive { return "Active. All traffic is confined to the VPN." }
        if vpn.killSwitchPending {
            return vpn.killSwitchEnabled
                ? "Not applied yet. This full tunnel started before the kill switch could be set."
                : "Still applied to the running tunnel. Restart to remove it."
        }
        return vpn.killSwitchEnabled
            ? "Inactive. No full tunnel is connected."
            : "Off. Traffic is not blocked if a full tunnel drops."
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Advanced").font(.headline)

            VStack(alignment: .leading, spacing: 4) {
                Text("Startup").font(.caption).foregroundStyle(.secondary)
                Toggle(isOn: Binding(
                    get: { launchAtLogin.isEnabled },
                    set: { launchAtLogin.setEnabled($0) }
                )) {
                    Text("Start velun at login").font(.caption)
                }
                .toggleStyle(.checkbox)
                if launchAtLogin.requiresApproval {
                    Text("Approval pending. Open System Settings → Login Items.")
                        .font(.caption2).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Toggle(isOn: $vpn.autoreconnectEnabled) {
                    Text("Auto-reconnect last session at launch").font(.caption)
                }
                .toggleStyle(.checkbox)
                Text("Reconnects whichever profiles were connected when velun last quit.")
                    .font(.caption2).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
                Toggle(isOn: $vpn.autoReconnectOnNetworkRestore) {
                    Text("Reconnect when network comes back").font(.caption)
                }
                .toggleStyle(.checkbox)
                Text("After sleep/wake or Wi-Fi loss, automatically reconnect tunnels that dropped on their own.")
                    .font(.caption2).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Divider()

            VStack(alignment: .leading, spacing: 6) {
                Text("Kill switch").font(.caption).foregroundStyle(.secondary)
                Toggle(isOn: $vpn.killSwitchEnabled) {
                    Text("Block traffic outside the VPN on full tunnels").font(.caption)
                }
                .toggleStyle(.checkbox)
                Text("When a full tunnel is active, strictly all traffic is forced through the VPN. Partial tunnels are unaffected.")
                    .font(.caption2).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: 5) {
                    Image(systemName: vpn.killSwitchActive ? "lock.fill"
                                    : vpn.killSwitchPending ? "exclamationmark.triangle.fill" : "lock.open")
                        .font(.caption2)
                        .foregroundStyle(vpn.killSwitchActive ? Color.green
                                       : vpn.killSwitchPending ? Color.orange : Color.secondary)
                    Text(killSwitchStateLabel).font(.caption2)
                        .foregroundStyle(vpn.killSwitchPending ? Color.orange : Color.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if vpn.killSwitchPending {
                    Button("Apply now (reconnects tunnels)") { vpn.applyKillSwitchNow() }
                        .controlSize(.small)
                    Text("Applying restarts the shared tunnel, so every connected profile signs in again. Takes about a minute: VPN servers reject a sign-in that follows too soon after the previous session ended.")
                        .font(.caption2).foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Divider()

            VStack(alignment: .leading, spacing: 6) {
                Text("Data channel (AnyConnect)")
                    .font(.caption).foregroundStyle(.secondary)
                Toggle(isOn: $vpn.dtlsEnabled) {
                    Text("Use DTLS when the server offers it").font(.caption)
                }
                .toggleStyle(.checkbox)
                Text("Carries data over UDP (DTLS) instead of TCP when available, for steadier throughput on lossy links. Falls back to TLS automatically. Applies on next connect.")
                    .font(.caption2).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Divider()

            VStack(alignment: .leading, spacing: 4) {
                Text("Updates").font(.caption).foregroundStyle(.secondary)
                Button("Check for Updates…") { updater.checkForUpdates() }
                    .controlSize(.small)
                Toggle(isOn: Binding(
                    get: { updater.automaticallyChecks },
                    set: { updater.setAutomaticallyChecks($0) }
                )) {
                    Text("Automatically check for updates").font(.caption)
                }
                .toggleStyle(.checkbox)
            }

            Divider()

            VStack(alignment: .leading, spacing: 4) {
                Text("License").font(.caption).foregroundStyle(.secondary)
                Text(about.statusLabel)
                    .font(.caption2).foregroundStyle(.secondary)
                HStack(spacing: 6) {
                    Button(about.hasLicense ? "Manage License…" : "Enter License…") {
                        showLicense = true
                    }
                    .controlSize(.small)
                    if about.hasLicense {
                        Button("Remove") { about.removeLicense() }
                            .controlSize(.small)
                    }
                }
            }
        }
        .padding(16)
        .frame(width: 320)
        .onAppear { vpn.refreshKillSwitchState() }
    }

}

// MARK: – 2FA automation explainer

struct TOTPHelpPopover: View {
    var showsQRButton: Bool = true

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("2FA automation").font(.headline)
            Text("Tired of typing your 2FA code on every connection? velun can generate it for you.")
            Text("To do that, velun needs your \"TOTP secret\": a base32 string your authenticator app uses to generate codes.")
            Text("In Google Authenticator: side menu → Transfer accounts → Export accounts → select your VPN account. It shows a QR code containing the secret. " +
                 (showsQRButton
                  ? "Use the QR button next to this field to scan it and import it automatically."
                  : "Scan it from this connection's settings, using the QR button next to the TOTP secret field."))
            Text("Note: some apps, like Microsoft Authenticator, don't allow exporting the secret. If yours doesn't, you must re-generate your 2FA seed, which should be possible in the account settings of your organization.")
                .foregroundStyle(.secondary)
        }
        .font(.caption)
        .fixedSize(horizontal: false, vertical: true)
        .padding(16)
        .frame(width: 320)
    }
}

// MARK: – Per-profile card

struct ProfileCard: View {
    @EnvironmentObject var vpn: VPNManager
    let profile: VPNProfile

    @State private var isExpanded     = false
    @State private var draft:          VPNProfile
    @State private var splitRoutingOn: Bool
    @State private var isSaving       = false
    @State private var saveSuccess    = false
    @State private var showError      = false
    @State private var mfaCode        = ""
    @State private var shareBlob:     String?    // non-nil → Share sheet shown
    @State private var showQRScanner       = false   // TOTP QR-import sheet
    @State private var showTOTPHelp        = false   // "2FA automation" explainer popover
    @State private var showCommandsManager = false   // "Commands through VPN" CRUD sheet
    @State private var runCommand: ScriptedCommand? = nil   // non-nil → CommandRunSheet shown

    private enum Field: Hashable { case name, host, username, password, wgConf }
    @FocusState private var focusedField: Field?

    init(profile: VPNProfile) {
        self.profile = profile
        self._draft          = State(initialValue: profile)
        self._splitRoutingOn = State(initialValue: profile.config.partialEnabled)
    }

    private var status:     ConnectionStatus { vpn.status(for: profile) }
    private var errorMsg:   String?          { vpn.errors[profile.id] }
    private var mfaPending: MFAChallenge?    { vpn.mfaChallenges[profile.id] }
    private var hasChanges: Bool             { draft != profile }
    private var connectionLost: Bool         { vpn.connectionLost.contains(profile.id) }
    private var keychainLoadFailed: Bool     { vpn.keychainLoadFailures.contains(profile.id) }
    private var shouldShowAlertPanel: Bool   {
        errorMsg != nil || connectionLost || keychainLoadFailed
    }

    var body: some View {
        VStack(spacing: 0) {
            summaryRow
            if shouldShowAlertPanel {
                Divider()
                alertPanel
            }
            if let challenge = mfaPending {
                Divider()
                mfaSection(challenge)
            }
            if showKillSwitchGap {
                Divider()
                killSwitchGapPanel
            }
            if let report = vpn.appliedRoutes[profile.id], status == .connected {
                Divider()
                appliedRoutesNote(report, stats: vpn.sessionStats[profile.id])
            }
            if isExpanded {
                Divider()
                editForm
            }
        }
        .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.2)))
        .animation(.spring(duration: 0.2), value: isExpanded)
        .animation(.spring(duration: 0.2), value: mfaPending != nil)
        .animation(.spring(duration: 0.2), value: vpn.appliedRoutes[profile.id])
        .animation(.spring(duration: 0.2), value: showKillSwitchGap)
        .animation(.spring(duration: 0.2), value: shouldShowAlertPanel)
        .onChange(of: profile) { newProfile in
            if !isExpanded {
                draft = newProfile
                splitRoutingOn = newProfile.config.partialEnabled
            }
        }
        .onAppear {
            if vpn.newlyAddedProfileID == profile.id {
                isExpanded = true
                vpn.newlyAddedProfileID = nil
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
                    focusedField = .name
                }
            }
            if vpn.newlyImportedProfileID == profile.id {
                isExpanded = true
                vpn.newlyImportedProfileID = nil
                if let target = firstMissingField {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
                        focusedField = target
                    }
                }
            }
        }
    }

    private func saveDraftIfChanged() {
        draft.normalizeServerAddress()
        guard hasChanges, saveAllowed else { return }
        Task { await vpn.save(profile: draft) }
    }

    @ViewBuilder
    private func appliedRoutesNote(_ report: AppliedRoutesReport,
                                   stats: TransferStats? = nil) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: appliedIcon(report))
                .font(.caption2).foregroundStyle(appliedColor(report))
            VStack(alignment: .leading, spacing: 2) {
                if report.source != .full, !(report.routes.isEmpty && report.resolvedHostRoutes.isEmpty) {
                    let domains = DomainRouteResolver.hostnames(from: profile.config.tunnelDomains)
                    let items = report.routes + domains
                    (Text(appliedTitle(report) + " ")
                        .font(.caption2).foregroundColor(.primary)
                     + Text(items.joined(separator: ", "))
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundColor(.secondary))
                        .lineLimit(1)
                        .truncationMode(.tail)
                        .textSelection(.enabled)
                } else {
                    Text(appliedTitle(report))
                        .font(.caption2).foregroundStyle(.primary)
                }
                if !report.dnsSuffixes.isEmpty && report.source != .full {
                    Text("DNS for " + report.dnsSuffixes.map { "*.\($0)" }.joined(separator: ", ") + " via VPN")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if report.source == .full {
                    let carried = !report.ipv6Routes.isEmpty && vpn.ipv6RoutedViaTunnel
                    let claimedButNotRouted = !report.ipv6Routes.isEmpty && !vpn.ipv6RoutedViaTunnel
                    Text(carried ? "IPv6 via VPN"
                         : claimedButNotRouted ? "IPv6 blocked: the system did not route it through the VPN"
                         : "IPv6 blocked: this server offers no IPv6")
                        .font(.caption2)
                        .foregroundStyle(claimedButNotRouted ? Color.orange : Color.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if !report.explanation.isEmpty,
                   report.source == .auto || report.source == .full {
                    Text(report.explanation)
                        .font(.caption2).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let conflict = report.routeConflictWarning {
                    Label(conflict, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption2).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let s = stats {
                    HStack(spacing: 10) {
                        Label(formatBytes(s.bytesSent),     systemImage: "arrow.up")
                        Label(formatBytes(s.bytesReceived), systemImage: "arrow.down")
                    }
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10).padding(.vertical, 6)
    }

    private func formatBytes(_ n: UInt64) -> String {
        switch n {
        case 0..<1_000:                  return "\(n) B"
        case 1_000..<1_000_000:          return String(format: "%.1f KB", Double(n) / 1_000)
        case 1_000_000..<1_000_000_000:  return String(format: "%.1f MB", Double(n) / 1_000_000)
        default:                         return String(format: "%.2f GB", Double(n) / 1_000_000_000)
        }
    }

    private func appliedIcon(_ r: AppliedRoutesReport) -> String {
        switch r.source {
        case .server: return "checkmark.seal.fill"
        case .auto:   return "wand.and.stars"
        case .manual: return "list.bullet"
        case .full:   return "globe"
        }
    }
    private func appliedColor(_ r: AppliedRoutesReport) -> Color {
        switch r.source {
        case .server: return .green
        case .auto:   return .blue
        case .manual: return .secondary
        case .full:   return .secondary
        }
    }
    private func appliedTitle(_ r: AppliedRoutesReport) -> String {
        switch r.source {
        case .full:                     return "All traffic via VPN"
        case .server, .auto, .manual:   return "Tunneling these networks:"
        }
    }

    // MARK: – Alert panel (errors + connection-lost warning)

    @ViewBuilder
    private var alertPanel: some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.caption2).foregroundStyle(alertColor)
            VStack(alignment: .leading, spacing: 2) {
                Text(alertTitle)
                    .font(.caption2).foregroundStyle(.primary)
                if let summary = alertSummary {
                    Text(summary)
                        .font(.caption2).foregroundStyle(.secondary)
                        .lineLimit(2).truncationMode(.tail)
                        .fixedSize(horizontal: false, vertical: true)
                }
                HStack(spacing: 8) {
                    if errorMsg != nil {
                        Button("View logs") { showError = true }
                            .buttonStyle(.borderless)
                            .controlSize(.small)
                            .popover(isPresented: $showError, arrowEdge: .bottom) {
                                ScrollView {
                                    Text(errorMsg ?? "")
                                        .font(.system(.caption, design: .monospaced))
                                        .textSelection(.enabled)
                                        .padding(12)
                                        .frame(minWidth: 360, maxWidth: 360, alignment: .leading)
                                }
                                .frame(maxHeight: 280)
                            }
                    }
                    if connectionLost && status == .disconnected {
                        Button("Reconnect") { vpn.connect(profile) }
                            .buttonStyle(.borderless)
                            .controlSize(.small)
                        Button("Dismiss") { vpn.dismissConnectionLost(profile) }
                            .buttonStyle(.borderless)
                            .controlSize(.small)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10).padding(.vertical, 6)
    }

    private var showKillSwitchGap: Bool {
        status == .connected && vpn.killSwitchEnabled && vpn.killSwitchPending && isFullTunnel
    }

    private var isFullTunnel: Bool {
        if vpn.fullTunnelOverrides.contains(profile.id) { return true }
        if let r = vpn.appliedRoutes[profile.id] { return r.source == .full }
        return !profile.config.partialEnabled
    }

    @ViewBuilder
    private var killSwitchGapPanel: some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: "lock.open.trianglebadge.exclamationmark")
                .font(.caption2).foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text("Kill switch not active")
                    .font(.caption2).foregroundStyle(.primary)
                Text("This tunnel became full after it connected, so traffic is not strictly forced through the VPN. Reconnecting applies it.")
                    .font(.caption2).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Button("Reconnect to apply") { vpn.applyKillSwitchNow() }
                    .buttonStyle(.borderless)
                    .controlSize(.small)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10).padding(.vertical, 6)
    }

    private var alertColor: Color {
        errorMsg != nil ? .red : .orange
    }

    private var alertTitle: String {
        if errorMsg != nil       { return "Connection failed" }
        if keychainLoadFailed    { return "Saved credentials unavailable" }
        return "Connection lost"
    }

    private var alertSummary: String? {
        if let err = errorMsg {
            return err.split(whereSeparator: { $0.isNewline })
                      .first { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
                      .map(String.init)
        }
        if keychainLoadFailed {
            return "velun couldn't read this profile's password from the system Keychain at startup. Quit and relaunch velun to retry."
        }
        if connectionLost {
            return "The VPN tunnel dropped. The link may be down or the server may have closed the session."
        }
        return nil
    }

    // MARK: – Summary row

    private var summaryRow: some View {
        HStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(width: 16)
                statusDot
                Text(profile.name.isEmpty ? "Unnamed" : profile.name)
                    .font(.subheadline).fontWeight(.medium)
                    .lineLimit(1).foregroundStyle(.primary)
            }

            Spacer()

            if status == .connected && profile.config.partialEnabled {
                tunnelModeMenu
            } else {
                Text(summaryStatusLabel).font(.caption2).foregroundStyle(.secondary)
            }

            commandsMenu
            connectButton
        }
        .padding(.horizontal, 10).padding(.vertical, 8)
        .contentShape(Rectangle())
        .onTapGesture { toggleExpand() }
    }

    private func toggleExpand() {
        if isExpanded { saveDraftIfChanged() }
        withAnimation { isExpanded.toggle() }
        if isExpanded { draft = profile }
    }

    @ViewBuilder
    private var commandsMenu: some View {
        if !profile.scriptedCommands.isEmpty, profile.provider != .wireguard {
            Menu {
                ForEach(profile.scriptedCommands) { cmd in
                    Button(cmd.name.isEmpty ? "Untitled" : cmd.name) {
                        runCommand = cmd
                    }
                }
                Divider()
                Button("Manage commands…") { showCommandsManager = true }
            } label: {
                Image(systemName: "terminal")
                    .foregroundStyle(.secondary)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .help("Run a saved command through this VPN")
        }
    }

    private var summaryStatusLabel: String {
        if shouldShowAlertPanel { return "" }
        return status.label
    }

    @ViewBuilder
    private var tunnelModeMenu: some View {
        if vpn.fullTunnelOverrides.contains(profile.id) {
            Menu {
                Button("Restore split routing") { vpn.reconnectWithSplits(profile) }
            } label: {
                Text("Full").font(.caption2).foregroundStyle(.blue)
            }
            .menuStyle(.borderlessButton).fixedSize()
        } else {
            Menu {
                Button("Route all traffic") { vpn.reconnectAsFull(profile) }
            } label: {
                Text("Partial").font(.caption2).foregroundStyle(.orange)
            }
            .menuStyle(.borderlessButton).fixedSize()
        }
    }

    private var statusDot: some View {
        Circle().fill(dotColor).frame(width: 8, height: 8)
    }

    private var dotColor: Color {
        switch status {
        case .connected:                              return .green
        case .connecting,.disconnecting,.reconnecting: return .yellow
        case .failed:                                 return .red
        case .disconnected:
            if errorMsg != nil       { return .red }
            if connectionLost        { return .orange }
            return .secondary
        }
    }

    private func expandToFirstMissingField() {
        if !isExpanded {
            draft = profile
            withAnimation { isExpanded = true }
        }
        let target = firstMissingField
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            focusedField = target
        }
    }

    private var firstMissingField: Field? {
        switch (isExpanded ? draft.config : profile.config) {
        case .sslVPN(let oc):
            if oc.host.isEmpty     { return .host }
            if oc.username.isEmpty { return .username }
            if oc.password.isEmpty { return .password }
            return nil
        case .wireguard(let wg):
            return wg.confText.isEmpty ? .wgConf : nil
        }
    }

    private var missingRequiredFields: Set<Field> {
        guard !canConnect else { return [] }
        switch draft.config {
        case .sslVPN(let oc):
            var s: Set<Field> = []
            if oc.host.isEmpty     { s.insert(.host) }
            if oc.username.isEmpty { s.insert(.username) }
            if oc.password.isEmpty { s.insert(.password) }
            return s
        case .wireguard:
            return []
        }
    }

    private var canConnect: Bool {
        let cfg = isExpanded ? draft.config : profile.config
        switch cfg {
        case .sslVPN(let oc):
            return !oc.host.isEmpty && !oc.username.isEmpty && !oc.password.isEmpty
        case .wireguard(let wg):
            return !wg.confText.isEmpty
        }
    }

    private var canConnectReason: String? {
        if canConnect { return nil }
        if keychainLoadFailed {
            return "velun couldn't read this profile's saved password from the system Keychain at startup. Quit and relaunch velun."
        }
        let cfg = isExpanded ? draft.config : profile.config
        switch cfg {
        case .sslVPN(let oc):
            var missing: [String] = []
            if oc.host.isEmpty     { missing.append("server") }
            if oc.username.isEmpty { missing.append("username") }
            if oc.password.isEmpty { missing.append("password") }
            guard !missing.isEmpty else { return nil }
            return "Expand this profile and fill in: " + missing.joined(separator: ", ") + "."
        case .wireguard(let wg):
            if wg.confText.isEmpty {
                return "Expand this profile and paste a WireGuard .conf to enable Connect."
            }
            return nil
        }
    }

    private var connectButton: some View {
        Group {
            if status.canDisconnect {
                Button("Disconnect") { vpn.userDisconnect(profile) }
                    .foregroundStyle(.red)
            } else {
                Button("Connect") {
                    guard canConnect else {
                        if !keychainLoadFailed { expandToFirstMissingField() }
                        return
                    }
                    if isExpanded {
                        saveDraftIfChanged()
                        withAnimation { isExpanded = false }
                    }
                    let target = hasChanges ? draft : profile
                    vpn.connect(target)
                }
                .opacity(canConnect ? 1 : 0.55)
                .help(canConnectReason ?? "")
            }
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
    }

    // MARK: – MFA section

    private func mfaSection(_ challenge: MFAChallenge) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(challenge.prompt)
                .font(.caption).foregroundStyle(.secondary)
            HStack(alignment: .top, spacing: 4) {
                Text("Tip: add a TOTP secret in the settings to skip this step automatically.")
                    .font(.caption2).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
                Button { showTOTPHelp = true } label: {
                    Image(systemName: "questionmark.circle")
                }
                .buttonStyle(.plain)
                .help("How does this work?")
                .popover(isPresented: $showTOTPHelp, arrowEdge: .bottom) {
                    TOTPHelpPopover(showsQRButton: false)
                }
            }
            HStack(spacing: 6) {
                SecureField("Verification code", text: $mfaCode)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { submitMFA() }
                Button("Submit") { submitMFA() }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                    .disabled(mfaCode.isEmpty)
            }
        }
        .padding(.horizontal, 10).padding(.vertical, 8)
    }

    private func submitMFA() {
        guard !mfaCode.isEmpty else { return }
        vpn.submitMFA(for: profile, code: mfaCode)
        mfaCode = ""
    }

    // MARK: – Edit form

    private var editForm: some View {
        VStack(alignment: .leading, spacing: 8) {

            HStack(spacing: 6) {
                Button {
                    draft.normalizeServerAddress()
                    isSaving = true
                    Task {
                        await vpn.save(profile: draft)
                        await MainActor.run { isSaving = false; saveSuccess = true }
                        try? await Task.sleep(nanoseconds: 1_500_000_000)
                        await MainActor.run { saveSuccess = false }
                    }
                } label: {
                    if isSaving         { Label("Saving",  systemImage: "arrow.clockwise") }
                    else if saveSuccess { Label("Saved",   systemImage: "checkmark") }
                    else                { Label("Save",    systemImage: "square.and.arrow.down") }
                }
                .disabled(isSaving || saveSuccess || !saveAllowed)
                .help("Save this connection")

                if hasChanges && !saveSuccess {
                    Button("Cancel") {
                        draft = profile
                        splitRoutingOn = !profile.config.splitRoutes.isEmpty
                        withAnimation { isExpanded = false }
                    }
                }

                Spacer()

                if profile.provider != .wireguard {
                    Button { showCommandsManager = true } label: {
                        Label(commandsButtonLabel, systemImage: "terminal")
                    }
                    .help("Set up commands to run through this VPN")
                }

                Menu {
                    Button("Share…") { exportProfile(includeCredentials: false) }
                    Button("Export with credentials…") { exportProfile(includeCredentials: true) }
                } label: {
                    Image(systemName: "square.and.arrow.up")
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .help("Export this connection")

                Button(role: .destructive) { vpn.removeProfile(profile) } label: {
                    Image(systemName: "trash")
                }
                .help("Delete this connection")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)

            Divider()

            HStack(alignment: .top, spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Name").font(.caption).foregroundStyle(.secondary)
                    TextField("My VPN", text: $draft.name)
                        .textFieldStyle(.roundedBorder)
                        .focused($focusedField, equals: .name)
                        .onChange(of: draft.name) { v in
                            let clean = v.components(separatedBy: .newlines).joined()
                            if clean != v { draft.name = clean }
                        }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Protocol").font(.caption).foregroundStyle(.secondary)
                    Picker("", selection: providerBinding) {
                        ForEach(ProviderType.allCases) { t in Text(t.displayName).tag(t) }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            if draft.provider == .fortinet || draft.provider == .globalProtect {
                Label(
                    "\(draft.provider.displayName) support is experimental: we lack test servers for it. Please contact the app author if you'd like to use it or help test it.",
                    systemImage: "exclamationmark.triangle.fill"
                )
                .font(.caption)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
            }

            switch draft.config {
            case .sslVPN:
                sslVPNFields
            case .wireguard:
                wireguardFields
            }

            splitRoutingSection
        }
        .padding(10)
        .sheet(item: Binding(
            get: { shareBlob.map { ShareBlob(text: $0) } },
            set: { shareBlob = $0?.text }
        )) { sb in
            ShareBlobSheet(blob: sb.text)
        }
        .sheet(isPresented: $showQRScanner) {
            QRScannerSheet { account in
                let oc = sslVPNBinding
                oc.totpSecret.wrappedValue = "base32:\(account.secretBase32)"
            }
        }
        .sheet(isPresented: $showCommandsManager) {
            CommandsManagerSheet(profileID: profile.id)
                .environmentObject(vpn)
        }
        .sheet(item: $runCommand) { cmd in
            CommandRunSheet(profile: profile, command: cmd)
        }
    }

    private var commandsButtonLabel: String {
        profile.scriptedCommands.isEmpty ? "Commands…" : "Commands"
    }

    private var saveAllowed: Bool {
        switch draft.config {
        case .sslVPN(let oc): return !oc.host.isEmpty
        case .wireguard(let wg):   return !wg.confText.isEmpty
        }
    }

    private var providerBinding: Binding<ProviderType> {
        Binding(
            get: { draft.provider },
            set: { newType in
                draft.provider = newType
                let wantsWG = (newType == .wireguard)
                let isWG = (draft.config.wireguard != nil)
                if wantsWG && !isWG {
                    draft.config = .wireguard(WireGuardConfig())
                } else if !wantsWG && isWG {
                    draft.config = .sslVPN(SSLVPNFamilyConfig())
                }
            }
        )
    }

    // MARK: – SSL-VPN-family fields

    @ViewBuilder
    private var sslVPNFields: some View {
        let oc = sslVPNBinding
        HStack(alignment: .top, spacing: 8) {
            field("Server", value: oc.host, placeholder: "vpn.example.com", focus: .host,
                  missing: missingRequiredFields.contains(.host))
                .frame(maxWidth: .infinity, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text("Port").font(.caption).foregroundStyle(.secondary)
                TextField("443", text: oc.portText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 64)
            }
        }
        HStack(alignment: .top, spacing: 8) {
            field("Username", value: oc.username, placeholder: "username", focus: .username,
                  missing: missingRequiredFields.contains(.username))
                .frame(maxWidth: .infinity, alignment: .leading)
            field("Group", value: oc.group, placeholder: "(optional)")
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        secureField("Password", value: oc.password, focus: .password,
                    missing: missingRequiredFields.contains(.password))
        VStack(alignment: .leading, spacing: 2) {
            Text("2FA automation (TOTP secret)").font(.caption).foregroundStyle(.secondary)
            HStack(spacing: 6) {
                SecureField("••••••••", text: oc.totpSecret)
                    .textFieldStyle(.roundedBorder)
                    .onChange(of: oc.totpSecret.wrappedValue) { v in
                        let clean = v.components(separatedBy: .newlines).joined()
                        if clean != v { oc.totpSecret.wrappedValue = clean }
                    }
                Button { showQRScanner = true } label: {
                    Image(systemName: "qrcode.viewfinder")
                }
                .buttonStyle(.bordered)
                .help("Scan a TOTP QR code with the camera")
                Button { showTOTPHelp = true } label: {
                    Image(systemName: "questionmark.circle")
                }
                .buttonStyle(.bordered)
                .help("How does this work?")
                .popover(isPresented: $showTOTPHelp, arrowEdge: .bottom) {
                    TOTPHelpPopover()
                }
            }
            Text("base32:XXX… or scan the export 2FA QR from your Authenticator app.")
                .font(.caption2).foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
        clientCertRow
    }

    @ViewBuilder
    private var clientCertRow: some View {
        let name = draft.sslVPNFamily.clientCertName
        VStack(alignment: .leading, spacing: 2) {
            Text("Client certificate").font(.caption).foregroundStyle(.secondary)
            HStack(spacing: 6) {
                Text(name.isEmpty ? "None" : name)
                    .font(.caption)
                    .foregroundStyle(name.isEmpty ? .secondary : .primary)
                    .lineLimit(1).truncationMode(.middle)
                Spacer()
                Button(name.isEmpty ? "Import .p12…" : "Replace…") { importClientCert() }
                    .controlSize(.small)
                if !name.isEmpty {
                    Button { removeClientCert() } label: { Image(systemName: "trash") }
                        .controlSize(.small)
                        .help("Remove the client certificate")
                }
            }
            Text("Only for VPNs that require a certificate. Import a .p12 (certificate + private key), exported from Keychain Access.")
                .font(.caption2).foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// Pick a .p12 file, prompt for its password, and stash it on the draft.
    private func importClientCert() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.pkcs12]
        panel.allowsMultipleSelection = false
        panel.title = "Choose a client certificate (.p12)"
        guard panel.runModal() == .OK, let url = panel.url,
              let data = try? Data(contentsOf: url) else { return }
        let alert = NSAlert()
        alert.messageText = "Certificate password"
        alert.informativeText = "Enter the password for \(url.lastPathComponent). Leave blank if it has none."
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 240, height: 24))
        alert.accessoryView = field
        alert.addButton(withTitle: "Import")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        guard case .sslVPN(var oc) = draft.config else { return }
        oc.clientCertName     = url.lastPathComponent
        oc.clientCertP12      = data.base64EncodedString()
        oc.clientCertPassword = field.stringValue
        draft.config = .sslVPN(oc)
    }

    private func removeClientCert() {
        guard case .sslVPN(var oc) = draft.config else { return }
        oc.clientCertName = ""; oc.clientCertP12 = ""; oc.clientCertPassword = ""
        draft.config = .sslVPN(oc)
    }

    private var sslVPNBinding: BoundSSLVPN {
        BoundSSLVPN(draft: $draft)
    }

    // MARK: – WireGuard fields

    @ViewBuilder
    private var wireguardFields: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("WireGuard configuration").font(.caption).foregroundStyle(.secondary)
            TextEditor(text: wgConfBinding)
                .font(.system(.caption, design: .monospaced))
                .frame(minHeight: 140, maxHeight: 220)
                .focused($focusedField, equals: .wgConf)
                .overlay(RoundedRectangle(cornerRadius: 4).stroke(Color.secondary.opacity(0.3)))
            Text("Paste the contents of a `wg-quick` `.conf` file (Interface + Peer sections).")
                .font(.caption2).foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var wgConfBinding: Binding<String> {
        Binding(
            get: { draft.wireguard.confText },
            set: { v in draft.wireguard = WireGuardConfig(confText: v,
                                                          splitRoutes: draft.wireguard.splitRoutes,
                                                          partialEnabled: draft.wireguard.partialEnabled) }
        )
    }

    private func exportProfile(includeCredentials: Bool) {
        shareBlob = vpn.exportBlob(includeCredentials: includeCredentials,
                                   profiles: [profile])
    }

    // MARK: – Split routing section

    private var splitRoutingSection: some View {
        VStack(alignment: .leading, spacing: 3) {
            Toggle(isOn: splitRoutingBinding) {
                Text("Split routing").font(.caption).foregroundStyle(.secondary)
            }
            .toggleStyle(.checkbox)

            if splitRoutingOn {
                let isWG = draft.config.wireguard != nil
                let routesEmpty = draft.config.splitRoutes
                    .trimmingCharacters(in: .whitespacesAndNewlines).isEmpty

                TextField(autoDetectPlaceholder, text: splitRoutesBinding)
                    .textFieldStyle(.roundedBorder)

                if !isWG && routesEmpty {
                    HStack(alignment: .top, spacing: 4) {
                        Image(systemName: "wand.and.stars")
                            .font(.caption2).foregroundStyle(.blue)
                        Text("Suggest subnets from VPN server hints (X-CSTP-SPLIT-INCLUDE, " +
                             "fallback to /16 of each VPN-DNS server and search domain). " +
                             "If services are unreachable, add CIDRs manually here.")
                            .font(.caption2).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } else if isWG && routesEmpty {
                    Text("Use AllowedIPs as written in the WireGuard configuration.")
                        .font(.caption2).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    Text(isWG
                         ? "Override AllowedIPs in the conf for partial-tunnel routing"
                         : "Comma-separated domains to be routed through the VPN")
                        .font(.caption2).foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                if !isWG {
                    TextField("Example: portal.example.org,mail.example.org",
                              text: tunnelDomainsBinding)
                        .textFieldStyle(.roundedBorder)
                }
            } else {
                HStack(alignment: .top, spacing: 4) {
                    Image(systemName: "lock.shield")
                        .font(.caption2).foregroundStyle(.blue)
                    Text("Full tunnel: every app is forced through the VPN, and all traffic " +
                         "is blocked if the tunnel drops, with no leaks to your real network.")
                        .font(.caption2).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private var autoDetectPlaceholder: String {
        draft.config.wireguard != nil
            ? "(blank → use AllowedIPs from conf)"
            : "(blank → suggest from server hints)   or   129.132.0.0/16,10.0.0.0/8"
    }

    private var splitRoutesBinding: Binding<String> {
        Binding(
            get: { draft.config.splitRoutes },
            set: { v in
                let clean = v.components(separatedBy: .newlines).joined()
                draft.config.splitRoutes = clean
            }
        )
    }

    private var tunnelDomainsBinding: Binding<String> {
        Binding(
            get: { draft.config.tunnelDomains },
            set: { v in
                let clean = v.components(separatedBy: .newlines).joined()
                draft.config.tunnelDomains = clean
            }
        )
    }

    private var splitRoutingBinding: Binding<Bool> {
        Binding(
            get: { splitRoutingOn },
            set: { on in
                splitRoutingOn = on
                draft.config.partialEnabled = on
                if !on {
                    draft.config.splitRoutes = ""
                    draft.config.tunnelDomains = ""
                }
            }
        )
    }

    // MARK: – Field builders

    private func field(_ label: String, value: Binding<String>,
                       placeholder: String = "", help: String? = nil,
                       focus: Field? = nil, missing: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(missing ? "\(label) (required)" : label)
                .font(.caption).foregroundStyle(missing ? .red : .secondary)
            Group {
                if let focus {
                    TextField(placeholder, text: value)
                        .focused($focusedField, equals: focus)
                } else {
                    TextField(placeholder, text: value)
                }
            }
            .textFieldStyle(.roundedBorder)
            .overlay(RoundedRectangle(cornerRadius: 5).stroke(Color.red.opacity(missing ? 0.6 : 0)))
            .onChange(of: value.wrappedValue) { v in
                let clean = v.components(separatedBy: .newlines).joined()
                if clean != v { value.wrappedValue = clean }
            }
            if let h = help {
                Text(h).font(.caption2).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func secureField(_ label: String, value: Binding<String>,
                             help: String? = nil, focus: Field? = nil, missing: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(missing ? "\(label) (required)" : label)
                .font(.caption).foregroundStyle(missing ? .red : .secondary)
            Group {
                if let focus {
                    SecureField("••••••••", text: value)
                        .focused($focusedField, equals: focus)
                } else {
                    SecureField("••••••••", text: value)
                }
            }
            .textFieldStyle(.roundedBorder)
            .overlay(RoundedRectangle(cornerRadius: 5).stroke(Color.red.opacity(missing ? 0.6 : 0)))
            .onChange(of: value.wrappedValue) { v in
                let clean = v.components(separatedBy: .newlines).joined()
                if clean != v { value.wrappedValue = clean }
            }
            if let h = help {
                Text(h).font(.caption2).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct BoundSSLVPN {
    let draft: Binding<VPNProfile>

    private func read() -> SSLVPNFamilyConfig { draft.wrappedValue.sslVPNFamily }
    private func write(_ mut: (inout SSLVPNFamilyConfig) -> Void) {
        var c = read()
        mut(&c)
        var p = draft.wrappedValue
        p.sslVPNFamily = c
        draft.wrappedValue = p
    }

    var host: Binding<String> { Binding(get: { read().host }, set: { v in write { $0.host = v } }) }

    var portText: Binding<String> {
        Binding(
            get: { let p = read().port; return p == 443 ? "" : String(p) },
            set: { v in
                let digits = v.filter(\.isNumber)
                let p = digits.isEmpty ? 443 : min(max(Int(digits) ?? 443, 1), 65535)
                write { $0.port = p }
            }
        )
    }

    var username: Binding<String> { Binding(get: { read().username }, set: { v in write { $0.username = v } }) }
    var password: Binding<String> { Binding(get: { read().password }, set: { v in write { $0.password = v } }) }
    var group: Binding<String> { Binding(get: { read().group }, set: { v in write { $0.group = v } }) }
    var totpSecret: Binding<String> { Binding(get: { read().totpSecret }, set: { v in write { $0.totpSecret = v } }) }
}
