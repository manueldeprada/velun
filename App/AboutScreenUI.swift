import SwiftUI

// MARK: – About popover

struct AboutPopover: View {
    @EnvironmentObject var about: AboutScreenManager
    @EnvironmentObject var updater: UpdaterManager
    var onViewChangelog: () -> Void = {}

    private var currentYear: String {
        let f = DateFormatter(); f.dateFormat = "yyyy"
        return f.string(from: Date())
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("velun").font(.headline)
            Text("Version: \(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0")")
                .font(.caption)
            if let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String {
                Text("Build: \(build)").font(.caption).foregroundStyle(.secondary)
            }
            Text("© \(currentYear) Manuel de Prada Corral").font(.caption2).foregroundStyle(.secondary)
            Text(about.statusLabel).font(.caption2).foregroundStyle(.secondary)
            Divider()
            Text("A random ID is used to count unique installations. It cannot be linked to you.")
                .font(.caption2)
                .foregroundStyle(.secondary)
            Divider()
            HStack {
                Button("Check for Updates…") { updater.checkForUpdates() }
                Button("View Changelog…") { onViewChangelog() }
            }
            .controlSize(.small)
        }
        .padding(16)
        .frame(width: 280)
    }
}

struct AboutScreenGateView: View {
    @EnvironmentObject var about: AboutScreenManager
    @State private var showSheet = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: "lock.shield.fill")
                    .font(.title2).foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Trial ended").font(.headline)
                    Text("Enter a license key to continue using velun.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }

            Text(about.statusLabel).font(.caption2).foregroundStyle(.tertiary)

            HStack {
                Button("Enter License Key") { showSheet = true }
                    .buttonStyle(.bordered)
                Spacer()
                Button("Buy a license") {
                    if let url = URL(string: "https://store.manueldeprada.com/velun/buy.php") {
                        NSWorkspace.shared.open(url)
                    }
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(width: 380, height: 180)
        .sheet(isPresented: $showSheet) {
            AboutScreenEntrySheet().environmentObject(about)
        }
    }
}

struct AboutScreenEntrySheet: View {
    @EnvironmentObject var about: AboutScreenManager
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @State private var feedback: String?
    @State private var isError = false
    @State private var isActivating = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(about.hasLicense ? "Manage License" : "Enter License Key")
                .font(.headline)

            if about.hasLicense {
                Text(about.statusLabel).font(.caption).foregroundStyle(.secondary)
                Divider()
            }

            Text("You can use velun for free, but buying a license is highly appreciated as it covers development costs, like the Apple Developer Program.\n\nAfter buying, the velun website opens with a one-click activation button. If you'd rather paste the key by hand, drop it into the box below.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if !about.hasLicense {
                HStack {
                    Button("Buy a license") {
                        if let url = URL(string: "https://store.manueldeprada.com/velun/buy.php") {
                            NSWorkspace.shared.open(url)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    Spacer()
                }
            }

            TextEditor(text: $text)
                .font(.system(.caption, design: .monospaced))
                .frame(minHeight: 110)
                .overlay(RoundedRectangle(cornerRadius: 4).stroke(Color.secondary.opacity(0.3)))

            if let f = feedback {
                Text(f).font(.caption2).foregroundStyle(isError ? .red : .green)
            }

            HStack {
                Button("Cancel") { dismiss() }
                Spacer()
                if about.hasLicense {
                    Button("Remove License", role: .destructive) {
                        about.removeLicense()
                        dismiss()
                    }
                }
                Button(isActivating ? "Activating…" : "Activate") { Task { await submit() } }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isActivating)
            }
        }
        .padding(20)
        .frame(width: 460)
    }

    private func submit() async {
        isActivating = true
        defer { isActivating = false }
        switch await about.submitLicense(text) {
        case .ok:
            feedback = "License activated."
            isError = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { dismiss() }
        case .signatureInvalid:
            feedback = "Invalid signature. Make sure you copied the entire blob."
            isError = true
        case .expired:
            feedback = "This license has expired. Please request a renewal."
            isError = true
        case .serverRejected:
            feedback = "This license is already activated on too many devices. Contact eu@manueldeprada.com to reset."
            isError = true
        case .parseError(let m):
            feedback = "Couldn't read license: \(m)"
            isError = true
        }
    }
}
