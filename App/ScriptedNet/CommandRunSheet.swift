import SwiftUI
import OSLog

private let log = Logger(subsystem: "com.manueldeprada.velun", category: "ScriptedNet.UI")

struct CommandRunSheet: View {
    let profile: VPNProfile
    let command: ScriptedCommand

    @Environment(\.dismiss) private var dismiss

    @State private var output: String = ""
    @State private var exitCode: Int32?
    @State private var isRunning = false
    @State private var errorBanner: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(command.name).font(.title3).fontWeight(.semibold)
                    Text("\(command.targetHost):\(command.targetPort) via \(profile.name)")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }

            Text(command.commandLine)
                .font(.system(.caption, design: .monospaced))
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(NSColor.controlBackgroundColor))
                .cornerRadius(4)

            if let err = errorBanner {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    Text(err).font(.caption)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(8)
                .background(Color.orange.opacity(0.08))
                .cornerRadius(6)
            }

            ScrollView {
                Text(output.isEmpty
                     ? (isRunning ? "Running…" : "Click Run to execute.")
                     : output)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(output.isEmpty ? .secondary : .primary)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
            }
            .background(Color(NSColor.textBackgroundColor))
            .overlay(RoundedRectangle(cornerRadius: 4).strokeBorder(Color.secondary.opacity(0.3)))
            .frame(minHeight: 180, idealHeight: 240, maxHeight: 380)

            HStack {
                if let code = exitCode {
                    Text("Exit code: \(code)")
                        .font(.caption).foregroundStyle(code == 0 ? .green : .red)
                }
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(isRunning ? "Running…" : "Run") { runIt() }
                    .buttonStyle(.borderedProminent)
                    .disabled(isRunning)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 560)
        .onAppear { runIt() }
    }

    private func runIt() {
        guard !isRunning else { return }
        errorBanner = nil
        output = ""
        exitCode = nil

        guard let ip = IPv4.toUInt32(command.targetHost.trimmingCharacters(in: .whitespaces)) else {
            errorBanner = "Target host must be an IPv4 literal. DNS through the tunnel isn't supported yet."
            return
        }
        guard command.targetPort > 0, command.targetPort < 65536 else {
            errorBanner = "Target port must be 1–65535."
            return
        }

        isRunning = true
        let cmd = command  // capture
        Task {
            defer { Task { @MainActor in isRunning = false } }
            do {
                let result = try await ScriptedRunner.run(
                    profile: profile,
                    forwards: [
                        ScriptedRunner.Forward(remoteIP: ip,
                                               remotePort: UInt16(cmd.targetPort),
                                               localPort: 0,
                                               envName: "TARGET"),
                    ],
                    command: ["/bin/sh", "-c", cmd.commandLine],
                    timeout: 90
                )
                await MainActor.run {
                    self.output = result.stdout +
                        (result.stderr.isEmpty ? "" : "\n--- stderr ---\n\(result.stderr)")
                    self.exitCode = result.exitCode
                }
            } catch {
                await MainActor.run {
                    self.errorBanner = error.localizedDescription
                }
            }
        }
    }
}
