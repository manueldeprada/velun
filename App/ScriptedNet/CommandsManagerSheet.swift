import SwiftUI

struct CommandsManagerSheet: View {
    @EnvironmentObject var vpn: VPNManager
    @Environment(\.dismiss) private var dismiss

    let profileID: UUID

    @State private var draft: [ScriptedCommand] = []
    @State private var editingIndex: Int? = nil

    private var profile: VPNProfile? {
        vpn.profiles.first { $0.id == profileID }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text("Commands through VPN")
                    .font(.title3).fontWeight(.semibold)
                Spacer()
                Text(profile?.name ?? "Unnamed")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Text("Commands run through a one-shot tunnel for this connection, with no system-wide routing and no admin prompt. Use IP literals (DNS through the tunnel isn't supported yet) and reference the local forward via $TARGET / $HOST / $PORT.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if draft.isEmpty {
                emptyState
            } else {
                commandList
            }

            if let idx = editingIndex {
                Divider()
                editor(for: idx)
            }

            Divider()

            HStack {
                Button {
                    var fresh = ScriptedCommand()
                    fresh.name = "New command"
                    draft.append(fresh)
                    editingIndex = draft.count - 1
                } label: {
                    Label("Add command", systemImage: "plus")
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") {
                    persist()
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(!isValid)
            }
        }
        .padding(20)
        .frame(width: 540, height: 480)
        .onAppear { draft = profile?.scriptedCommands ?? [] }
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Image(systemName: "terminal")
                .font(.largeTitle).foregroundStyle(.secondary)
            Text("No commands yet").font(.headline)
            Text("Add one to run a shell command through this VPN without a system-wide tunnel.")
                .font(.caption).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }

    private var commandList: some View {
        ScrollView {
            VStack(spacing: 4) {
                ForEach(draft.indices, id: \.self) { i in
                    commandRow(i)
                }
            }
        }
        .frame(maxWidth: .infinity)
    }

    private func commandRow(_ i: Int) -> some View {
        HStack(spacing: 8) {
            Image(systemName: editingIndex == i ? "pencil" : "terminal")
                .foregroundStyle(.secondary)
                .frame(width: 16)
            VStack(alignment: .leading, spacing: 1) {
                Text(draft[i].name.isEmpty ? "Untitled" : draft[i].name)
                    .font(.subheadline)
                Text("\(draft[i].targetHost):\(draft[i].targetPort)  \(draft[i].commandLine)")
                    .font(.caption2).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.tail)
            }
            Spacer()
            Button {
                editingIndex = (editingIndex == i) ? nil : i
            } label: {
                Image(systemName: editingIndex == i ? "chevron.up" : "pencil")
            }
            .buttonStyle(.borderless)
            Button(role: .destructive) {
                draft.remove(at: i)
                if editingIndex == i { editingIndex = nil }
                else if let e = editingIndex, e > i { editingIndex = e - 1 }
            } label: {
                Image(systemName: "trash")
            }
            .buttonStyle(.borderless)
        }
        .padding(.horizontal, 10).padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(editingIndex == i
                      ? Color.accentColor.opacity(0.08)
                      : Color(NSColor.controlBackgroundColor))
        )
    }

    @ViewBuilder
    private func editor(for i: Int) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Name").font(.caption).foregroundStyle(.secondary)
                    TextField("ssh dev-box", text: $draft[i].name)
                        .textFieldStyle(.roundedBorder)
                }
                VStack(alignment: .leading, spacing: 3) {
                    Text("Target host").font(.caption).foregroundStyle(.secondary)
                    TextField("10.0.0.5", text: $draft[i].targetHost)
                        .textFieldStyle(.roundedBorder)
                }
                .frame(width: 140)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Port").font(.caption).foregroundStyle(.secondary)
                    TextField("22", value: $draft[i].targetPort, format: .number)
                        .textFieldStyle(.roundedBorder)
                }
                .frame(width: 70)
            }
            VStack(alignment: .leading, spacing: 3) {
                Text("Command").font(.caption).foregroundStyle(.secondary)
                TextField("/usr/bin/ssh -p $PORT user@127.0.0.1",
                          text: $draft[i].commandLine)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
            }
            Text("Tip: $HOST and $PORT are set to the local forward; $TARGET is \"127.0.0.1:$PORT\". Run via /bin/sh -c so shell features work.")
                .font(.caption2).foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var isValid: Bool {
        draft.allSatisfy {
            !$0.name.trimmingCharacters(in: .whitespaces).isEmpty
            && !$0.targetHost.trimmingCharacters(in: .whitespaces).isEmpty
            && $0.targetPort > 0 && $0.targetPort < 65536
            && !$0.commandLine.trimmingCharacters(in: .whitespaces).isEmpty
        }
    }

    private func persist() {
        guard var p = profile else { return }
        p.scriptedCommands = draft
        vpn.updateProfile(p)
    }
}
