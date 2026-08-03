import Foundation
import Combine
import OSLog

private let log = Logger(subsystem: "com.manueldeprada.velun", category: "StatusBroadcaster")

@MainActor
final class StatusBroadcaster {
    static let shared = StatusBroadcaster()

    private var cancellables = Set<AnyCancellable>()
    private let fileURL: URL
    private let queue = DispatchQueue(label: "velun.status-broadcaster", qos: .utility)

    private init() {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir     = support.appendingPathComponent("velun", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        fileURL = dir.appendingPathComponent("status.json")
    }

    func start() {
        let vpn = VPNManager.shared

        // Snapshot whenever any of the inputs change.
        Publishers.CombineLatest3(
            vpn.$profiles,
            vpn.$statuses,
            vpn.$errors
        )
        .combineLatest(vpn.$appliedRoutes)
        .debounce(for: .milliseconds(50), scheduler: DispatchQueue.main)
        .sink { [weak self] _ in self?.writeSnapshot() }
        .store(in: &cancellables)

        writeSnapshot()
    }

    private func writeSnapshot() {
        let vpn = VPNManager.shared
        let profiles = vpn.profiles.map { p -> [String: Any] in
            var d: [String: Any] = [
                "id":     p.id.uuidString,
                "name":   p.name,
                "status": (vpn.statuses[p.id] ?? .disconnected).cliRawValue,
            ]
            if let err = vpn.errors[p.id] { d["error"] = err }
            if let routes = vpn.appliedRoutes[p.id] {
                d["appliedRoutes"] = routes.routes
                d["routesSource"]  = routes.source.rawValue
            }
            return d
        }
        let payload: [String: Any] = [
            "updatedAt": Int(Date().timeIntervalSince1970),
            "profiles":  profiles,
        ]
        let url = fileURL
        queue.async {
            do {
                let data = try JSONSerialization.data(withJSONObject: payload,
                                                      options: [.prettyPrinted, .sortedKeys])
                try data.write(to: url, options: .atomic)
            } catch {
                log.error("Failed to write status.json: \(error.localizedDescription, privacy: .public)")
            }
        }
    }
}

private extension ConnectionStatus {
    var cliRawValue: String {
        switch self {
        case .disconnected:  return "disconnected"
        case .connecting:    return "connecting"
        case .connected:     return "connected"
        case .disconnecting: return "disconnecting"
        case .reconnecting:  return "reconnecting"
        case .failed:        return "failed"
        }
    }
}
