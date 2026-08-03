import Foundation
import Network
import OSLog

private let log = Logger(subsystem: "com.manueldeprada.velun", category: "NetworkPath")

final class NetworkPathWatcher {
    private let monitor = NWPathMonitor()
    private let queue   = DispatchQueue(label: "com.manueldeprada.velun.NetworkPath")
    private var wasSatisfied = false
    private let onPathRestored: @Sendable () -> Void

    init(onPathRestored: @escaping @Sendable () -> Void) {
        self.onPathRestored = onPathRestored
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let nowSatisfied = path.status == .satisfied
            if !self.wasSatisfied, nowSatisfied {
                let interfaces = path.availableInterfaces.map { $0.name }.joined(separator: ",")
                log.info("network path restored: interfaces=\(interfaces, privacy: .public)")
                self.onPathRestored()
            } else if self.wasSatisfied, !nowSatisfied {
                log.info("network path lost: status=\(String(describing: path.status), privacy: .public)")
            }
            self.wasSatisfied = nowSatisfied
        }
    }

    func start() {
        monitor.start(queue: queue)
    }

    func stop() {
        monitor.cancel()
    }

    deinit {
        monitor.cancel()
    }
}
