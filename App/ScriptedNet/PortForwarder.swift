import Foundation
import Network
import OSLog

private let log = Logger(subsystem: "com.manueldeprada.velun", category: "ScriptedNet.PortForward")

final class PortForwarder {

    let remoteIP: UInt32
    let remotePort: UInt16
    private(set) var localPort: UInt16 = 0

    private let router: IPRouter
    private var listener: NWListener?

    init(router: IPRouter, remoteIP: UInt32, remotePort: UInt16, localPort: UInt16 = 0) throws {
        self.router = router
        self.remoteIP = remoteIP
        self.remotePort = remotePort

        let params = NWParameters.tcp
        params.requiredInterfaceType = .loopback
        params.allowLocalEndpointReuse = true
        if localPort != 0 {
            self.listener = try NWListener(using: params, on: NWEndpoint.Port(rawValue: localPort)!)
        } else {
            self.listener = try NWListener(using: params, on: .any)
        }
    }

    func start() async throws {
        guard let listener else { throw PortForwardError.notInitialized }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            let resumed = ContinuationGate()
            listener.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    let port = listener.port?.rawValue ?? 0
                    self?.localPort = port
                    log.info("port-forward 127.0.0.1:\(port, privacy: .public) → \(IPv4.toString(self?.remoteIP ?? 0), privacy: .public):\(self?.remotePort ?? 0, privacy: .public)")
                    resumed.resumeOnce(cont, with: .success(()))
                case .failed(let err):
                    resumed.resumeOnce(cont, with: .failure(err))
                default: break
                }
            }
            listener.newConnectionHandler = { [weak self] conn in
                self?.handleAccept(conn)
            }
            listener.start(queue: .global(qos: .userInitiated))
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
    }

    // MARK: – Splice

    private func handleAccept(_ local: NWConnection) {
        local.start(queue: .global(qos: .userInitiated))

        var conn: UserspaceTCPConnection?
        let writeGate = ContinuationGate()        // suppress writes before .established

        let connection = router.openConnection(
            remoteIP: remoteIP, remotePort: remotePort,
            onEstablished: {
                writeGate.open()
            },
            onData: { data in
                if data.isEmpty {
                    // Upstream half-close → mirror on local side.
                    local.send(content: nil, contentContext: .finalMessage,
                               isComplete: true,
                               completion: .contentProcessed { _ in })
                    return
                }
                local.send(content: data, completion: .contentProcessed { _ in })
            },
            onClose: { _ in
                local.cancel()
            }
        )
        conn = connection

        Task.detached {
            await writeGate.wait()
            guard let conn else { return }
            await PortForwarder.drainLocal(local, into: conn, router: self.router)
        }
    }

    private static func drainLocal(_ local: NWConnection,
                                   into conn: UserspaceTCPConnection,
                                   router: IPRouter) async {
        while true {
            let chunk: Data? = await withCheckedContinuation { cont in
                local.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { data, _, isComplete, err in
                    if err != nil || isComplete && (data?.isEmpty ?? true) {
                        cont.resume(returning: nil)
                        return
                    }
                    cont.resume(returning: data)
                }
            }
            guard let chunk, !chunk.isEmpty else {
                router.close(conn)
                return
            }
            router.send(chunk, on: conn)
        }
    }
}

enum PortForwardError: LocalizedError {
    case notInitialized
    var errorDescription: String? {
        switch self { case .notInitialized: return "Port forwarder not initialised" }
    }
}

final class ContinuationGate: @unchecked Sendable {
    private var lock = NSLock()
    private var alreadyResumed = false
    private var opened = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func resumeOnce<T>(_ cont: CheckedContinuation<T, Error>, with result: Result<T, Error>) {
        lock.lock()
        let shouldResume = !alreadyResumed
        if shouldResume { alreadyResumed = true }
        lock.unlock()
        guard shouldResume else { return }
        switch result {
        case .success(let v): cont.resume(returning: v)
        case .failure(let e): cont.resume(throwing: e)
        }
    }

    func open() {
        lock.lock()
        let toFire = waiters
        waiters.removeAll()
        opened = true
        lock.unlock()
        for w in toFire { w.resume() }
    }

    func wait() async {
        lock.lock()
        if opened { lock.unlock(); return }
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            waiters.append(cont)
            lock.unlock()
        }
    }
}
