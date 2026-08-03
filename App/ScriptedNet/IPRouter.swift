import Foundation
import OSLog

private let log = Logger(subsystem: "com.manueldeprada.velun", category: "ScriptedNet.IPRouter")

protocol PacketTransport: AnyObject {
    func readPacket() async throws -> Data?
    func writePacket(_ packet: Data) async throws
    func close()
}

final class IPRouter: UserspaceTCPDelegate {

    private let transport: PacketTransport
    private let localIP: UInt32
    private var connections: [Key: UserspaceTCPConnection] = [:]
    private struct Key: Hashable { let localPort: UInt16; let remoteIP: UInt32; let remotePort: UInt16 }

    private let queue = DispatchQueue(label: "velun.ScriptedNet.IPRouter")
    private var readTask: Task<Void, Never>?
    private var nextEphemeralPort: UInt16 = 49152      // IANA dynamic range start
    private var stopped = false

    private var dataHandlers:        [Key: (Data) -> Void]   = [:]
    private var closeHandlers:       [Key: (Error?) -> Void] = [:]
    private var establishedHandlers: [Key: () -> Void]       = [:]

    init(transport: PacketTransport, localIP: UInt32) {
        self.transport = transport
        self.localIP = localIP
    }

    func start() {
        readTask = Task { [weak self] in
            await self?.readLoop()
        }
    }

    func stop() {
        queue.sync {
            guard !stopped else { return }
            stopped = true
            for c in connections.values { c.abort() }
            connections.removeAll()
            dataHandlers.removeAll()
            closeHandlers.removeAll()
        }
        readTask?.cancel()
        readTask = nil
        transport.close()
    }

    // MARK: – Outbound: open a TCP client connection

    func openConnection(remoteIP: UInt32, remotePort: UInt16,
                        onEstablished: @escaping () -> Void,
                        onData: @escaping (Data) -> Void,
                        onClose: @escaping (Error?) -> Void) -> UserspaceTCPConnection {
        return queue.sync {
            let port = allocateLocalPort()
            let key = Key(localPort: port, remoteIP: remoteIP, remotePort: remotePort)
            let c = UserspaceTCPConnection(
                localIP: localIP, localPort: port,
                remoteIP: remoteIP, remotePort: remotePort
            )
            c.delegate = self
            connections[key] = c
            establishedHandlers[key] = onEstablished
            dataHandlers[key] = onData
            closeHandlers[key] = onClose
            c.open()
            return c
        }
    }

    func send(_ data: Data, on connection: UserspaceTCPConnection) {
        queue.async { connection.send(data) }
    }

    func close(_ connection: UserspaceTCPConnection) {
        queue.async { connection.close() }
    }

    // MARK: – Inbound packet loop

    private func readLoop() async {
        while !Task.isCancelled {
            do {
                guard let pkt = try await transport.readPacket() else {
                    if Task.isCancelled { return }
                    continue
                }
                queue.sync { handleInbound(pkt) }
            } catch {
                if Task.isCancelled { return }
                log.error("transport read failed: \(error.localizedDescription, privacy: .public)")
                queue.sync {
                    let err = error
                    for c in connections.values { c.abort() }
                    for (k, h) in closeHandlers { h(err); _ = k }
                    connections.removeAll()
                    dataHandlers.removeAll()
                    closeHandlers.removeAll()
                }
                return
            }
        }
    }

    private func handleInbound(_ packet: Data) {
        guard let ip = IPv4Header.parse(packet),
              ip.proto == IPProtocol.tcp.rawValue,
              ip.destinationAddress == localIP else { return }
        let payload = packet.suffix(from: ip.headerLength)
        guard let tcp = TCPSegment.parse(Data(payload)) else { return }

        let key = Key(localPort: tcp.destinationPort,
                      remoteIP: ip.sourceAddress,
                      remotePort: tcp.sourcePort)
        guard let c = connections[key] else {
            if !tcp.flags.contains(.rst) {
                let pkt = PacketBuilder.ipv4TCP(
                    srcIP: localIP, dstIP: ip.sourceAddress,
                    srcPort: tcp.destinationPort, dstPort: tcp.sourcePort,
                    seq: tcp.ackNumber, ack: 0,
                    flags: [.rst], window: 0, payload: Data()
                )
                Task { try? await transport.writePacket(pkt) }
            }
            return
        }
        c.handle(tcp)
    }

    // MARK: – UserspaceTCPDelegate (called on router queue)

    func tcpDidEmitPacket(_ packet: Data, connection: UserspaceTCPConnection) {
        Task { try? await transport.writePacket(packet) }
    }

    func tcpDidEstablish(_ connection: UserspaceTCPConnection) {
        let key = keyFor(connection)
        establishedHandlers[key]?()
    }

    func tcpDidReceiveData(_ data: Data, connection: UserspaceTCPConnection) {
        let key = keyFor(connection)
        dataHandlers[key]?(data)
    }

    func tcpDidClose(_ connection: UserspaceTCPConnection, error: Error?) {
        let key = keyFor(connection)
        closeHandlers[key]?(error)
        connections.removeValue(forKey: key)
        dataHandlers.removeValue(forKey: key)
        closeHandlers.removeValue(forKey: key)
        establishedHandlers.removeValue(forKey: key)
    }

    private func keyFor(_ c: UserspaceTCPConnection) -> Key {
        Key(localPort: c.localPort, remoteIP: c.remoteIP, remotePort: c.remotePort)
    }

    private func allocateLocalPort() -> UInt16 {
        for _ in 0..<10000 {
            let port = nextEphemeralPort
            nextEphemeralPort = nextEphemeralPort == 65535 ? 49152 : nextEphemeralPort + 1
            if !connections.contains(where: { $0.key.localPort == port }) {
                return port
            }
        }
        return UInt16.random(in: 49152...65535)
    }
}
