import Foundation
import OSLog

private let log = Logger(subsystem: "com.manueldeprada.velun", category: "ScriptedNet.Runner")

final class ScriptedRunner {

    struct Forward {
        let remoteIP: UInt32
        let remotePort: UInt16
        /// Optional fixed local port. Pass 0 to let the kernel pick one.
        var localPort: UInt16 = 0
        /// Substituted in command env as `${envName}=127.0.0.1:<port>`.
        var envName: String
    }

    struct Result {
        let exitCode: Int32
        let stdout: String
        let stderr: String
    }

    enum RunnerError: LocalizedError {
        case unsupportedProvider
        case tunnelHandshakeFailed(String)
        case noAssignedIP
        case missingHostInProfile
        case profileMissingCredentials
        case forwardFailed(String)

        var errorDescription: String? {
            switch self {
            case .unsupportedProvider:           return "WireGuard scripted runs aren't supported yet"
            case .tunnelHandshakeFailed(let m):  return "Tunnel handshake failed: \(m)"
            case .noAssignedIP:                  return "Server did not return an inner IPv4"
            case .missingHostInProfile:          return "Profile is missing a server host"
            case .profileMissingCredentials:     return "Profile is missing credentials"
            case .forwardFailed(let m):          return "Could not start local forward: \(m)"
            }
        }
    }

    static func run(profile: VPNProfile,
                    forwards: [Forward],
                    command: [String],
                    timeout: TimeInterval = 60) async throws -> Result {

        guard profile.provider != .wireguard else { throw RunnerError.unsupportedProvider }

        let tunnelBackend = try makeBackend(for: profile.provider)
        let cfg = sharedConfig(from: profile)
        log.info("scripted run: provider=\(profile.provider.rawValue, privacy: .public) host=\(cfg.host, privacy: .public)")

        let netCfg: TunnelNetworkConfig
        do {
            netCfg = try await tunnelBackend.connect(config: cfg)
        } catch {
            throw RunnerError.tunnelHandshakeFailed(error.localizedDescription)
        }

        guard let assignedIP = IPv4.toUInt32(netCfg.ipAddress) else {
            tunnelBackend.disconnect()
            throw RunnerError.noAssignedIP
        }

        // Wire the tunnel to a packet transport, then to a router.
        let transport = SSLVPNFamilyPacketTransport(tunnel: tunnelBackend)
        let router = IPRouter(transport: transport, localIP: assignedIP)
        router.start()

        defer {
            router.stop()
            tunnelBackend.disconnect()
        }

        // Spin up port forwards.
        var listeners: [PortForwarder] = []
        for fwd in forwards {
            do {
                let pf = try PortForwarder(router: router,
                                           remoteIP: fwd.remoteIP,
                                           remotePort: fwd.remotePort,
                                           localPort: fwd.localPort)
                try await pf.start()
                listeners.append(pf)
            } catch {
                listeners.forEach { $0.stop() }
                throw RunnerError.forwardFailed(error.localizedDescription)
            }
        }
        defer { listeners.forEach { $0.stop() } }

        var env = ProcessInfo.processInfo.environment
        for (i, fwd) in forwards.enumerated() {
            let port = listeners[i].localPort
            env[fwd.envName]            = "127.0.0.1:\(port)"
            env["\(fwd.envName)_HOST"]  = "127.0.0.1"
            env["\(fwd.envName)_PORT"]  = "\(port)"
            if i == 0 {
                env["HOST"]   = "127.0.0.1"
                env["PORT"]   = "\(port)"
                env["TARGET"] = "127.0.0.1:\(port)"
            }
        }
        env["VELUN_TUNNEL_IP"] = netCfg.ipAddress

        // Run the command.
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: command[0])
        proc.arguments = Array(command.dropFirst())
        proc.environment = env
        let outPipe = Pipe(), errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError  = errPipe
        try proc.run()

        // Enforce timeout.
        let timeoutTask = Task {
            try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            if proc.isRunning { proc.terminate() }
        }
        proc.waitUntilExit()
        timeoutTask.cancel()

        let stdout = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""

        return Result(exitCode: proc.terminationStatus, stdout: stdout, stderr: stderr)
    }

    // MARK: – Plumbing

    private static func makeBackend(for provider: ProviderType) throws -> SSLVPNFamilyTunnel {
        switch provider {
        case .anyConnect:    return CSTPTunnelBackend()
        case .fortinet:      return FortinetTunnelBackend()
        case .globalProtect: return GPTunnelBackend()
        case .wireguard:     throw RunnerError.unsupportedProvider
        }
    }

    private static func sharedConfig(from profile: VPNProfile) -> SharedTunnelConfig {
        var c = SharedTunnelConfig()
        c.profileID    = profile.id.uuidString
        c.providerType = profile.provider.rawValue
        c.userAgent    = profile.provider.userAgent
        c.partialMode  = .full
        c.manualRoutes = ""

        switch profile.config {
        case .sslVPN(let oc):
            c.host       = oc.host
            c.port       = oc.port
            c.username   = oc.username
            c.password   = oc.password
            c.group      = oc.group
            c.totpSecret = oc.totpSecret
            c.clientCertP12      = oc.clientCertP12
            c.clientCertPassword = oc.clientCertPassword
        case .wireguard:
            // Caught above by `unsupportedProvider`, but keep the switch exhaustive.
            break
        }
        return c
    }
}

private final class SSLVPNFamilyPacketTransport: PacketTransport {
    private let tunnel: SSLVPNFamilyTunnel
    init(tunnel: SSLVPNFamilyTunnel) { self.tunnel = tunnel }

    func readPacket() async throws -> Data? { try await tunnel.readDataPacket() }
    func writePacket(_ packet: Data) async throws { try await tunnel.writeDataPacket(packet) }
    func close() { tunnel.disconnect() }
}
