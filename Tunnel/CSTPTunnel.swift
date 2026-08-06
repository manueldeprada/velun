import Foundation
import Network
import NetworkExtension
import OSLog

private let log = Logger(subsystem: "com.manueldeprada.velun.PacketTunnel", category: "CSTP")

private enum ACPkt: UInt8 {
    case data        = 0
    case dpdOut      = 3   // Dead-peer-detection request
    case dpdResp     = 4   // Dead-peer-detection response
    case disconnect  = 5
    case keepalive   = 7
    case compressed  = 8
    case termServer  = 9
}

class CSTPTunnel {
    private let host:    String
    private let port:    Int
    private let cookie:  String
    private let group:   String
    private let userAgent: String
    private let clientCertP12: String
    private let clientCertPassword: String

    // Set after connect()
    private(set) var networkConfig: TunnelNetworkConfig?

    private var connection: NWConnection?
    private var keepaliveTimer: DispatchSourceTimer?
    private var running = false

    private let inboundLock = NSLock()
    private var _lastInboundAt = Date()
    private func noteInbound() { inboundLock.lock(); _lastInboundAt = Date(); inboundLock.unlock() }
    var secondsSinceLastInbound: TimeInterval {
        inboundLock.lock(); defer { inboundLock.unlock() }
        return Date().timeIntervalSince(_lastInboundAt)
    }

    // MARK: – DTLS data-plane acceleration (optional, additive)

    static var dtlsEnabled = true

    private let inbound = InboundQueue()
    private var tlsReaderTask: Task<Void, Never>?

    private let dtlsLock = NSLock()
    private var dtls: DTLSConnection?
    private var pendingDTLSParams: DTLSParams?
    private var dtlsBringUpTask: Task<Void, Never>?

    private let dtlsAllowed: Bool

    init(host: String, port: Int = 443, cookie: String, group: String, userAgent: String,
         dtlsEnabled: Bool = true, clientCertP12: String = "", clientCertPassword: String = "") {
        self.host      = host
        self.port      = port
        self.cookie    = cookie
        self.group     = group
        self.userAgent = userAgent
        self.dtlsAllowed = dtlsEnabled
        self.clientCertP12 = clientCertP12
        self.clientCertPassword = clientCertPassword
    }

    // Establish TLS connection, do HTTP CONNECT handshake, parse CSTP headers.
    func connect() async throws -> TunnelNetworkConfig {
        let conn = try await openTLSConnection()
        self.connection = conn

        let masterSecret = Self.randomBytes(48)
        let connectReq = Self.buildConnectRequest(host: host, cookie: cookie, reconnect: false,
                                                  masterSecretHex: Self.hexEncode(masterSecret))
        try await send(data: connectReq.data(using: .utf8)!)

        let responseText = try await readHTTPResponse()
        var cfg = try Self.parseCSTPHeaders(responseText)
        captureDTLSParams(responseText, masterSecret: masterSecret, cfg: &cfg)
        self.networkConfig = cfg
        self.running = true
        noteInbound()              // baseline so the watchdog doesn't fire pre-first-DPD
        startKeepalive()
        startTLSReader()
        startDTLS()                // best-effort; stays on TLS if it fails
        return cfg
    }

    func reconnectTransport() async throws {
        guard let originalCfg = networkConfig else {
            throw AnyConnectError.tunnelConnectFailed("Cannot reconnect before initial connect")
        }
        keepaliveTimer?.cancel()
        keepaliveTimer = nil
        tlsReaderTask?.cancel(); tlsReaderTask = nil
        teardownDTLS()             // the UDP socket died with the network too
        connection?.cancel()
        connection = nil

        let conn = try await openTLSConnection()
        self.connection = conn

        let masterSecret = Self.randomBytes(48)
        let req = Self.buildConnectRequest(host: host, cookie: cookie, reconnect: true,
                                           masterSecretHex: Self.hexEncode(masterSecret))
        try await send(data: req.data(using: .utf8)!)

        let responseText = try await readHTTPResponse()
        var newCfg = try Self.parseCSTPHeaders(responseText)

        guard newCfg.ipAddress == originalCfg.ipAddress else {
            throw AnyConnectError.tunnelConnectFailed(
                "Server reassigned inner IP on reconnect (\(originalCfg.ipAddress) → \(newCfg.ipAddress))")
        }

        captureDTLSParams(responseText, masterSecret: masterSecret, cfg: &newCfg)
        running = true
        noteInbound()              // fresh transport — reset the silence clock
        inbound.reset()
        startKeepalive()
        startTLSReader()
        startDTLS()
    }

    private func openTLSConnection() async throws -> NWConnection {
        let params = NWParameters.tls
        // Accept self-signed / enterprise CA
        if let tlsOpts = params.defaultProtocolStack.applicationProtocols.first as? NWProtocolTLS.Options {
            sec_protocol_options_set_verify_block(tlsOpts.securityProtocolOptions, { _, _, complete in
                complete(true)
            }, .global())
            velunApplyClientCert(tlsOpts, p12Base64: clientCertP12, password: clientCertPassword)
        }
        params.prohibitedInterfaceTypes = [.other]
        params.preferNoProxies = true

        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: UInt16(port))!
        )
        let conn = NWConnection(to: endpoint, using: params)

        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                let once = ResumeOnce(cont)
                conn.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        once.resume()
                    case .failed(let err):
                        once.resume(throwing: AnyConnectError.tunnelConnectFailed(err.localizedDescription))
                    case .cancelled:
                        once.resume(throwing: AnyConnectError.tunnelConnectFailed("Connection cancelled"))
                    case .waiting(let err):
                        once.resume(throwing: AnyConnectError.tunnelConnectFailed("Path unavailable: \(err.localizedDescription)"))
                    default: break
                    }
                }
                conn.start(queue: .global(qos: .userInitiated))
            }
        } onCancel: {
            conn.cancel()
        }

        conn.viabilityUpdateHandler = { [weak conn] viable in
            guard !viable, let conn else { return }
            conn.cancel()
        }
        return conn
    }

    func abortTransport() {
        connection?.cancel()
    }

    func disconnect() {
        running = false
        keepaliveTimer?.cancel()
        tlsReaderTask?.cancel(); tlsReaderTask = nil
        teardownDTLS()
        inbound.fail(AnyConnectError.tunnelConnectFailed("disconnected"))
        guard let conn = connection else { return }
        connection = nil
        Task {
            var hdr = Data(count: 8)
            hdr[0] = 0x53; hdr[1] = 0x54; hdr[2] = 0x46; hdr[3] = 0x01
            hdr[6] = ACPkt.disconnect.rawValue
            try? await withTimeout(seconds: 1.0) {
                await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                    conn.send(content: hdr, completion: .contentProcessed { _ in cont.resume() })
                }
            }
            conn.cancel()
        }
    }

    // MARK: – Packet I/O

    func readDataPacket() async throws -> Data? {
        try await inbound.pop()
    }

    func writeDataPacket(_ data: Data) async throws {
        dtlsLock.lock(); let d = dtls; dtlsLock.unlock()
        if let d, d.isAlive, data.count <= d.mtu, d.send(data) { return }
        try await send(pktType: .data, payload: data)
    }

    private func startTLSReader() {
        tlsReaderTask?.cancel()
        tlsReaderTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, self.running else { return }
                do {
                    let hdr = try await self.receiveExact(8)
                    self.noteInbound()      // any packet (data/DPD/keepalive) proves liveness
                    guard hdr[0] == 0x53, hdr[1] == 0x54, hdr[2] == 0x46 else {
                        self.inbound.fail(AnyConnectError.protocolError(
                            "Bad CSTP magic: \(hdr.prefix(4).map { String($0, radix: 16) })"))
                        return
                    }
                    let length = (Int(hdr[4]) << 8) | Int(hdr[5])
                    let type   = hdr[6]
                    let payload = length > 0 ? try await self.receiveExact(length) : Data()
                    switch ACPkt(rawValue: type) {
                    case .data:
                        self.inbound.push(payload)
                    case .dpdOut:
                        try? await self.send(pktType: .dpdResp, payload: Data())
                    case .dpdResp, .keepalive:
                        break
                    case .disconnect, .termServer:
                        self.inbound.fail(AnyConnectError.tunnelConnectFailed("Server disconnected (type \(type))"))
                        return
                    case .compressed:
                        self.inbound.fail(AnyConnectError.protocolError(
                            "Server sent a compressed packet, which velun did not "
                            + "advertise support for. Turn off compression on the gateway."))
                        return
                    default:
                        break
                    }
                } catch {
                    if Task.isCancelled { return }
                    self.inbound.fail(error)
                    return
                }
            }
        }
    }

    // MARK: – DTLS bring-up / teardown

    private func captureDTLSParams(_ response: String, masterSecret: Data, cfg: inout TunnelNetworkConfig) {
        dtlsLock.lock(); pendingDTLSParams = nil; dtlsLock.unlock()
        guard Self.dtlsEnabled, dtlsAllowed, let pd = parseDTLSHeaders(response) else { return }
        cfg.mtu = min(cfg.mtu, pd.mtu)
        let params = DTLSParams(host: host, port: pd.port, sessionID: pd.sessionID,
                                masterSecret: masterSecret, cipher: pd.cipher, mtu: pd.mtu,
                                keepalive: pd.keepalive, dpd: pd.dpd)
        dtlsLock.lock(); pendingDTLSParams = params; dtlsLock.unlock()
    }

    private func startDTLS() {
        dtlsLock.lock(); let params = pendingDTLSParams; dtlsLock.unlock()
        guard Self.dtlsEnabled, dtlsAllowed, let params else { return }
        dtlsBringUpTask?.cancel()
        dtlsBringUpTask = Task { [weak self] in
            guard let self else { return }
            let d = DTLSConnection(params: params)
            do {
                try await d.connect(
                    onData: { [weak self] pkt in self?.inbound.push(pkt) },
                    onDead: { [weak self] in
                        guard let self else { return }
                        self.dtlsLock.lock(); if self.dtls === d { self.dtls = nil }; self.dtlsLock.unlock()
                    })
                if Task.isCancelled || !self.running { d.close(); return }
                self.dtlsLock.lock(); self.dtls = d; self.dtlsLock.unlock()
            } catch {
                d.close()   // best-effort: the TLS data plane carries on
            }
        }
    }

    private func teardownDTLS() {
        dtlsBringUpTask?.cancel(); dtlsBringUpTask = nil
        dtlsLock.lock(); let d = dtls; dtls = nil; dtlsLock.unlock()
        d?.close()
    }

    // MARK: – Private helpers

    static func buildConnectRequest(host: String, cookie: String, reconnect: Bool,
                                    masterSecretHex: String? = nil) -> String {
        let hostname = Host.current().localizedName ?? "MacBook"
        var lines = [
            "CONNECT /CSCOSSLC/tunnel HTTP/1.1",
            "Host: \(host)",
            "User-Agent: Cisco AnyConnect VPN Agent for MacOSX 4.10.07062",
            "Cookie: webvpn=\(cookie)",
            "X-CSTP-Version: 1",
            "X-CSTP-Hostname: \(hostname)",
            "X-CSTP-Base-MTU: 1500",
            "X-CSTP-Address-Type: IPv4,IPv6",
            "X-DTLS-Master-Secret: \(masterSecretHex ?? randomHex(48))",
            "X-DTLS12-CipherSuite: \(DTLSCipherSuite.proposalList.map(\.opensslName).joined(separator: ":"))",
        ]
        if reconnect {
            lines.append("X-CSTP-Reconnect: true")
        }
        lines.append("\r\n")
        return lines.joined(separator: "\r\n")
    }

    // MARK: – DTLS header parsing + byte helpers

    private struct ParsedDTLS {
        var sessionID: Data
        var cipher: DTLSCipherSuite
        var port: Int
        var mtu: Int
        var keepalive: TimeInterval
        var dpd: TimeInterval
    }

    private func parseDTLSHeaders(_ response: String) -> ParsedDTLS? {
        var sid: Data?, cipher: DTLSCipherSuite?
        var port = 443, mtu = 1300
        var keepalive: TimeInterval = 20, dpd: TimeInterval = 30
        var compressed = false
        for line in response.components(separatedBy: "\r\n").dropFirst() {
            let kv = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard kv.count == 2 else { continue }
            switch kv[0].uppercased() {
            case "X-DTLS-SESSION-ID":    sid = Self.hexDecode(kv[1])
            case "X-DTLS12-CIPHERSUITE": cipher = DTLSCipherSuite.fromOpenSSLName(kv[1])
            case "X-DTLS-PORT":          port = Int(kv[1]) ?? port
            case "X-DTLS-MTU":           mtu = Int(kv[1]) ?? mtu
            case "X-DTLS-KEEPALIVE":     keepalive = TimeInterval(kv[1]) ?? keepalive
            case "X-DTLS-DPD":           dpd = TimeInterval(kv[1]) ?? dpd
            case "X-DTLS-CONTENT-ENCODING":
                let enc = kv[1].lowercased()
                compressed = !enc.isEmpty && enc != "none" && enc != "identity"
            default: break
            }
        }
        if compressed {
            log.notice("server offers a compressed DTLS channel — staying on TLS")
            return nil
        }
        guard let sid, sid.count >= 16, let cipher else { return nil }
        return ParsedDTLS(sessionID: sid, cipher: cipher, port: port, mtu: mtu,
                          keepalive: keepalive, dpd: dpd)
    }

    static func hexDecode(_ s: String) -> Data? {
        let chars = Array(s.unicodeScalars)
        guard chars.count % 2 == 0 else { return nil }
        var out = Data(capacity: chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = Character(chars[i]).hexDigitValue,
                  let lo = Character(chars[i + 1]).hexDigitValue else { return nil }
            out.append(UInt8(hi << 4 | lo)); i += 2
        }
        return out
    }

    static func hexEncode(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func randomBytes(_ n: Int) -> Data {
        var b = Data(count: n)
        b.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, n, $0.baseAddress!) }
        return b
    }

    // Reads until \r\n\r\n (end of HTTP headers)
    private func readHTTPResponse() async throws -> String {
        var buf = Data()
        let terminator = Data([0x0d, 0x0a, 0x0d, 0x0a])
        while !buf.hasSuffix(terminator) {
            let chunk = try await receiveExact(1)
            buf.append(chunk)
            if buf.count > 65536 { throw AnyConnectError.protocolError("HTTP response too large") }
        }
        return String(data: buf, encoding: .utf8) ?? ""
    }

    static func parseCSTPHeaders(_ response: String) throws -> TunnelNetworkConfig {
        let lines = response.components(separatedBy: "\r\n")
        guard let statusLine = lines.first, statusLine.contains("200") else {
            throw AnyConnectError.tunnelConnectFailed("Server rejected CONNECT: \(lines.first ?? "?")")
        }

        var addr = "", mask = "", gw = ""
        var dns: [String] = [], domains: [String] = []
        var splitInc: [String] = [], splitExc: [String] = []
        var mtu = 1406
        var addr6 = "", prefix6 = 0
        var splitInc6: [String] = []

        for line in lines.dropFirst() {
            let kv = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard kv.count == 2 else { continue }
            let key = kv[0].uppercased(), val = kv[1]
            switch key {
            case "X-CSTP-ADDRESS":
                if val.contains(":") { if addr6.isEmpty { addr6 = val } } else { addr = val }
            case "X-CSTP-NETMASK":       mask = val
            case "X-CSTP-GATEWAY":       gw   = val
            case "X-CSTP-MTU":           mtu  = Int(val) ?? mtu
            case "X-CSTP-DNS":           dns.append(val)
            case "X-CSTP-DEFAULT-DOMAIN": domains.append(val)
            case "X-CSTP-SPLIT-INCLUDE": splitInc.append(subnetToCIDR(val))
            case "X-CSTP-SPLIT-EXCLUDE": splitExc.append(subnetToCIDR(val))
            case "X-CSTP-ADDRESS-IP6":
                // "2001:db8::1000/64" — address plus the on-link prefix length.
                let parts = val.split(separator: "/", maxSplits: 1).map(String.init)
                addr6 = parts[0]
                prefix6 = parts.count == 2 ? (Int(parts[1]) ?? 0) : 0
            case "X-CSTP-SPLIT-INCLUDE-IP6":
                splitInc6.append(val)
            case "X-CSTP-CONTENT-ENCODING":
                let enc = val.lowercased()
                if !enc.isEmpty, enc != "none", enc != "identity" {
                    throw AnyConnectError.protocolError(
                        "This VPN server insists on compressing the tunnel (\(val)), "
                        + "which velun doesn't support. Ask whoever runs the gateway to "
                        + "turn off AnyConnect SSL compression for it.")
                }
            default: break
            }
        }

        let v4DNS = dns.filter { IPv4.toUInt32($0) != nil }
        if v4DNS.count != dns.count {
            log.info("ignoring \(dns.count - v4DNS.count, privacy: .public) IPv6 DNS server(s) — resolver stays IPv4")
        }
        if !addr6.isEmpty, IPv6Addr(addr6) == nil {
            log.error("unparseable X-CSTP-Address-IP6 \(addr6, privacy: .public) — treating upstream as IPv4-only")
            addr6 = ""; prefix6 = 0; splitInc6 = []
        }

        guard !addr.isEmpty, IPv4.toUInt32(addr) != nil else {
            throw AnyConnectError.protocolError(
                addr6.isEmpty
                ? "No X-CSTP-Address in server response"
                : "Server issued an IPv6-only session (\(addr6)); velun needs an IPv4 address too")
        }
        if gw.isEmpty { gw = addr }

        return TunnelNetworkConfig(
            ipAddress:     addr,
            netmask:       mask.isEmpty ? "255.255.255.0" : mask,
            gateway:       gw,
            dnsServers:    v4DNS,
            searchDomains: domains,
            mtu:           mtu,
            splitIncludes: splitInc,
            splitExcludes: splitExc,
            ipv6Address:      addr6,
            ipv6PrefixLength: prefix6,
            ipv6SplitIncludes: splitInc6
        )
    }

    // Send a CSTP packet
    private func send(pktType: ACPkt, payload: Data) async throws {
        var hdr = Data(count: 8)
        hdr[0] = 0x53; hdr[1] = 0x54; hdr[2] = 0x46; hdr[3] = 0x01
        hdr[4] = UInt8(payload.count >> 8)
        hdr[5] = UInt8(payload.count & 0xff)
        hdr[6] = pktType.rawValue
        hdr[7] = 0x00
        try await send(data: hdr + payload)
    }

    // Low-level send
    private func send(data: Data) async throws {
        guard let conn = connection else { return }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.send(content: data, completion: .contentProcessed { err in
                if let err { cont.resume(throwing: err) } else { cont.resume() }
            })
        }
    }

    // Receive exactly `count` bytes
    private func receiveExact(_ count: Int) async throws -> Data {
        guard let conn = connection else { throw AnyConnectError.tunnelConnectFailed("Not connected") }
        return try await withCheckedThrowingContinuation { cont in
            conn.receive(minimumIncompleteLength: count, maximumLength: count) { data, _, isComplete, err in
                if let err { cont.resume(throwing: err); return }
                if let data, data.count == count { cont.resume(returning: data); return }
                if isComplete { cont.resume(throwing: AnyConnectError.tunnelConnectFailed("Connection closed")) }
            }
        }
    }

    private func startKeepalive() {
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + 20, repeating: 20)
        timer.setEventHandler { [weak self] in
            guard let self, self.running else { return }
            Task { try? await self.send(pktType: .dpdOut, payload: Data()) }
        }
        timer.resume()
        keepaliveTimer = timer
    }

    // "10.x.x.x/255.y.y.y" → "10.x.x.x/prefix"  (pass-through if already CIDR)
    static func subnetToCIDR(_ val: String) -> String {
        let parts = val.split(separator: "/").map(String.init)
        if parts.count == 2, let mask = IPv4MaskToPrefix(parts[1]) {
            return "\(parts[0])/\(mask)"
        }
        return val
    }

    private static func IPv4MaskToPrefix(_ mask: String) -> Int? {
        let octets = mask.split(separator: ".").compactMap { UInt8($0) }
        guard octets.count == 4 else { return nil }
        var bits = 0
        for o in octets { bits += o.nonzeroBitCount }
        return bits
    }

    private static func randomHex(_ byteCount: Int) -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        _ = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
}

private extension Data {
    func hasSuffix(_ other: Data) -> Bool {
        count >= other.count && suffix(other.count) == other
    }
}

// MARK: – InboundQueue

private final class InboundQueue {
    private let lock = NSLock()
    private var buffer: [Data] = []
    private var waiter: ResumeOnce<Data>?
    private var error: Error?

    func push(_ d: Data) {
        lock.lock()
        if let w = waiter { waiter = nil; lock.unlock(); w.resume(returning: d); return }
        buffer.append(d); lock.unlock()
    }

    func fail(_ e: Error) {
        lock.lock(); let w = waiter; waiter = nil; if error == nil { error = e }; lock.unlock()
        w?.resume(throwing: e)
    }

    /// Clear the terminal error so a rebuilt transport's reads can be consumed.
    func reset() { lock.lock(); error = nil; lock.unlock() }

    func pop() async throws -> Data {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            let once = ResumeOnce(cont)
            lock.lock()
            if !buffer.isEmpty { let d = buffer.removeFirst(); lock.unlock(); once.resume(returning: d); return }
            if let e = error { lock.unlock(); once.resume(throwing: e); return }
            waiter = once; lock.unlock()
        }
    }
}

// MARK: – SSLVPNFamilyTunnel adapter

final class CSTPTunnelBackend: SSLVPNFamilyTunnel {
    private var inner: CSTPTunnel?

    var secondaryPasswordProvider: SecondaryPasswordProvider?

    var ssoTokenProvider: SSOTokenProvider?

    var supportsSeamlessReconnect: Bool { true }

    func connect(config: SharedTunnelConfig) async throws -> TunnelNetworkConfig {
        let auth = VPNAuthClient(
            host: config.host, port: config.port,
            username: config.username, password: config.password,
            group: config.group, totpSecret: config.totpSecret,
            userAgent: config.userAgent,
            secondaryPasswordProvider: secondaryPasswordProvider,
            ssoTokenProvider: ssoTokenProvider,
            clientCertP12: config.clientCertP12, clientCertPassword: config.clientCertPassword
        )
        let cookie = try await auth.authenticate()
        let t = CSTPTunnel(host: config.host, port: config.port, cookie: cookie,
                           group: config.group, userAgent: config.userAgent,
                           dtlsEnabled: config.dtlsEnabled,
                           clientCertP12: config.clientCertP12,
                           clientCertPassword: config.clientCertPassword)
        self.inner = t
        return try await t.connect()
    }

    func reconnectTransport() async throws {
        guard let inner else { throw AnyConnectError.tunnelConnectFailed("Not connected") }
        try await inner.reconnectTransport()
    }

    var secondsSinceLastInbound: TimeInterval? { inner?.secondsSinceLastInbound }
    func disconnect() { inner?.disconnect(); inner = nil }
    func abortTransport() { inner?.abortTransport() }
    func readDataPacket() async throws -> Data?  { try await inner?.readDataPacket() ?? nil }
    func writeDataPacket(_ data: Data) async throws {
        guard let inner else { throw AnyConnectError.tunnelConnectFailed("Not connected") }
        try await inner.writeDataPacket(data)
    }
}
