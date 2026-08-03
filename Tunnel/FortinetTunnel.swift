import Foundation
import Network
import OSLog

private let fnLog = Logger(subsystem: "com.manueldeprada.velun.PacketTunnel", category: "Fortinet")

final class FortinetTunnelBackend: SSLVPNFamilyTunnel {

    private var connection: NWConnection?
    private var pppEngine:  PPPEngine?
    private var rxBuffer    = Data()
    private var keepalive:   DispatchSourceTimer?
    private var running     = false

    func connect(config: SharedTunnelConfig) async throws -> TunnelNetworkConfig {
        let auth = FortinetAuthClient(host: config.host, port: config.port,
                                      username: config.username, password: config.password,
                                      group: config.group, totpSecret: config.totpSecret,
                                      userAgent: config.userAgent)
        let cookie = try await auth.login()
        var preset = try await auth.fetchTunnelConfig(cookie: cookie)
        try await openSSL(host: config.host, port: config.port)
        try await sendTunnelStart(host: config.host, cookie: cookie)

        // Spin up PPP and pump LCP / IPCP exchanges until both layers are up.
        let ppp = PPPEngine(send: { [weak self] frame in
            try await self?.writeFortinetEncap(frame)
        })
        self.pppEngine = ppp
        try await ppp.bringUp(initialNetwork: &preset, read: { [weak self] in
            try await self?.readFortinetEncap()
        })
        running = true
        startKeepalive()
        return preset
    }

    func disconnect() {
        running = false
        keepalive?.cancel()
        connection?.cancel()
        connection = nil
        pppEngine  = nil
    }

    func abortTransport() { connection?.cancel() }

    func readDataPacket() async throws -> Data? {
        guard let pppEngine else { return nil }
        while running {
            guard let frame = try await readFortinetEncap() else { return nil }
            if let ip = pppEngine.ingestAndExtractIPv4(frame) {
                return ip
            }
        }
        return nil
    }

    func writeDataPacket(_ data: Data) async throws {
        // PPP frame for IP packet: ff 03 [proto 0x0021] payload
        var frame = Data([0xff, 0x03, 0x00, 0x21])
        frame.append(data)
        try await writeFortinetEncap(frame)
    }

    // MARK: – TLS + tunnel startup

    private func openSSL(host: String, port: Int) async throws {
        let params = NWParameters.tls
        if let tlsOpts = params.defaultProtocolStack.applicationProtocols.first as? NWProtocolTLS.Options {
            sec_protocol_options_set_verify_block(tlsOpts.securityProtocolOptions, { _, _, complete in
                complete(true)
            }, .global())
        }
        params.prohibitedInterfaceTypes = [.other]
        params.preferNoProxies = true
        let conn = NWConnection(to: .hostPort(host: NWEndpoint.Host(host),
                                              port: NWEndpoint.Port(rawValue: UInt16(port))!),
                                using: params)
        self.connection = conn
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                let once = ResumeOnce(cont)
                conn.stateUpdateHandler = { state in
                    switch state {
                    case .ready: once.resume()
                    case .failed(let err): once.resume(throwing: FortinetError.tunnelConnectFailed(err.localizedDescription))
                    case .cancelled: once.resume(throwing: FortinetError.tunnelConnectFailed("Connection cancelled"))
                    case .waiting(let err): once.resume(throwing: FortinetError.tunnelConnectFailed("Path unavailable: \(err.localizedDescription)"))
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
    }

    private func sendTunnelStart(host: String, cookie: String) async throws {
        let req = """
        GET /remote/sslvpn-tunnel HTTP/1.1\r
        Host: \(host)\r
        User-Agent: velun-fortinet\r
        Cookie: SVPNCOOKIE=\(cookie)\r
        \r

        """
        try await sendRaw(req.data(using: .utf8)!)
    }

    // MARK: – Fortinet encap framing

    private func writeFortinetEncap(_ pppFrame: Data) async throws {
        var hdr = Data(count: 6)
        let total = UInt16(pppFrame.count + 6)
        hdr[0] = UInt8(total >> 8); hdr[1] = UInt8(total & 0xff)
        hdr[2] = 0x50;              hdr[3] = 0x50              // magic
        hdr[4] = UInt8(pppFrame.count >> 8); hdr[5] = UInt8(pppFrame.count & 0xff)
        try await sendRaw(hdr + pppFrame)
    }

    private func readFortinetEncap() async throws -> Data? {
        let hdr = try await receiveExact(6)
        guard hdr.count == 6 else { return nil }
        if hdr.starts(with: "HTTP".utf8) {
            let rest = (try? await receiveExact(120)) ?? Data()
            let preview = String(data: hdr + rest, encoding: .utf8) ?? "<binary>"
            throw FortinetError.tunnelConnectFailed("Server rejected tunnel: \(preview.prefix(160))")
        }
        let total = (UInt16(hdr[0]) << 8) | UInt16(hdr[1])
        let magic = (UInt16(hdr[2]) << 8) | UInt16(hdr[3])
        let plen  = (UInt16(hdr[4]) << 8) | UInt16(hdr[5])
        guard magic == 0x5050, total == UInt16(plen) + 6 else {
            throw FortinetError.protocolError("Bad Fortinet header magic=0x\(String(magic, radix: 16)) total=\(total) plen=\(plen)")
        }
        return try await receiveExact(Int(plen))
    }

    private func sendRaw(_ data: Data) async throws {
        guard let conn = connection else { throw FortinetError.tunnelConnectFailed("Not connected") }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.send(content: data, completion: .contentProcessed { err in
                if let err { cont.resume(throwing: err) } else { cont.resume() }
            })
        }
    }

    private func receiveExact(_ count: Int) async throws -> Data {
        if rxBuffer.count >= count {
            let chunk = rxBuffer.prefix(count); rxBuffer.removeFirst(count)
            return Data(chunk)
        }
        guard let conn = connection else { throw FortinetError.tunnelConnectFailed("Not connected") }
        while rxBuffer.count < count {
            let next = try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
                conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, err in
                    if let err { cont.resume(throwing: err); return }
                    if let data, !data.isEmpty { cont.resume(returning: data); return }
                    if isComplete { cont.resume(throwing: FortinetError.tunnelConnectFailed("Connection closed")); return }
                    cont.resume(returning: Data())
                }
            }
            if next.isEmpty { break }
            rxBuffer.append(next)
        }
        guard rxBuffer.count >= count else { throw FortinetError.tunnelConnectFailed("Short read") }
        let out = rxBuffer.prefix(count); rxBuffer.removeFirst(count)
        return Data(out)
    }

    private func startKeepalive() {
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + 30, repeating: 30)
        timer.setEventHandler { [weak self] in
            guard let self, self.running else { return }
            // LCP Echo-Request as a keepalive: ff 03 [c021] [09 id 00 04]
            Task {
                let id = UInt8(Int.random(in: 0...255))
                let frame = Data([0xff, 0x03, 0xc0, 0x21, 0x09, id, 0x00, 0x04])
                try? await self.writeFortinetEncap(frame)
            }
        }
        timer.resume()
        keepalive = timer
    }
}

// MARK: – Errors

enum FortinetError: LocalizedError {
    case authFailed(String)
    case tunnelConnectFailed(String)
    case protocolError(String)

    var errorDescription: String? {
        switch self {
        case .authFailed(let m):           return "Fortinet auth failed: \(m)"
        case .tunnelConnectFailed(let m):  return "Fortinet tunnel failed: \(m)"
        case .protocolError(let m):        return "Fortinet protocol error: \(m)"
        }
    }
}

// MARK: – Auth client

final class FortinetAuthClient: NSObject, URLSessionDelegate {
    private let host:        String
    private let port:        Int
    private let username:    String
    private let password:    String
    private let group:       String
    private let totpSecret:  String
    private let userAgent:   String

    private lazy var session: URLSession = {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest  = 30
        cfg.timeoutIntervalForResource = 60
        cfg.httpShouldSetCookies = true
        cfg.httpCookieAcceptPolicy = .always
        return URLSession(configuration: cfg, delegate: self, delegateQueue: nil)
    }()

    init(host: String, port: Int = 443,
         username: String, password: String,
         group: String, totpSecret: String,
         userAgent: String) {
        self.host = host; self.port = port
        self.username = username; self.password = password
        self.group = group; self.totpSecret = totpSecret
        self.userAgent = userAgent
    }

    func login() async throws -> String {
        var fields: [String: String] = [
            "username":      username,
            "credential":    password,
            "realm":         group,
            "ajax":          "1",
            "just_logged_in": "1",
        ]

        let resp = try await postForm(path: "/remote/logincheck", fields: fields)
        if let cookie = svpnCookie() {
            return cookie
        }
        // tokeninfo-style 2FA: response body is "ret=…,tokeninfo=…"
        if let totp = nonEmpty(totpSecret).map({ TOTPGenerator.generate(secret: $0) }) ?? nil,
           let parsed = parseTokenInfo(resp), !totp.isEmpty {
            fields = parsed
            fields["username"] = username
            fields["code"]     = totp
            fields["realm"]    = group
            _ = try await postForm(path: "/remote/logincheck", fields: fields)
            if let cookie = svpnCookie() { return cookie }
        }
        throw FortinetError.authFailed("No SVPNCOOKIE in response: \(resp.prefix(200))")
    }

    // GET /remote/fortisslvpn_xml?dual_stack=1 → IP address, DNS, split routes.
    func fetchTunnelConfig(cookie: String) async throws -> TunnelNetworkConfig {
        let urlStr = "https://\(host)\(port == 443 ? "" : ":\(port)")/remote/fortisslvpn_xml?dual_stack=1"
        guard let url = URL(string: urlStr) else { throw FortinetError.authFailed("Bad URL") }
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        req.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        req.setValue("SVPNCOOKIE=\(cookie)", forHTTPHeaderField: "Cookie")
        let (data, resp) = try await session.data(for: req)
        if let http = resp as? HTTPURLResponse, http.statusCode >= 400 {
            throw FortinetError.authFailed("fortisslvpn_xml HTTP \(http.statusCode)")
        }
        let xml = String(data: data, encoding: .utf8) ?? ""
        return try FortinetConfigXML.parse(xml)
    }

    private func svpnCookie() -> String? {
        guard let storage = session.configuration.httpCookieStorage,
              let url = URL(string: "https://\(host)/") else { return nil }
        return storage.cookies(for: url)?.first(where: { $0.name == "SVPNCOOKIE" && !$0.value.isEmpty })?.value
    }

    private func parseTokenInfo(_ body: String) -> [String: String]? {
        guard body.hasPrefix("ret=") else { return nil }
        var out: [String: String] = [:]
        for piece in body.split(separator: ",") {
            let kv = piece.split(separator: "=", maxSplits: 1).map(String.init)
            if kv.count == 2 {
                let k = kv[0].trimmingCharacters(in: .whitespaces)
                if ["reqid", "polid", "grp", "portal", "peer", "magic"].contains(k) {
                    out[k] = kv[1].trimmingCharacters(in: .whitespacesAndNewlines)
                }
            }
        }
        return out.isEmpty ? nil : out
    }

    private func postForm(path: String, fields: [String: String]) async throws -> String {
        let urlStr = "https://\(host)\(port == 443 ? "" : ":\(port)")\(path)"
        guard let url = URL(string: urlStr) else { throw FortinetError.authFailed("Bad URL: \(urlStr)") }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        req.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        var comps = URLComponents()
        comps.queryItems = fields.map { URLQueryItem(name: $0.key, value: $0.value) }
        req.httpBody = (comps.percentEncodedQuery ?? "").data(using: .utf8)
        let (data, _) = try await session.data(for: req)
        return String(data: data, encoding: .utf8) ?? ""
    }

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

private func nonEmpty(_ s: String) -> String? { s.isEmpty ? nil : s }

// MARK: – Fortinet XML config parser

enum FortinetConfigXML {
    static func parse(_ xml: String) throws -> TunnelNetworkConfig {
        let p = FortinetConfigParser(xml: xml)
        return p.parse()
    }
}

private final class FortinetConfigParser: NSObject, XMLParserDelegate {
    private let xml: String
    private var path: [String] = []
    private var ipv4 = "", netmask = "255.255.255.255", gateway = ""
    private var dns: [String] = []
    private var domains: [String] = []
    private var includes: [String] = []
    private var excludes: [String] = []
    private var mtu = 1400

    init(xml: String) { self.xml = xml }

    func parse() -> TunnelNetworkConfig {
        guard let data = xml.data(using: .utf8) else { return empty() }
        let parser = XMLParser(data: data); parser.delegate = self
        parser.parse()
        if gateway.isEmpty { gateway = ipv4 }
        return TunnelNetworkConfig(
            ipAddress: ipv4, netmask: netmask, gateway: gateway,
            dnsServers: dns, searchDomains: domains, mtu: mtu,
            splitIncludes: includes, splitExcludes: excludes
        )
    }

    private func empty() -> TunnelNetworkConfig {
        TunnelNetworkConfig(ipAddress: "", netmask: "255.255.255.255", gateway: "",
                            dnsServers: [], searchDomains: [], mtu: 1400,
                            splitIncludes: [], splitExcludes: [])
    }

    func parser(_ parser: XMLParser, didStartElement name: String,
                namespaceURI: String?, qualifiedName: String?,
                attributes attrs: [String: String] = [:]) {
        path.append(name)
        switch name {
        case "assigned-addr":
            if let v = attrs["ipv4"] { ipv4 = v }
            if let v = attrs["mask"] { netmask = v }
        case "dns":
            if let v = attrs["ipv4"] { dns.append(v) }
            if let v = attrs["domain"] { domains.append(v) }
        case "split-dns":
            if let v = attrs["domains"] {
                domains.append(contentsOf: v.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) })
            }
        case "addr":
            // <split-tunnel-info include="1"><addr ip="…" mask="…"/></split-tunnel-info>
            if let ip = attrs["ip"], let mask = attrs["mask"] {
                let cidr = "\(ip)/\(maskToPrefix(mask))"
                if path.contains("split-tunnel-info") {
                    let inc = (attrs["include"] ?? "1") != "0"
                    if inc { includes.append(cidr) } else { excludes.append(cidr) }
                }
            }
        case "mtu":
            if let v = attrs["value"], let n = Int(v) { mtu = n }
        default: break
        }
    }

    func parser(_ parser: XMLParser, didEndElement name: String,
                namespaceURI: String?, qualifiedName: String?) {
        if path.last == name { path.removeLast() }
    }

    private func maskToPrefix(_ mask: String) -> Int {
        let bytes = mask.split(separator: ".").compactMap { UInt8($0) }
        guard bytes.count == 4 else { return 32 }
        return bytes.reduce(0) { $0 + $1.nonzeroBitCount }
    }
}

// MARK: – Minimal PPP engine (LCP / IPCP)

final class PPPEngine {
    private let send: (Data) async throws -> Void
    private var lcpUp  = false
    private var ipcpUp = false
    private var ourMagic: UInt32 = UInt32.random(in: 1...UInt32.max)
    private var idCounter: UInt8 = 1

    init(send: @escaping (Data) async throws -> Void) {
        self.send = send
    }

    func bringUp(initialNetwork: inout TunnelNetworkConfig,
                 read: () async throws -> Data?) async throws {
        try await sendLCPConfigRequest()
        let deadline = Date().addingTimeInterval(15)
        while !ipcpUp {
            if Date() > deadline {
                throw FortinetError.protocolError("PPP did not come up within 15s")
            }
            guard let frame = try await read() else {
                throw FortinetError.protocolError("EOF while bringing up PPP")
            }
            try await handle(frame: frame, network: &initialNetwork)
        }
    }

    func ingestAndExtractIPv4(_ frame: Data) -> Data? {
        guard let (proto, body) = PPPFraming.decode(frame) else { return nil }
        if proto == 0x0021 { return body }
        // Background LCP / IPCP messages mid-session: Echo-Request → Echo-Reply.
        Task { try? await self.handleAsync(proto: proto, body: body) }
        return nil
    }

    private func handleAsync(proto: UInt16, body: Data) async throws {
        var dummy = TunnelNetworkConfig(ipAddress: "", netmask: "", gateway: "",
                                        dnsServers: [], searchDomains: [], mtu: 0,
                                        splitIncludes: [], splitExcludes: [])
        try await handleControl(proto: proto, body: body, network: &dummy)
    }

    private func handle(frame: Data, network: inout TunnelNetworkConfig) async throws {
        guard let (proto, body) = PPPFraming.decode(frame) else { return }
        try await handleControl(proto: proto, body: body, network: &network)
    }

    private func handleControl(proto: UInt16, body: Data, network: inout TunnelNetworkConfig) async throws {
        switch proto {
        case 0xC021:  // LCP
            try await handleLCP(body: body)
        case 0x8021:  // IPCP
            try await handleIPCP(body: body, network: &network)
        default:
            break
        }
    }

    private func handleLCP(body: Data) async throws {
        guard body.count >= 4 else { return }
        let code = body[0], id = body[1]
        let len  = (Int(body[2]) << 8) | Int(body[3])
        let payload = body.count >= len ? body.subdata(in: 4..<len) : Data()
        switch code {
        case 1: // Configure-Request — Ack everything we recognize.
            var ack = Data([0x02, id])
            ack.append(UInt8(payload.count + 4 >> 8)); ack.append(UInt8((payload.count + 4) & 0xff))
            ack.append(payload)
            try await sendPPP(proto: 0xC021, body: ack)
        case 2: // Configure-Ack — our request accepted.
            lcpUp = true
            try await sendIPCPConfigRequest()
        case 3, 4: // Configure-Nak / Reject
            // Fortinet rejects ACFC + PFCOMP; we just send a leaner request.
            try await sendLCPConfigRequest(includeAuth: false, magicOnly: true)
        case 9: // Echo-Request → Echo-Reply
            var reply = Data([0x0a, id])
            let plen = payload.count + 4
            reply.append(UInt8(plen >> 8)); reply.append(UInt8(plen & 0xff))
            reply.append(payload)
            try await sendPPP(proto: 0xC021, body: reply)
        default: break
        }
    }

    private func handleIPCP(body: Data, network: inout TunnelNetworkConfig) async throws {
        guard body.count >= 4 else { return }
        let code = body[0], id = body[1]
        let len  = (Int(body[2]) << 8) | Int(body[3])
        let payload = body.count >= len ? body.subdata(in: 4..<len) : Data()
        switch code {
        case 1: // Configure-Request from server — Ack
            var ack = Data([0x02, id])
            ack.append(UInt8((payload.count + 4) >> 8)); ack.append(UInt8((payload.count + 4) & 0xff))
            ack.append(payload)
            try await sendPPP(proto: 0x8021, body: ack)
        case 2: // Configure-Ack of our IPCP request
            ipcpUp = true
        case 3: // Configure-Nak — server suggests its preferred IP/DNS, accept
            absorbIPCP(options: payload, into: &network)
            try await sendIPCPConfigRequest()
        default: break
        }
    }

    private func absorbIPCP(options: Data, into network: inout TunnelNetworkConfig) {
        var i = 0
        while i + 1 < options.count {
            let typ = options[i], oplen = Int(options[i + 1])
            guard oplen >= 2, i + oplen <= options.count else { break }
            let raw = options.subdata(in: (i + 2)..<(i + oplen))
            switch typ {
            case 0x03:  // IP address
                if raw.count == 4 { network.ipAddress = ipString(raw) }
            case 0x81:  // Primary DNS
                if raw.count == 4 { network.dnsServers = [ipString(raw)] + network.dnsServers }
            case 0x83:  // Secondary DNS
                if raw.count == 4 { network.dnsServers.append(ipString(raw)) }
            default: break
            }
            i += oplen
        }
    }

    // MARK: – Outgoing config requests

    private func sendLCPConfigRequest(includeAuth: Bool = false, magicOnly: Bool = false) async throws {
        var opts = Data()
        // MRU = 1500
        opts.append(contentsOf: [0x01, 0x04, 0x05, 0xdc])
        // Magic-Number
        opts.append(0x05); opts.append(0x06)
        opts.append(UInt8(ourMagic >> 24)); opts.append(UInt8((ourMagic >> 16) & 0xff))
        opts.append(UInt8((ourMagic >> 8)  & 0xff)); opts.append(UInt8(ourMagic & 0xff))

        var pkt = Data([0x01, idCounter])
        idCounter &+= 1
        let total = opts.count + 4
        pkt.append(UInt8(total >> 8)); pkt.append(UInt8(total & 0xff))
        pkt.append(opts)
        try await sendPPP(proto: 0xC021, body: pkt)
    }

    private func sendIPCPConfigRequest() async throws {
        var opts = Data()
        opts.append(contentsOf: [0x03, 0x06, 0, 0, 0, 0])   // IP 0.0.0.0 (placeholder)
        opts.append(contentsOf: [0x81, 0x06, 0, 0, 0, 0])   // Primary DNS
        opts.append(contentsOf: [0x83, 0x06, 0, 0, 0, 0])   // Secondary DNS

        var pkt = Data([0x01, idCounter])
        idCounter &+= 1
        let total = opts.count + 4
        pkt.append(UInt8(total >> 8)); pkt.append(UInt8(total & 0xff))
        pkt.append(opts)
        try await sendPPP(proto: 0x8021, body: pkt)
    }

    private func sendPPP(proto: UInt16, body: Data) async throws {
        var frame = Data([0xff, 0x03])
        frame.append(UInt8(proto >> 8)); frame.append(UInt8(proto & 0xff))
        frame.append(body)
        try await send(frame)
    }

    private func ipString(_ d: Data) -> String {
        d.map { String($0) }.joined(separator: ".")
    }
}

enum PPPFraming {
    static func decode(_ frame: Data) -> (UInt16, Data)? {
        var i = 0
        if frame.count >= 2 && frame[frame.startIndex] == 0xff && frame[frame.startIndex + 1] == 0x03 {
            i = 2
        }
        guard frame.count > i else { return nil }
        var proto: UInt16 = UInt16(frame[frame.startIndex + i])
        if (proto & 1) == 1 {
            // Compressed: protocol fits in 1 byte (low bit set).
            i += 1
        } else {
            guard frame.count > i + 1 else { return nil }
            proto = (proto << 8) | UInt16(frame[frame.startIndex + i + 1])
            i += 2
        }
        let payload = frame.subdata(in: (frame.startIndex + i)..<frame.endIndex)
        return (proto, payload)
    }

    static func encode(proto: UInt16, body: Data) -> Data {
        var out = Data([0xff, 0x03])
        out.append(UInt8(proto >> 8))
        out.append(UInt8(proto & 0xff))
        out.append(body)
        return out
    }
}
