import Foundation
import Network
import OSLog

private let gpLog = Logger(subsystem: "com.manueldeprada.velun.PacketTunnel", category: "GP")

final class GPTunnelBackend: SSLVPNFamilyTunnel {

    private var connection: NWConnection?
    private var keepaliveTimer: DispatchSourceTimer?
    private var running = false
    private var rxBuffer = Data()      // unread bytes from a previous receive

    // MARK: – SSLVPNFamilyTunnel

    func connect(config: SharedTunnelConfig) async throws -> TunnelNetworkConfig {
        let auth = GPAuthClient(host: config.host, port: config.port,
                                username: config.username, password: config.password,
                                totpSecret: config.totpSecret, userAgent: config.userAgent)
        let session = try await auth.login()
        let netCfg  = try await auth.fetchTunnelConfig(session: session)
        try await openTunnel(host: config.host, port: config.port, session: session)
        running = true
        startKeepalive()
        return netCfg
    }

    func disconnect() {
        running = false
        keepaliveTimer?.cancel()
        connection?.cancel()
        connection = nil
    }

    func abortTransport() { connection?.cancel() }

    func readDataPacket() async throws -> Data? {
        while true {
            let hdr = try await receiveExact(16)
            guard hdr.count == 16 else { return nil }
            let magic = hdr.beUInt32(at: 0)
            let etype = hdr.beUInt16(at: 4)
            let plen  = Int(hdr.beUInt16(at: 6))
            guard magic == 0x1a2b3c4d else {
                throw GPError.protocolError("Bad GP magic 0x\(String(magic, radix: 16))")
            }
            let payload = plen > 0 ? try await receiveExact(plen) : Data()
            switch etype {
            case 0x0800, 0x86DD: return payload
            case 0x0000: continue
            default:
                gpLog.error("Unknown GP ethertype 0x\(String(etype, radix: 16, uppercase: false), privacy: .public)")
                continue
            }
        }
    }

    func writeDataPacket(_ data: Data) async throws {
        let etype: UInt16 = (data.first ?? 0) >> 4 == 6 ? 0x86DD : 0x0800
        try await send(payload: data, ethertype: etype, isData: true)
    }

    // MARK: – Tunnel handshake

    private func openTunnel(host: String, port: Int, session: GPSession) async throws {
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
                // One-shot guard — see ResumeOnce in TunnelConfiguration.swift.
                let once = ResumeOnce(cont)
                conn.stateUpdateHandler = { state in
                    switch state {
                    case .ready: once.resume()
                    case .failed(let err): once.resume(throwing: GPError.tunnelConnectFailed(err.localizedDescription))
                    case .cancelled: once.resume(throwing: GPError.tunnelConnectFailed("Connection cancelled"))
                    case .waiting(let err): once.resume(throwing: GPError.tunnelConnectFailed("Path unavailable: \(err.localizedDescription)"))
                    default: break
                    }
                }
                conn.start(queue: .global(qos: .userInitiated))
            }
        } onCancel: {
            conn.cancel()
        }
        // Proactive dead-path detection — see CSTPTunnel.openTLSConnection.
        conn.viabilityUpdateHandler = { [weak conn] viable in
            guard !viable, let conn else { return }
            conn.cancel()
        }

        var query = URLComponents()
        query.queryItems = [
            URLQueryItem(name: "user",       value: session.user),
            URLQueryItem(name: "authcookie", value: session.authcookie),
        ]
        let path = "/ssl-tunnel-connect.sslvpn?" + (query.percentEncodedQuery ?? "")
        let req = "GET \(path) HTTP/1.1\r\nHost: \(host)\r\n\r\n"
        try await sendRaw(req.data(using: .utf8)!)

        let token = "START_TUNNEL".data(using: .utf8)!
        let header = try await receiveExact(token.count)
        guard header == token else {
            let dump = String(data: header, encoding: .utf8) ?? "<binary>"
            throw GPError.tunnelConnectFailed("Expected START_TUNNEL, got: \(dump)")
        }
    }

    // MARK: – Packet I/O

    private func send(payload: Data, ethertype: UInt16, isData: Bool) async throws {
        var hdr = Data(count: 16)
        hdr.bePut32(0x1a2b3c4d, at: 0)
        hdr.bePut16(ethertype, at: 4)
        hdr.bePut16(UInt16(payload.count), at: 6)
        // 'one' is little-endian per gpst.c. 1 for data, 0 for keepalive.
        var one: UInt32 = isData ? 1 : 0
        withUnsafeBytes(of: &one) { hdr.replaceSubrange(8..<12, with: $0) }
        try await sendRaw(hdr + payload)
    }

    private func sendRaw(_ data: Data) async throws {
        guard let conn = connection else { throw GPError.tunnelConnectFailed("Not connected") }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.send(content: data, completion: .contentProcessed { err in
                if let err { cont.resume(throwing: err) } else { cont.resume() }
            })
        }
    }

    private func receiveExact(_ count: Int) async throws -> Data {
        if rxBuffer.count >= count {
            let chunk = rxBuffer.prefix(count)
            rxBuffer.removeFirst(count)
            return Data(chunk)
        }
        guard let conn = connection else { throw GPError.tunnelConnectFailed("Not connected") }
        while rxBuffer.count < count {
            let next = try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
                conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, err in
                    if let err { cont.resume(throwing: err); return }
                    if let data, !data.isEmpty { cont.resume(returning: data); return }
                    if isComplete { cont.resume(throwing: GPError.tunnelConnectFailed("Connection closed")); return }
                    cont.resume(returning: Data())
                }
            }
            if next.isEmpty { break }
            rxBuffer.append(next)
        }
        guard rxBuffer.count >= count else {
            throw GPError.tunnelConnectFailed("Short read")
        }
        let out = rxBuffer.prefix(count)
        rxBuffer.removeFirst(count)
        return Data(out)
    }

    private func startKeepalive() {
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + 30, repeating: 30)
        timer.setEventHandler { [weak self] in
            guard let self, self.running else { return }
            Task { try? await self.send(payload: Data(), ethertype: 0, isData: false) }
        }
        timer.resume()
        keepaliveTimer = timer
    }
}

// MARK: – GP errors

enum GPError: LocalizedError {
    case authFailed(String)
    case tunnelConnectFailed(String)
    case protocolError(String)

    var errorDescription: String? {
        switch self {
        case .authFailed(let m):           return "GlobalProtect auth failed: \(m)"
        case .tunnelConnectFailed(let m):  return "GlobalProtect tunnel failed: \(m)"
        case .protocolError(let m):        return "GlobalProtect protocol error: \(m)"
        }
    }
}

// MARK: – GP auth client

struct GPSession {
    var user:        String   // effective username after login (may differ from input)
    var authcookie:  String
    var portal:      String   // gateway portal name (used by getconfig.esp)
    var domain:      String
    var preloginCookie: String
    var portalUserAuthCookie: String
}

final class GPAuthClient: NSObject, URLSessionDelegate {
    private let host:       String
    private let port:       Int
    private let username:   String
    private let password:   String
    private let totpSecret: String
    private let userAgent:  String

    private lazy var session: URLSession = {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest  = 30
        cfg.timeoutIntervalForResource = 60
        cfg.httpShouldSetCookies = true
        cfg.httpCookieAcceptPolicy = .always
        return URLSession(configuration: cfg, delegate: self, delegateQueue: nil)
    }()

    init(host: String, port: Int = 443, username: String, password: String,
         totpSecret: String, userAgent: String) {
        self.host       = host
        self.port       = port
        self.username   = username
        self.password   = password
        self.totpSecret = totpSecret
        self.userAgent  = userAgent
    }

    func login() async throws -> GPSession {
        let totp = totpSecret.isEmpty ? "" : TOTPGenerator.generate(secret: totpSecret)
        let credential = totp.isEmpty ? password : password + totp
        let fields: [String: String] = [
            "prot":        "https:",
            "server":      host,
            "inputStr":    "",
            "jnlpReady":   "jnlpReady",
            "user":        username,
            "passwd":      credential,
            "computer":    Host.current().localizedName ?? "Mac",
            "ok":          "Login",
            "direct":      "yes",
            "clientVer":   "4100",
            "clientos":    "Mac",
            "os-version":  "Apple Mac OS X 14.0.0",
            "portal-userauthcookie": "",
            "portal-prelogonuserauthcookie": "",
            "ipv6-support": "no",
        ]
        let xml = try await postForm(path: "/ssl-vpn/login.esp", fields: fields)
        let parsed = GPLoginXML.parse(xml)
        if let err = parsed.errorMessage { throw GPError.authFailed(err) }
        guard !parsed.authcookie.isEmpty else {
            throw GPError.authFailed("Login XML had no authcookie")
        }
        let user = parsed.username.isEmpty ? username : parsed.username
        return GPSession(
            user:        user,
            authcookie:  parsed.authcookie,
            portal:      parsed.portal,
            domain:      parsed.domain,
            preloginCookie:        parsed.preloginCookie,
            portalUserAuthCookie:  parsed.portalUserAuthCookie
        )
    }

    func fetchTunnelConfig(session s: GPSession) async throws -> TunnelNetworkConfig {
        let fields: [String: String] = [
            "user":        s.user,
            "authcookie":  s.authcookie,
            "portal":      s.portal,
            "domain":      s.domain,
            "computer":    Host.current().localizedName ?? "Mac",
            "os-version":  "Apple Mac OS X 14.0.0",
            "clientos":    "Mac",
            "preferred-ip":  "",
            "preferred-ipv6": "",
            "app-version":   "velun-1.0",
            "client-ip":     "",
            "client-ipv6":   "",
            "client-version": "4100",
        ]
        let xml = try await postForm(path: "/ssl-vpn/getconfig.esp", fields: fields)
        return try GPGetConfigXML.parse(xml)
    }

    // MARK: - HTTP

    private func postForm(path: String, fields: [String: String]) async throws -> String {
        let urlStr = "https://\(host)\(port == 443 ? "" : ":\(port)")\(path)"
        guard let url = URL(string: urlStr) else { throw GPError.authFailed("Bad URL: \(urlStr)") }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        req.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        req.setValue("*/*", forHTTPHeaderField: "Accept")
        var comps = URLComponents()
        comps.queryItems = fields.map { URLQueryItem(name: $0.key, value: $0.value) }
        req.httpBody = (comps.percentEncodedQuery ?? "").data(using: .utf8)
        let (data, resp) = try await session.data(for: req)
        if let http = resp as? HTTPURLResponse, http.statusCode >= 400 {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw GPError.authFailed("POST \(path) HTTP \(http.statusCode): \(body.prefix(200))")
        }
        return String(data: data, encoding: .utf8) ?? ""
    }

    // URLSessionDelegate – accept any server cert (enterprise CA / self-signed)
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

// MARK: – Login XML parser

struct GPLoginXMLParsed {
    var authcookie:  String = ""
    var portal:      String = ""
    var preloginCookie: String = ""
    var portalUserAuthCookie: String = ""
    var domain:      String = ""
    var username:    String = ""
    var errorMessage: String? = nil
}

enum GPLoginXML {
    static func parse(_ xml: String) -> GPLoginXMLParsed {
        let p = GPLoginXMLParser(xml: xml)
        return p.parse()
    }
}

private final class GPLoginXMLParser: NSObject, XMLParserDelegate {
    private let xml: String
    private var args: [String] = []
    private var inArgument = false
    private var current = ""
    private var foundError: String?

    init(xml: String) { self.xml = xml }

    func parse() -> GPLoginXMLParsed {
        guard let data = xml.data(using: .utf8) else { return GPLoginXMLParsed() }
        let parser = XMLParser(data: data)
        parser.delegate = self
        parser.parse()
        var out = GPLoginXMLParsed()
        if args.count > 1  { out.portal     = args[1] }
        if args.count > 2  { out.authcookie = args[2] }
        if args.count > 3  { out.preloginCookie = args[3] }
        if args.count > 4  { out.portalUserAuthCookie = args[4] }
        if args.count > 14 { out.domain     = args[14] }
        if args.count > 15 { out.username   = args[15] }
        out.errorMessage = foundError
        return out
    }

    func parser(_ parser: XMLParser, didStartElement name: String,
                namespaceURI: String?, qualifiedName: String?,
                attributes: [String: String] = [:]) {
        current = ""
        if name == "argument" { inArgument = true }
    }

    func parser(_ parser: XMLParser, foundCharacters s: String) { current += s }

    func parser(_ parser: XMLParser, didEndElement name: String,
                namespaceURI: String?, qualifiedName: String?) {
        switch name {
        case "argument":
            args.append(current.trimmingCharacters(in: .whitespacesAndNewlines))
            inArgument = false
        case "msg", "message", "error":
            let t = current.trimmingCharacters(in: .whitespacesAndNewlines)
            if !t.isEmpty { foundError = t }
        default: break
        }
    }
}

// MARK: – getconfig.esp XML parser

enum GPGetConfigXML {
    static func parse(_ xml: String) throws -> TunnelNetworkConfig {
        let p = GPConfigParser(xml: xml)
        let result = p.parse()
        guard !result.ipAddress.isEmpty else {
            throw GPError.protocolError("getconfig.esp: missing <ip-address>")
        }
        return result
    }
}

private final class GPConfigParser: NSObject, XMLParserDelegate {
    private let xml: String
    private var current = ""
    private var element = ""
    private var path:    [String] = []
    private var ip = "", netmask = "255.255.255.0", gateway = "", mtu = "1400"
    private var dns: [String] = []
    private var domains: [String] = []
    private var includes: [String] = []
    private var excludes: [String] = []

    init(xml: String) { self.xml = xml }

    func parse() -> TunnelNetworkConfig {
        guard let data = xml.data(using: .utf8) else { return empty() }
        let parser = XMLParser(data: data); parser.delegate = self
        parser.parse()
        if gateway.isEmpty { gateway = ip }
        return TunnelNetworkConfig(
            ipAddress: ip,
            netmask: netmask,
            gateway: gateway,
            dnsServers: dns,
            searchDomains: domains,
            mtu: Int(mtu) ?? 1400,
            splitIncludes: includes,
            splitExcludes: excludes
        )
    }

    private func empty() -> TunnelNetworkConfig {
        TunnelNetworkConfig(ipAddress: "", netmask: "255.255.255.0", gateway: "",
                            dnsServers: [], searchDomains: [], mtu: 1400,
                            splitIncludes: [], splitExcludes: [])
    }

    func parser(_ parser: XMLParser, didStartElement name: String,
                namespaceURI: String?, qualifiedName: String?,
                attributes: [String: String] = [:]) {
        current = ""; element = name; path.append(name)
    }

    func parser(_ parser: XMLParser, foundCharacters s: String) { current += s }

    func parser(_ parser: XMLParser, didEndElement name: String,
                namespaceURI: String?, qualifiedName: String?) {
        let v = current.trimmingCharacters(in: .whitespacesAndNewlines)
        switch name {
        case "ip-address":  if !v.isEmpty { ip = v }
        case "netmask":     if !v.isEmpty { netmask = v }
        case "gw-address":  if !v.isEmpty { gateway = v }
        case "mtu":         if !v.isEmpty { mtu = v }
        case "primary-dns", "secondary-dns":
            // Some GP servers ship DNS as <primary-dns>x</primary-dns> directly.
            if !v.isEmpty { dns.append(v) }
        case "default-domain":
            if !v.isEmpty { domains.append(v) }
        case "member":
            let parent = path.count >= 2 ? path[path.count - 2] : ""
            if !v.isEmpty {
                switch parent {
                case "dns", "dns-v4", "dns-v6":          dns.append(v)
                case "dns-suffix":                        domains.append(v)
                case "access-routes":                     includes.append(v)
                case "exclude-access-routes":             excludes.append(v)
                default: break
                }
            }
        default: break
        }
        if path.last == name { path.removeLast() }
    }
}

// MARK: – Endian helpers

private extension Data {
    func beUInt16(at i: Int) -> UInt16 {
        (UInt16(self[i]) << 8) | UInt16(self[i + 1])
    }
    func beUInt32(at i: Int) -> UInt32 {
        var v: UInt32 = 0
        for k in 0..<4 { v = (v << 8) | UInt32(self[i + k]) }
        return v
    }
    mutating func bePut16(_ v: UInt16, at i: Int) {
        self[i]     = UInt8((v >> 8) & 0xff)
        self[i + 1] = UInt8(v & 0xff)
    }
    mutating func bePut32(_ v: UInt32, at i: Int) {
        for k in 0..<4 { self[i + k] = UInt8((v >> (8 * (3 - k))) & 0xff) }
    }
}
