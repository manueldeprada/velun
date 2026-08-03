import Foundation
import Network
import Security
import OSLog

private let authLog = Logger(subsystem: "com.manueldeprada.velun.PacketTunnel", category: "Auth")

func velunClientTLSIdentity(p12Base64: String, password: String) -> sec_identity_t? {
    guard !p12Base64.isEmpty, let data = Data(base64Encoded: p12Base64) else { return nil }
    guard #available(macOS 15.0, *) else {
        authLog.error("client certificates require macOS 15 or later")
        return nil
    }
    let opts: [String: Any] = [
        kSecImportExportPassphrase as String: password,
        kSecImportToMemoryOnly as String: true,   // no keychain (sandboxed ext)
    ]
    var items: CFArray?
    let status = SecPKCS12Import(data as CFData, opts as CFDictionary, &items)
    guard status == errSecSuccess,
          let array = items as? [[String: Any]],
          let identityRef = array.first?[kSecImportItemIdentity as String] else {
        authLog.error("client cert PKCS#12 import failed: OSStatus \(status)")
        return nil
    }
    // Force-cast is safe: kSecImportItemIdentity is always a SecIdentity.
    return sec_identity_create(identityRef as! SecIdentity)
}

func velunApplyClientCert(_ tlsOpts: NWProtocolTLS.Options, p12Base64: String, password: String) {
    guard !p12Base64.isEmpty else { return }
    if let identity = velunClientTLSIdentity(p12Base64: p12Base64, password: password) {
        sec_protocol_options_set_local_identity(tlsOpts.securityProtocolOptions, identity)
        authLog.info("client certificate attached to TLS handshake")
    } else {
        authLog.error("client certificate configured but could not be loaded")
    }
}

typealias SecondaryPasswordProvider = (_ prompt: String) async -> String?

typealias SSOTokenProvider = (_ request: SSOLoginRequest) async -> String?

enum AnyConnectError: Error, LocalizedError {
    case authFailed(String)
    case tunnelConnectFailed(String)
    case protocolError(String)
    case noSessionToken

    var errorDescription: String? {
        switch self {
        case .authFailed(let m):          return "Auth failed: \(m)"
        case .tunnelConnectFailed(let m): return "Tunnel connect failed: \(m)"
        case .protocolError(let m):       return "Protocol error: \(m)"
        case .noSessionToken:             return "Server did not return a session token"
        }
    }
}

struct AuthState {
    var sessionToken:  String?       // set on success
    var authComplete:  Bool = false
    var action:        String = "/+webvpn+/index.html"
    var errorMessage:  String?       // from <error>...</error>
    var hiddenFields:  [String: String] = [:]  // server-echoed hidden inputs
    var formFieldNames: Set<String> = []       // every <input name=…> in the form
    var ssoLogin:           String?  // <sso-v2-login> — IdP / kickoff URL
    var ssoLoginFinal:      String?  // <sso-v2-login-final> — sentinel URL
    var ssoTokenCookieName: String?  // <sso-v2-token-cookie-name>
    var ssoErrorCookieName: String?  // <sso-v2-error-cookie-name>
    var ssoTokenFieldName:  String?  // <input type="sso" name=…> — auth-reply element
    var clientCertRequested: Bool = false  // <client-cert-request> — server wants mutual TLS
}

class VPNAuthClient {
    private let host:        String
    private let port:        Int
    private let username:    String
    private let password:    String
    private let group:       String
    private let totpSecret:  String
    private let userAgent:   String
    private let secondaryPasswordProvider: SecondaryPasswordProvider?
    /// Browser-SSO source, used only when the server's init demands SAML/SSO.
    private let ssoTokenProvider: SSOTokenProvider?
    private let clientCertP12: String
    private let clientCertPassword: String

    private var conn:       NWConnection?
    private var reader:     HTTPReader?
    private var connAlive  = false

    private static let preferXMLPost = true
    private static let anyConnectVersion = "4.10.07062"

    init(host: String, port: Int = 443,
         username: String, password: String,
         group: String, totpSecret: String,
         userAgent: String = "AnyConnect",
         secondaryPasswordProvider: SecondaryPasswordProvider? = nil,
         ssoTokenProvider: SSOTokenProvider? = nil,
         clientCertP12: String = "", clientCertPassword: String = "") {
        self.host       = host
        self.port       = port
        self.username   = username
        self.password   = password
        self.group      = group
        self.totpSecret = totpSecret
        self.userAgent  = userAgent
        self.secondaryPasswordProvider = secondaryPasswordProvider
        self.ssoTokenProvider = ssoTokenProvider
        self.clientCertP12 = clientCertP12
        self.clientCertPassword = clientCertPassword
    }

    private func secondaryPassword() async -> String {
        if !totpSecret.isEmpty { return TOTPGenerator.generate(secret: totpSecret) }
        guard let provider = secondaryPasswordProvider else { return "" }
        let code = await provider("Enter your one-time verification code")
        return (code ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func authenticate() async throws -> String {
        defer { closeConnection() }
        guard Self.preferXMLPost else { return try await authenticateForm() }
        do {
            return try await authenticateXMLPost()
        } catch let e as AnyConnectError {
            if case .authFailed = e { throw e }   // genuine rejection — don't double-attempt
            authLog.info("XML POST auth unavailable (\(e.localizedDescription, privacy: .public)); using form login")
            closeConnection()                       // clean socket for the fallback
            return try await authenticateForm()
        }
    }

    // MARK: - HTML form login (fallback)

    private func authenticateForm() async throws -> String {
        let base = "https://\(host)\(port == 443 ? "" : ":\(port)")"
        authLog.info("Auth start base=\(base, privacy: .public) user=\(self.username, privacy: .public) group=\(self.group.isEmpty ? "(none)" : self.group, privacy: .public) hasTOTP=\(!self.totpSecret.isEmpty, privacy: .public)")

        var jar: [String: String] = [:]

        let (body1, jar1) = try await doGet(path: "/", cookies: jar, maxRedirects: 5)
        jar.merge(jar1) { _, new in new }
        authLog.info("Step1 (GET /) resp (\(body1.count, privacy: .public) bytes):\n\(body1, privacy: .public)")
        let state1 = parseResponse(body1)
        authLog.info("Step1 parsed: action=\(state1.action, privacy: .public) hidden=\(state1.hiddenFields.keys.sorted().joined(separator: ","), privacy: .public) fields=\(state1.formFieldNames.sorted().joined(separator: ","), privacy: .public)")

        // Step 2 – POST credentials as application/x-www-form-urlencoded.
        var fields: [String: String] = [
            "username": username,
            "password": password,
            "Login":    "Login",
        ]
        if state1.formFieldNames.contains("secondary_username") {
            fields["secondary_username"] = username
        }
        if state1.formFieldNames.contains("secondary_password") {
            fields["secondary_password"] = await secondaryPassword()
        }
        // Only send group_list when a group is configured.
        if !group.isEmpty { fields["group_list"] = group }
        // Echo back any hidden fields the form included (CSRF, etc.).
        for (k, v) in state1.hiddenFields { fields[k] = v }

        authLog.debug("Step2 req fields (pwd/totp redacted): \(fields.keys.sorted().joined(separator: ","), privacy: .public)")
        let (body2, jar2) = try await doPost(path: state1.action, fields: fields, cookies: jar)
        jar.merge(jar2) { _, new in new }
        authLog.info("Step2 resp (\(body2.count, privacy: .public) bytes):\n\(body2, privacy: .public)")
        let state2 = parseResponse(body2)
        authLog.info("Step2 parsed: authComplete=\(state2.authComplete, privacy: .public) tokenSet=\(state2.sessionToken != nil, privacy: .public) errorMsg=\(state2.errorMessage ?? "(nil)", privacy: .public)")

        if state2.authComplete {
            if let tok = jar["webvpn"], !tok.isEmpty {
                authLog.info("Session token acquired from webvpn cookie (len=\(tok.count, privacy: .public))")
                return tok
            }
            authLog.error("Auth succeeded but no webvpn cookie was set.")
        }
        if let tok = state2.sessionToken { return tok }
        if let msg = state2.errorMessage {
            throw AnyConnectError.authFailed(msg)
        }
        throw AnyConnectError.noSessionToken
    }

    private func authenticateXMLPost() async throws -> String {
        authLog.info("XMLPOST start host=\(self.host, privacy: .public) group=\(self.group.isEmpty ? "(none)" : self.group, privacy: .public) hasTOTP=\(!self.totpSecret.isEmpty, privacy: .public)")
        var jar: [String: String] = [:]

        let aggPath = group.isEmpty ? "/" : "/\(group)"
        let initXML = Self.buildConfigAuthInit(host: host, port: port, group: group, version: Self.anyConnectVersion)
        let (s1, c1, _, b1) = try await roundTrip(
            method: "POST", path: aggPath,
            headers: xmlHeaders(bodyLen: initXML.utf8.count, cookies: jar),
            body: Data(initXML.utf8), idempotent: true)
        for (k, v) in c1 { jar[k] = v }
        authLog.info("XMLPOST init → \(s1, privacy: .public) (\(b1.count, privacy: .public) B)")
        guard (200..<300).contains(s1) else {
            throw AnyConnectError.protocolError("init status \(s1)")   // structural → fall back to form
        }
        let state1 = parseResponse(b1)
        if state1.clientCertRequested && clientCertP12.isEmpty {
            throw AnyConnectError.authFailed(
                "This VPN requires a client certificate. Add one in this connection's settings " +
                "(Import .p12). Export it from Keychain Access — your login or System keychain — " +
                "as a .p12 with its private key; if the key is marked non-exportable, only the " +
                "official client can connect.")
        }
        if let login = state1.ssoLogin, !login.isEmpty {
            return try await authenticateSSO(state1: state1, body1: b1, aggPath: aggPath, jar: jar)
        }
        guard !state1.formFieldNames.isEmpty || state1.authComplete else {
            authLog.info("XMLPOST init returned no auth form; body:\n\(b1, privacy: .public)")
            throw AnyConnectError.protocolError("init returned no auth form")  // not config-auth → fall back
        }
        let opaque = Self.extractOpaque(from: b1)
        authLog.debug("XMLPOST opaque \(opaque == nil ? "absent" : "present", privacy: .public)")

        var authFields: [(String, String)] = [("username", username), ("password", password)]
        if state1.formFieldNames.contains("secondary_username") { authFields.append(("secondary_username", username)) }
        if state1.formFieldNames.contains("secondary_password") { authFields.append(("secondary_password", await secondaryPassword())) }

        let replyXML = Self.buildConfigAuthReply(opaque: opaque, authFields: authFields,
                                                 version: Self.anyConnectVersion)
        let (s2, c2, _, b2) = try await roundTrip(
            method: "POST", path: aggPath,
            headers: xmlHeaders(bodyLen: replyXML.utf8.count, cookies: jar),
            body: Data(replyXML.utf8), idempotent: false)   // carries TOTP — never auto-retried
        for (k, v) in c2 { jar[k] = v }
        authLog.info("XMLPOST auth-reply → \(s2, privacy: .public) (\(b2.count, privacy: .public) B)")
        let state2 = parseResponse(b2)

        if state2.authComplete {
            if let tok = jar["webvpn"], !tok.isEmpty {
                authLog.info("XMLPOST session token from webvpn cookie (len=\(tok.count, privacy: .public))")
                return tok
            }
            if let tok = state2.sessionToken { return tok }
            authLog.error("XMLPOST auth succeeded but no webvpn cookie / session-token")
        }
        if let msg = state2.errorMessage { throw AnyConnectError.authFailed(msg) }
        guard (200..<300).contains(s2) else {
            throw AnyConnectError.protocolError("auth-reply status \(s2)")
        }
        throw AnyConnectError.noSessionToken
    }

    private func authenticateSSO(state1: AuthState, body1: String,
                                 aggPath: String, jar: [String: String]) async throws -> String {
        guard let provider = ssoTokenProvider else {
            throw AnyConnectError.authFailed("This VPN uses single sign-on (SSO), which isn't available in this mode.")
        }
        let req = SSOLoginRequest(
            loginURL:        resolveAbsolute(state1.ssoLogin ?? ""),
            finalURL:        resolveAbsolute(state1.ssoLoginFinal ?? ""),
            tokenCookieName: state1.ssoTokenCookieName ?? "",
            errorCookieName: state1.ssoErrorCookieName ?? "",
            tokenFieldName:  state1.ssoTokenFieldName ?? "sso-token")
        authLog.info("SSO required login=\(req.loginURL, privacy: .public) final=\(req.finalURL, privacy: .public) cookie=\(req.tokenCookieName, privacy: .public) field=\(req.tokenFieldName, privacy: .public)")

        guard let token = await provider(req), !token.isEmpty else {
            throw AnyConnectError.authFailed("SSO sign-in was cancelled or didn't complete.")
        }
        authLog.info("SSO token captured (len=\(token.count, privacy: .public)); sending auth-reply")

        // auth-reply: echo the opaque blob + the SSO token under its field name.
        let opaque = Self.extractOpaque(from: body1)
        let replyXML = Self.buildConfigAuthReply(opaque: opaque,
                                                 authFields: [(req.tokenFieldName, token)],
                                                 version: Self.anyConnectVersion)
        var jar2 = jar
        let (s2, c2, _, b2) = try await roundTrip(
            method: "POST", path: aggPath,
            headers: xmlHeaders(bodyLen: replyXML.utf8.count, cookies: jar2),
            body: Data(replyXML.utf8), idempotent: false)
        for (k, v) in c2 { jar2[k] = v }
        authLog.info("SSO auth-reply → \(s2, privacy: .public) (\(b2.count, privacy: .public) B)")
        let state2 = parseResponse(b2)
        if state2.authComplete {
            if let tok = jar2["webvpn"], !tok.isEmpty {
                authLog.info("SSO session token from webvpn cookie (len=\(tok.count, privacy: .public))")
                return tok
            }
            if let tok = state2.sessionToken { return tok }
        }
        if let msg = state2.errorMessage { throw AnyConnectError.authFailed(msg) }
        guard (200..<300).contains(s2) else {
            throw AnyConnectError.protocolError("SSO auth-reply status \(s2)")
        }
        throw AnyConnectError.noSessionToken
    }

    private func resolveAbsolute(_ s: String) -> String {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty || t.hasPrefix("http://") || t.hasPrefix("https://") { return t }
        let base = "https://\(host)\(port == 443 ? "" : ":\(port)")"
        return t.hasPrefix("/") ? base + t : base + "/" + t
    }

    private func xmlHeaders(bodyLen: Int, cookies: [String: String]) -> [(String, String)] {
        let pad = 64 * (1 + bodyLen / 64) - bodyLen
        var h: [(String, String)] = [
            ("X-Pad", String(repeating: "0", count: pad)),
            ("Content-Type", "application/xml; charset=utf-8"),
            ("Content-Length", "\(bodyLen)"),
            ("X-Aggregate-Auth", "1"),
        ]
        h.append(contentsOf: ciscoHeaders())
        if !cookies.isEmpty {
            h.append(("Cookie", cookies.map { "\($0.key)=\($0.value)" }.joined(separator: "; ")))
        }
        return h
    }

    // MARK: config-auth XML builders (pure, unit-tested)

    static func buildConfigAuthInit(host: String, port: Int = 443, group: String, version: String) -> String {
        let hostPort = port == 443 ? host : "\(host):\(port)"
        let groupPath = group.isEmpty ? "/" : "/\(group)"
        var xml = #"<?xml version="1.0" encoding="UTF-8"?>"#
        xml += #"<config-auth client="vpn" type="init" aggregate-auth-version="2">"#
        xml += "<version who=\"vpn\">\(xmlEscape(version))</version>"
        xml += "<device-id>mac-intel</device-id>"
        xml += "<capabilities/>"
        xml += "<group-access>https://\(xmlEscape(hostPort))\(xmlEscape(groupPath))</group-access>"
        xml += "</config-auth>"
        return xml
    }

    static func buildConfigAuthReply(opaque: String?, authFields: [(String, String)],
                                     version: String) -> String {
        var xml = #"<?xml version="1.0" encoding="UTF-8"?>"#
        xml += #"<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">"#
        xml += "<version who=\"vpn\">\(xmlEscape(version))</version>"
        xml += "<device-id>mac-intel</device-id>"
        xml += "<capabilities/>"
        if let opaque, !opaque.isEmpty { xml += opaque }   // server state, echoed verbatim
        xml += "<auth>"
        for (name, value) in authFields { xml += "<\(name)>\(xmlEscape(value))</\(name)>" }
        xml += "</auth>"
        xml += "</config-auth>"
        return xml
    }

    static func extractOpaque(from body: String) -> String? {
        guard let open = body.range(of: "<opaque", options: .caseInsensitive),
              let close = body.range(of: "</opaque>", options: .caseInsensitive,
                                     range: open.upperBound..<body.endIndex) else { return nil }
        return String(body[open.lowerBound..<close.upperBound])
    }

    static func xmlEscape(_ s: String) -> String {
        var out = ""
        out.reserveCapacity(s.count)
        for ch in s {
            switch ch {
            case "&":  out += "&amp;"
            case "<":  out += "&lt;"
            case ">":  out += "&gt;"
            case "\"": out += "&quot;"
            case "'":  out += "&apos;"
            default:   out.append(ch)
            }
        }
        return out
    }

    // MARK: - NWConnection

    private func openAuthConnection() async throws -> NWConnection {
        let params = NWParameters.tls
        if let tlsOpts = params.defaultProtocolStack.applicationProtocols.first as? NWProtocolTLS.Options {
            sec_protocol_options_set_verify_block(tlsOpts.securityProtocolOptions, { _, _, complete in
                complete(true)
            }, .global())
            // Present the client certificate (mutual TLS) when configured.
            velunApplyClientCert(tlsOpts, p12Base64: clientCertP12, password: clientCertPassword)
        }
        params.prohibitedInterfaceTypes = [.other]
        params.preferNoProxies = true
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: UInt16(port))!
        )
        let conn = NWConnection(to: endpoint, using: params)
        do {
            try await withTimeout(seconds: 20, onTimeout: { conn.cancel() }) {
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
                                authLog.info("auth socket waiting, will retry: \(err.localizedDescription, privacy: .public)")
                            default: break
                            }
                        }
                        conn.start(queue: .global(qos: .userInitiated))
                    }
                } onCancel: {
                    conn.cancel()
                }
            }
        } catch is TimeoutError {
            conn.cancel()
            throw AnyConnectError.tunnelConnectFailed("Couldn't reach the VPN server — the network path stayed unavailable. Is another full-tunnel VPN active?")
        }
        return conn
    }

    // MARK: - HTTP/1.1 (keep-alive)

    private func doGet(path: String, cookies: [String: String],
                       maxRedirects: Int) async throws -> (body: String, cookies: [String: String]) {
        var headers = ciscoHeaders()
        if !cookies.isEmpty {
            headers.append(("Cookie", cookies.map { "\($0.key)=\($0.value)" }.joined(separator: "; ")))
        }
        let (status, newCookies, location, body) = try await roundTrip(
            method: "GET", path: path, headers: headers, body: nil, idempotent: true)
        authLog.info("GET \(status, privacy: .public) path=\(path, privacy: .public) bytes=\(body.count, privacy: .public)")
        var merged = cookies
        for (k, v) in newCookies { merged[k] = v }

        if (status == 301 || status == 302 || status == 303), let loc = location, maxRedirects > 0 {
            let nextPath = resolveRedirectPath(loc)
            return try await doGet(path: nextPath, cookies: merged, maxRedirects: maxRedirects - 1)
        }
        return (body, merged)
    }

    private func doPost(path: String, fields: [String: String],
                        cookies: [String: String]) async throws -> (body: String, cookies: [String: String]) {
        var comps = URLComponents()
        comps.queryItems = fields.map { URLQueryItem(name: $0.key, value: $0.value) }
        let bodyData = Data((comps.percentEncodedQuery ?? "").utf8)
        var headers: [(String, String)] = [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Content-Length", "\(bodyData.count)"),
        ]
        headers.append(contentsOf: ciscoHeaders())
        if !cookies.isEmpty {
            headers.append(("Cookie", cookies.map { "\($0.key)=\($0.value)" }.joined(separator: "; ")))
        }
        let (status, newCookies, _, body) = try await roundTrip(
            method: "POST", path: path, headers: headers, body: bodyData, idempotent: false)
        authLog.info("POST \(status, privacy: .public) path=\(path, privacy: .public) bytes=\(body.count, privacy: .public)")
        var merged = cookies
        for (k, v) in newCookies { merged[k] = v }
        return (body, merged)
    }

    private func resolveRedirectPath(_ loc: String) -> String {
        if loc.hasPrefix("/") { return loc }
        if let url = URL(string: loc), url.host == host {
            let p = url.path
            return p.isEmpty ? "/" : p
        }
        return loc  // absolute URL to a different host — return as-is; doGet will just GET it
    }

    private func ciscoHeaders() -> [(String, String)] {
        [
            ("User-Agent", userAgent),
            ("Accept", "*/*"),
            ("Accept-Encoding", "identity"),
            ("X-Transcend-Version", "1"),
            ("X-Support-HTTP-Auth", "true"),
        ]
    }

    // MARK: - connection lifecycle

    private func liveConnection() async throws -> (conn: NWConnection, fresh: Bool) {
        if let c = conn, connAlive, reader != nil { return (c, false) }
        closeConnection()
        let c = try await openAuthConnection()
        conn = c
        reader = HTTPReader(source: { try await VPNAuthClient.recvChunk(conn: c) })
        connAlive = true
        return (c, true)
    }

    private func closeConnection() {
        conn?.cancel()
        conn = nil
        reader = nil
        connAlive = false
    }

    private func roundTrip(method: String, path: String,
                           headers: [(String, String)], body: Data?,
                           idempotent: Bool) async throws -> (status: Int, cookies: [(String, String)], location: String?, body: String) {
        var lastError: Error = AnyConnectError.protocolError("auth request not attempted")
        for _ in 0..<2 {
            let (c, fresh) = try await liveConnection()
            do {
                return try await performRequest(conn: c, method: method, path: path,
                                                headers: headers, body: body)
            } catch {
                lastError = error
                closeConnection()                       // socket is suspect — drop it
                if fresh || !idempotent { throw error }  // fresh socket failed, or non-retryable → propagate
                // otherwise: stale keep-alive race — loop reopens fresh and retries
            }
        }
        throw lastError
    }

    private func performRequest(conn: NWConnection, method: String, path: String,
                                headers: [(String, String)], body: Data?) async throws -> (status: Int, cookies: [(String, String)], location: String?, body: String) {
        guard let reader else { throw AnyConnectError.protocolError("no HTTP reader for connection") }
        let hostHeader = port == 443 ? host : "\(host):\(port)"
        var req = "\(method) \(path) HTTP/1.1\r\nHost: \(hostHeader)\r\n"
        for (k, v) in headers { req += "\(k): \(v)\r\n" }
        req += "\r\n"
        var reqData = Data(req.utf8)
        if let b = body { reqData.append(b) }
        try await sendData(conn: conn, data: reqData)
        let resp = try await reader.readResponse()
        connAlive = resp.keepAlive
        return (resp.status, resp.cookies, resp.location, resp.body)
    }

    // MARK: - Low-level I/O

    private func sendData(conn: NWConnection, data: Data) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.send(content: data, completion: .contentProcessed { err in
                if let err = err { cont.resume(throwing: err) } else { cont.resume() }
            })
        }
    }

    static func recvChunk(conn: NWConnection) async throws -> Data {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { data, _, isComplete, err in
                if let err = err {
                    cont.resume(throwing: err)
                } else if let data = data, !data.isEmpty {
                    cont.resume(returning: data)
                } else {
                    // isComplete with no data = clean close; return empty sentinel.
                    cont.resume(returning: Data())
                }
            }
        }
    }

    // MARK: - XML parsing

    private func parseResponse(_ xml: String) -> AuthState {
        AuthXMLParser(xml: xml).parse()
    }
}

// MARK: - HTTP/1.1 response reader (keep-alive, testable)

final class HTTPReader {
    /// Returns the next chunk of bytes, or empty Data on a clean close.
    typealias ByteSource = () async throws -> Data

    struct Response {
        let status:    Int
        let cookies:   [(String, String)]
        let location:  String?
        let body:      String
        let keepAlive: Bool
    }

    private let source: ByteSource
    private var buffer  = Data()

    init(source: @escaping ByteSource) { self.source = source }

    /// Append one more chunk from the source. Returns false on a clean close.
    private func fill() async throws -> Bool {
        let chunk = try await source()
        if chunk.isEmpty { return false }
        buffer.append(chunk)
        return true
    }

    func readResponse() async throws -> Response {
        let crlfcrlf = Data("\r\n\r\n".utf8)
        while buffer.range(of: crlfcrlf) == nil {
            if !(try await fill()) {
                throw AnyConnectError.protocolError("Connection closed before headers complete")
            }
            if buffer.count > 131_072 { throw AnyConnectError.protocolError("HTTP headers too large") }
        }
        let sep = buffer.range(of: crlfcrlf)!
        let headerBytes = buffer.prefix(sep.lowerBound)
        buffer = Data(buffer.suffix(from: sep.upperBound))   // body starts here

        let headerStr = String(data: headerBytes, encoding: .utf8) ?? ""
        let lines = headerStr.components(separatedBy: "\r\n")
        guard let statusLine = lines.first else {
            throw AnyConnectError.protocolError("Empty HTTP response")
        }
        let parts = statusLine.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2, let status = Int(parts[1]) else {
            throw AnyConnectError.protocolError("Bad status line: \(statusLine)")
        }

        var contentLength: Int?
        var chunked = false
        var cookies: [(String, String)] = []
        var location: String?
        var serverClose = false

        for line in lines.dropFirst() where !line.isEmpty {
            let lower = line.lowercased()
            if lower.hasPrefix("content-length:") {
                contentLength = Int(line.dropFirst(15).trimmingCharacters(in: .whitespaces))
            } else if lower.hasPrefix("transfer-encoding:") && lower.contains("chunked") {
                chunked = true
            } else if lower.hasPrefix("connection:") && lower.contains("close") {
                serverClose = true   // server won't keep the socket; don't reuse it
            } else if lower.hasPrefix("set-cookie:") {
                let raw = String(line.dropFirst(11)).trimmingCharacters(in: .whitespaces)
                let nameVal = raw.components(separatedBy: ";").first?.trimmingCharacters(in: .whitespaces) ?? ""
                if let eq = nameVal.firstIndex(of: "=") {
                    let name  = String(nameVal[..<eq]).trimmingCharacters(in: .whitespaces)
                    let value = String(nameVal[nameVal.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
                    cookies.append((name, value))
                }
            } else if lower.hasPrefix("location:") {
                location = String(line.dropFirst(9)).trimmingCharacters(in: .whitespaces)
            }
        }

        let bodyData: Data
        var keepAlive = !serverClose
        if chunked {
            bodyData = try await readChunkedBody()
        } else if let cl = contentLength {
            while buffer.count < cl {
                if !(try await fill()) { keepAlive = false; break }
            }
            bodyData = Data(buffer.prefix(cl))
            buffer = Data(buffer.dropFirst(cl))   // any extra belongs to the next response
        } else {
            while try await fill() {}
            bodyData = buffer
            buffer = Data()
            keepAlive = false
        }

        let bodyStr = String(data: bodyData, encoding: .utf8)
                   ?? String(data: bodyData, encoding: .isoLatin1)
                   ?? ""
        return Response(status: status, cookies: cookies, location: location,
                        body: bodyStr, keepAlive: keepAlive)
    }

    private func readChunkedBody() async throws -> Data {
        var result = Data()
        let crlf = Data("\r\n".utf8)

        func nextLine() async throws -> String {
            while buffer.range(of: crlf) == nil {
                if !(try await fill()) {
                    throw AnyConnectError.protocolError("Connection closed inside chunked body")
                }
                if buffer.count > 131_072 { throw AnyConnectError.protocolError("Chunk header too long") }
            }
            let end = buffer.range(of: crlf)!
            let line = String(data: buffer.prefix(end.lowerBound), encoding: .utf8) ?? ""
            buffer = Data(buffer.suffix(from: end.upperBound))
            return line
        }

        while true {
            let sizeLine = try await nextLine()
            // chunk-size may be followed by chunk-extensions (";...") — strip them
            let hexStr = sizeLine.components(separatedBy: ";").first?
                                 .trimmingCharacters(in: .whitespaces) ?? ""
            guard let size = Int(hexStr, radix: 16) else {
                throw AnyConnectError.protocolError("Bad chunk size: '\(sizeLine)'")
            }
            if size == 0 {
                while true {
                    let line = try await nextLine()
                    if line.isEmpty { break }
                }
                break
            }
            while buffer.count < size + 2 {
                if !(try await fill()) {
                    throw AnyConnectError.protocolError("Connection closed inside chunk data")
                }
            }
            result.append(buffer.prefix(size))
            buffer = Data(buffer.dropFirst(size + 2)) // chunk data + trailing CRLF
        }
        return result
    }
}

// MARK: - SAX-style XML parser for auth responses

private class AuthXMLParser: NSObject, XMLParserDelegate {
    private let xml: String
    private var state   = AuthState()
    private var element = ""
    private var text    = ""

    init(xml: String) { self.xml = xml }

    func parse() -> AuthState {
        guard let data = xml.data(using: .utf8) else { return state }
        let p = XMLParser(data: data)
        p.delegate = self
        p.parse()

        // Fallback: grep for session-token in case of malformed XML wrapper
        if !state.authComplete, let range = xml.range(of: "(?<=<session-token>)[^<]+",
                                                       options: .regularExpression) {
            state.sessionToken = String(xml[range]).trimmingCharacters(in: .whitespacesAndNewlines)
            state.authComplete = true
        }
        return state
    }

    func parser(_ parser: XMLParser, didStartElement name: String,
                namespaceURI: String?, qualifiedName: String?,
                attributes attrs: [String: String] = [:]) {
        element = name
        text    = ""
        switch name {
        case "form":
            if let a = attrs["action"] { state.action = a }
        case "auth":
            if attrs["id"] == "success" { state.authComplete = true }
        case "client-cert-request":
            state.clientCertRequested = true
        case "input":
            if let n = attrs["name"] { state.formFieldNames.insert(n) }
            if attrs["type"] == "hidden", let k = attrs["name"], let v = attrs["value"] {
                state.hiddenFields[k] = v
            }
            if attrs["type"] == "sso", let n = attrs["name"] { state.ssoTokenFieldName = n }
        default: break
        }
    }

    func parser(_ parser: XMLParser, foundCharacters s: String) { text += s }

    func parser(_ parser: XMLParser, didEndElement name: String,
                namespaceURI: String?, qualifiedName: String?) {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        switch name {
        case "session-token":
            state.sessionToken = t
            state.authComplete = true
        case "error":
            state.errorMessage = t
        case "sso-v2-login":             state.ssoLogin = t
        case "sso-v2-login-final":       state.ssoLoginFinal = t
        case "sso-v2-token-cookie-name": state.ssoTokenCookieName = t
        case "sso-v2-error-cookie-name": state.ssoErrorCookieName = t
        default: break
        }
        text = ""
    }
}
