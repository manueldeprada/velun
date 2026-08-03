import Foundation

func testXMLPostInitRequest() {
    R.enter("XMLPost/init request")
    let xml = VPNAuthClient.buildConfigAuthInit(host: "sslvpn.ethz.ch",
                                                group: "student-net", version: "4.10.07062")
    R.assertTrue(xml.contains(#"<config-auth client="vpn" type="init" aggregate-auth-version="2">"#),
                 "init root with client/type/aggregate-auth-version")
    R.assertTrue(xml.contains("<group-access>https://sslvpn.ethz.ch/student-net</group-access>"),
                 "group-access URL includes the group path")
    let xml695 = VPNAuthClient.buildConfigAuthInit(host: "vpn.corp", port: 695,
                                                   group: "anyconnect-win", version: "1")
    R.assertTrue(xml695.contains("<group-access>https://vpn.corp:695/anyconnect-win</group-access>"),
                 "non-443 port included in group-access")
    R.assertTrue(xml.contains("<capabilities/>"), "empty capabilities element present")
    R.assertTrue(!xml.contains("group-select"), "group conveyed by path/URL, not <group-select>")
    R.assertTrue(xml.contains(#"<version who="vpn">4.10.07062</version>"#), "version node")
    R.assertTrue(xml.contains("<device-id>mac-intel</device-id>"), "device-id")
    R.assertTrue(!xml.contains("single-sign-on"), "no SSO capability advertised (local auth)")
}

func testXMLPostInitNoGroup() {
    R.enter("XMLPost/init no group")
    let xml = VPNAuthClient.buildConfigAuthInit(host: "vpn.example", group: "", version: "1")
    R.assertTrue(!xml.contains("group-select"), "no group → no <group-select>")
    R.assertTrue(xml.contains("<group-access>https://vpn.example/</group-access>"),
                 "no group → group-access is host URL WITH trailing slash")
}

func testXMLPostAuthReplyEchoesOpaqueAndFields() {
    R.enter("XMLPost/auth-reply")
    let opaque = #"<opaque is-for="sg"><tunnel-group>student-net</tunnel-group><config-hash>42</config-hash></opaque>"#
    let fields: [(String, String)] = [
        ("username", "mdeprada@student-net.ethz.ch"),
        ("password", "pw"),
        ("secondary_password", "123456"),
    ]
    let xml = VPNAuthClient.buildConfigAuthReply(opaque: opaque, authFields: fields,
                                                 version: "4.10.07062")
    R.assertTrue(xml.contains(#"type="auth-reply""#), "auth-reply type")
    R.assertTrue(xml.contains("<capabilities/>"), "capabilities element present")
    R.assertTrue(xml.contains(opaque), "opaque echoed verbatim (byte-for-byte)")
    R.assertTrue(xml.contains("<username>mdeprada@student-net.ethz.ch</username>"), "username element")
    R.assertTrue(xml.contains("<password>pw</password>"), "password element")
    R.assertTrue(xml.contains("<secondary_password>123456</secondary_password>"), "TOTP in secondary_password")
    R.assertTrue(!xml.contains("group-select"), "no <group-select> in auth-reply")
    // <auth> wraps the credential fields.
    R.assertTrue(xml.contains("<auth><username>"), "<auth> opens with the first field")
}

func testXMLPostAuthReplyNoOpaqueNoSecondary() {
    R.enter("XMLPost/auth-reply minimal")
    let xml = VPNAuthClient.buildConfigAuthReply(opaque: nil,
                                                 authFields: [("username", "u"), ("password", "p")],
                                                 version: "1")
    R.assertTrue(!xml.contains("<opaque"), "nil opaque → nothing echoed")
    R.assertTrue(!xml.contains("secondary"), "no secondary fields when not declared")
}

func testXMLPostSSOAuthReply() {
    R.enter("XMLPost/SSO auth-reply")
    let opaque = #"<opaque is-for="sg"><aggauth-handle>9981</aggauth-handle></opaque>"#
    let xml = VPNAuthClient.buildConfigAuthReply(
        opaque: opaque,
        authFields: [("sso-token", "AAdzZWNyZXRfc2FtbF90b2tlbg==")],
        version: "4.10.07062")
    R.assertTrue(xml.contains(#"type="auth-reply""#), "auth-reply type")
    R.assertTrue(xml.contains(opaque), "opaque echoed verbatim")
    R.assertTrue(xml.contains("<auth><sso-token>AAdzZWNyZXRfc2FtbF90b2tlbg==</sso-token></auth>"),
                 "SSO token under its field name inside <auth>")
    R.assertTrue(!xml.contains("<password>"), "no password field in an SSO reply")
}

func testXMLPostEscaping() {
    R.enter("XMLPost/escaping")
    R.assertEqual(VPNAuthClient.xmlEscape("a&b<c>d\"e'f"), "a&amp;b&lt;c&gt;d&quot;e&apos;f", "all five entities")
    // A password with XML metacharacters must not break the document.
    let xml = VPNAuthClient.buildConfigAuthReply(opaque: nil,
                                                 authFields: [("password", "p&<>\"'x")],
                                                 version: "1")
    R.assertTrue(xml.contains("<password>p&amp;&lt;&gt;&quot;&apos;x</password>"), "password escaped")
}

func testXMLPostExtractOpaque() {
    R.enter("XMLPost/extract opaque")
    let body = """
    <?xml version="1.0"?>
    <config-auth>
      <opaque is-for="sg">
        <tunnel-group>student-net</tunnel-group>
      </opaque>
      <auth id="main"><form><input name="username"/></form></auth>
    </config-auth>
    """
    let op = VPNAuthClient.extractOpaque(from: body)
    R.assertTrue(op != nil, "opaque found")
    R.assertTrue(op?.hasPrefix("<opaque is-for=\"sg\">") ?? false, "starts at the opening tag")
    R.assertTrue(op?.hasSuffix("</opaque>") ?? false, "ends at the closing tag")
    R.assertTrue(op?.contains("<tunnel-group>student-net</tunnel-group>") ?? false, "inner content preserved")
    R.assertTrue(VPNAuthClient.extractOpaque(from: "<config-auth><auth/></config-auth>") == nil,
                 "no opaque → nil")
}

func testXMLPostParsesConfigAuthResponse() {
    R.enter("XMLPost/parse config-auth response")
    let initResp = """
    <?xml version="1.0"?>
    <config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
      <opaque is-for="sg"><tg>x</tg></opaque>
      <auth id="main">
        <form action="/+webvpn+/index.html">
          <input type="text" name="username"/>
          <input type="password" name="password"/>
          <input type="password" name="secondary_password"/>
        </form>
      </auth>
    </config-auth>
    """
    let parser = ASAFormParser2()
    let s = parser.parse(initResp)
    R.assertTrue(s.fields.contains("username"), "username field parsed from config-auth")
    R.assertTrue(s.fields.contains("secondary_password"), "secondary_password field parsed")
    R.assertTrue(!s.authComplete, "auth-request form is not success")

    // Success response: config-auth with session-token + auth id=success.
    let okResp = """
    <?xml version="1.0"?>
    <config-auth type="complete">
      <session-token>SESSIONTOKEN123</session-token>
      <auth id="success"><message>Success</message></auth>
    </config-auth>
    """
    let ok = ASAFormParser2().parse(okResp)
    R.assertTrue(ok.authComplete, "auth id=success in config-auth → complete")
    R.assertEqual(ok.sessionToken ?? "", "SESSIONTOKEN123", "session-token extracted from config-auth")
}

private struct ASAFormSnap2 {
    var fields: Set<String> = []
    var authComplete = false
    var sessionToken: String?
}
private final class ASAFormParser2: NSObject, XMLParserDelegate {
    private var snap = ASAFormSnap2()
    private var text = ""
    func parse(_ xml: String) -> ASAFormSnap2 {
        guard let data = xml.data(using: .utf8) else { return snap }
        let p = XMLParser(data: data); p.delegate = self; p.parse()
        return snap
    }
    func parser(_ parser: XMLParser, didStartElement n: String, namespaceURI: String?,
                qualifiedName: String?, attributes a: [String: String] = [:]) {
        text = ""
        if n == "auth", a["id"] == "success" { snap.authComplete = true }
        if n == "input", let name = a["name"] { snap.fields.insert(name) }
    }
    func parser(_ parser: XMLParser, foundCharacters s: String) { text += s }
    func parser(_ parser: XMLParser, didEndElement n: String, namespaceURI: String?,
                qualifiedName: String?) {
        if n == "session-token" {
            snap.sessionToken = text.trimmingCharacters(in: .whitespacesAndNewlines)
            snap.authComplete = true
        }
    }
}
