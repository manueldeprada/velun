import Foundation

private struct ASAFormSnapshot {
    var action:          String  = "/+webvpn+/index.html"
    var formFieldNames:  Set<String> = []
    var hiddenFields:    [String: String] = [:]
    var sessionToken:    String? = nil
    var authComplete:    Bool    = false
    var errorMessage:    String? = nil
}

private final class ASAFormParser: NSObject, XMLParserDelegate {
    var snap = ASAFormSnapshot()
    private var element = ""
    private var text    = ""
    func parse(_ xml: String) -> ASAFormSnapshot {
        guard let data = xml.data(using: .utf8) else { return snap }
        let p = XMLParser(data: data); p.delegate = self
        p.parse()
        return snap
    }
    func parser(_ parser: XMLParser, didStartElement n: String, namespaceURI: String?,
                qualifiedName: String?, attributes a: [String: String] = [:]) {
        element = n; text = ""
        switch n {
        case "form":
            if let v = a["action"] { snap.action = v }
        case "auth":
            if a["id"] == "success" { snap.authComplete = true }
        case "input":
            if let name = a["name"] { snap.formFieldNames.insert(name) }
            if a["type"] == "hidden", let k = a["name"], let v = a["value"] {
                snap.hiddenFields[k] = v
            }
        default: break
        }
    }
    func parser(_ parser: XMLParser, foundCharacters s: String) { text += s }
    func parser(_ parser: XMLParser, didEndElement n: String, namespaceURI: String?,
                qualifiedName: String?) {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        switch n {
        case "session-token":
            snap.sessionToken = t; snap.authComplete = true
        case "error":
            snap.errorMessage = t
        default: break
        }
    }
}

func testAnyConnectFormParsing() {
    R.enter("AnyConnect form parsing")

    // 1. Initial auth form with group_list + secondary_password (2FA realm)
    let form = """
    <?xml version="1.0" encoding="UTF-8"?>
    <auth id="main">
      <form action="/+webvpn+/index.html" method="post">
        <input type="text" name="username"/>
        <input type="password" name="password"/>
        <input type="password" name="secondary_password"/>
        <input type="hidden" name="tgroup" value="2fa"/>
        <input type="submit" name="Login" value="Login"/>
        <select name="group_list">
          <option>student-net</option>
          <option>staff-net</option>
        </select>
      </form>
    </auth>
    """
    let snap = ASAFormParser().parse(form)
    R.assertEqual(snap.action, "/+webvpn+/index.html", "form action")
    R.assertTrue(snap.formFieldNames.contains("secondary_password"),
                 "form declares secondary_password (TOTP slot)")
    R.assertTrue(snap.formFieldNames.contains("password"), "form declares password")
    R.assertTrue(snap.formFieldNames.contains("username"), "form declares username")
    R.assertEqual(snap.hiddenFields["tgroup"] ?? "", "2fa",
                  "tgroup hidden field captured for echo-back")

    let single = """
    <?xml version="1.0"?>
    <auth id="main">
      <form action="/+webvpn+/index.html"><input name="username"/><input name="password"/></form>
    </auth>
    """
    let s2 = ASAFormParser().parse(single)
    R.assertTrue(!s2.formFieldNames.contains("secondary_password"),
                 "single-realm form has no secondary_password field")
    R.assertTrue(!s2.formFieldNames.contains("group_list"),
                 "single-realm form has no group_list field")

    // 3. Success response: <auth id="success">
    let ok = """
    <?xml version="1.0"?>
    <auth id="success"><success/></auth>
    """
    let s3 = ASAFormParser().parse(ok)
    R.assertTrue(s3.authComplete, "auth id=success → authComplete")

    // 4. Error response: <error id="15">Login failed.</error>
    let bad = """
    <?xml version="1.0"?>
    <auth id="main"><message id="login-error"><error id="15">Login failed.</error></message></auth>
    """
    let s4 = ASAFormParser().parse(bad)
    R.assertEqual(s4.errorMessage, "Login failed.", "error text captured")
}
