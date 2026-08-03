import Foundation

func testGPLoginXML() {
    R.enter("GPLoginXML")

    let xml = """
    <?xml version="1.0" encoding="UTF-8" ?>
    <jnlp>
      <application-desc>
        <argument>(empty)</argument>
        <argument>VelunPortal</argument>
        <argument>SECRET-AUTH-COOKIE-12345</argument>
        <argument>PRELOG-ABCD</argument>
        <argument>USERAUTH-XYZ</argument>
        <argument>(null)</argument>
        <argument>(null)</argument>
        <argument>(null)</argument>
        <argument>(null)</argument>
        <argument>(null)</argument>
        <argument>(null)</argument>
        <argument>(null)</argument>
        <argument>(null)</argument>
        <argument>(empty)</argument>
        <argument>corp.example.com</argument>
        <argument>alice@corp.example.com</argument>
      </application-desc>
    </jnlp>
    """
    let p = GPLoginXML.parse(xml)
    R.assertEqual(p.portal,                    "VelunPortal",              "portal arg[1]")
    R.assertEqual(p.authcookie,                "SECRET-AUTH-COOKIE-12345", "authcookie arg[2]")
    R.assertEqual(p.preloginCookie,            "PRELOG-ABCD",              "prelogin arg[3]")
    R.assertEqual(p.portalUserAuthCookie,      "USERAUTH-XYZ",             "portal-userauth arg[4]")
    R.assertEqual(p.domain,                    "corp.example.com",         "domain arg[14]")
    R.assertEqual(p.username,                  "alice@corp.example.com",   "username arg[15]")
    R.assertTrue(p.errorMessage == nil,                                    "no error on success")

    // Error response shape — should surface in errorMessage, not as a parse failure.
    let errXML = """
    <?xml version="1.0"?>
    <response status="error">
      <msg>Invalid username or password.</msg>
    </response>
    """
    let pe = GPLoginXML.parse(errXML)
    R.assertEqual(pe.errorMessage, "Invalid username or password.", "error msg surfaced")
    R.assertEqual(pe.authcookie, "", "no authcookie on error")
}

func testGPGetConfigXML() throws {
    R.enter("GPGetConfigXML")

    let xml = """
    <response>
      <ip-address>10.20.30.40</ip-address>
      <netmask>255.255.255.0</netmask>
      <mtu>1400</mtu>
      <gw-address>10.20.30.1</gw-address>
      <dns>
        <member>10.20.30.5</member>
        <member>10.20.30.6</member>
      </dns>
      <dns-suffix>
        <member>corp.example.com</member>
      </dns-suffix>
      <access-routes>
        <member>10.0.0.0/8</member>
        <member>172.16.0.0/12</member>
      </access-routes>
      <exclude-access-routes>
        <member>192.168.0.0/16</member>
      </exclude-access-routes>
    </response>
    """
    let cfg = try GPGetConfigXML.parse(xml)
    R.assertEqual(cfg.ipAddress, "10.20.30.40", "ip-address")
    R.assertEqual(cfg.netmask,   "255.255.255.0", "netmask")
    R.assertEqual(cfg.gateway,   "10.20.30.1", "gw-address")
    R.assertEqual(cfg.mtu,       1400,         "mtu")
    R.assertEqual(cfg.dnsServers, ["10.20.30.5", "10.20.30.6"], "dns members")
    R.assertEqual(cfg.searchDomains, ["corp.example.com"], "dns suffix")
    R.assertEqual(cfg.splitIncludes, ["10.0.0.0/8", "172.16.0.0/12"], "access-routes")
    R.assertEqual(cfg.splitExcludes, ["192.168.0.0/16"], "exclude-access-routes")
}

func testGPGetConfigXMLMissingIP() {
    R.enter("GPGetConfigXML missing IP")
    let xml = "<response><netmask>255.255.255.0</netmask></response>"
    do {
        _ = try GPGetConfigXML.parse(xml)
        R.assertTrue(false, "should have thrown for missing ip-address")
    } catch {
        R.assertTrue(true, "throws on missing ip-address")
    }
}
