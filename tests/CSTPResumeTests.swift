import Foundation

func testCSTPResumeRequestIncludesCookieAndReconnectHeader() {
    R.enter("CSTPTunnel: resume CONNECT request shape")
    let req = CSTPTunnel.buildConnectRequest(host: "vpn.example.com",
                                             cookie: "abcd1234",
                                             reconnect: true)
    R.assertTrue(req.hasPrefix("CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n"),
                 "request line")
    R.assertTrue(req.contains("Host: vpn.example.com\r\n"), "Host header")
    R.assertTrue(req.contains("Cookie: webvpn=abcd1234\r\n"), "cookie reuses existing session")
    R.assertTrue(req.contains("X-CSTP-Reconnect: true\r\n"),
                 "X-CSTP-Reconnect header signals server to skip session init")
    R.assertTrue(req.hasSuffix("\r\n\r\n"), "double CRLF terminates headers")
}

func testCSTPInitialRequestOmitsReconnectHeader() {
    R.enter("CSTPTunnel: initial CONNECT request shape")
    let req = CSTPTunnel.buildConnectRequest(host: "vpn.example.com",
                                             cookie: "xyz",
                                             reconnect: false)
    R.assertTrue(req.contains("Cookie: webvpn=xyz\r\n"), "cookie present")
    R.assertTrue(!req.contains("X-CSTP-Reconnect"),
                 "no reconnect header on initial CONNECT")
    R.assertTrue(req.contains("X-CSTP-Version: 1\r\n"), "version header")
}
