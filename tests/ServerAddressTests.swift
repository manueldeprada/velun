import Foundation

func testServerAddressBareHost() {
    R.enter("ServerAddress bare host")
    let a = ServerAddress.parse("vpn.example.com")
    R.assertEqual(a.host, "vpn.example.com", "bare host")
    R.assertTrue(a.port == nil, "bare host has no explicit port")
    R.assertEqual(a.group, "", "bare host has no group")
}

func testServerAddressHostPort() {
    R.enter("ServerAddress host:port")
    let a = ServerAddress.parse("vpn.example.com:10443")
    R.assertEqual(a.host, "vpn.example.com", "host:port host")
    R.assertEqual(a.port, 10443, "host:port port")
    R.assertEqual(a.group, "", "host:port no group")
}

func testServerAddressHostPortPath() {
    // The motivating case: NTT Data writes host:port/group in one field.
    R.enter("ServerAddress host:port/path (NTT Data)")
    let a = ServerAddress.parse("cbcn52fclas03b.rdc.emeal.nttdata.com:695/anyconnect-win")
    R.assertEqual(a.host, "cbcn52fclas03b.rdc.emeal.nttdata.com", "splits host off port+path")
    R.assertEqual(a.port, 695, "extracts the non-default port")
    R.assertEqual(a.group, "anyconnect-win", "first path segment is the group hint")
}

func testServerAddressScheme() {
    R.enter("ServerAddress scheme + path")
    let a = ServerAddress.parse("https://vpn.example.com/student-net")
    R.assertEqual(a.host, "vpn.example.com", "strips https scheme")
    R.assertTrue(a.port == nil, "no port given")
    R.assertEqual(a.group, "student-net", "path becomes group")
}

func testServerAddressSchemePortPath() {
    R.enter("ServerAddress scheme + port + multi-segment path + query")
    let a = ServerAddress.parse("https://vpn.example.com:8443/grp/extra?x=1")
    R.assertEqual(a.host, "vpn.example.com", "scheme+port+path host")
    R.assertEqual(a.port, 8443, "scheme+port+path port")
    R.assertEqual(a.group, "grp", "only the first path segment, query stripped")
}

func testServerAddressTrailingSlashNoGroup() {
    R.enter("ServerAddress trailing slash")
    let a = ServerAddress.parse("vpn.example.com:443/")
    R.assertEqual(a.host, "vpn.example.com", "trailing slash host")
    R.assertEqual(a.port, 443, "trailing slash port")
    R.assertEqual(a.group, "", "trailing slash yields no group")
}

func testServerAddressIPv4Literal() {
    R.enter("ServerAddress IPv4 literal")
    let a = ServerAddress.parse("10.0.0.1:1234")
    R.assertEqual(a.host, "10.0.0.1", "ipv4 host")
    R.assertEqual(a.port, 1234, "ipv4 port")
}

func testServerAddressBareIPv6Untouched() {
    R.enter("ServerAddress bare IPv6 untouched")
    let a = ServerAddress.parse("2001:db8::1")
    R.assertEqual(a.host, "2001:db8::1", "bare ipv6 left intact")
    R.assertTrue(a.port == nil, "bare ipv6 has no parsed port")
}

func testServerAddressBracketedIPv6Port() {
    R.enter("ServerAddress bracketed IPv6 + port")
    let a = ServerAddress.parse("[2001:db8::1]:443")
    R.assertEqual(a.host, "2001:db8::1", "bracketed ipv6 host")
    R.assertEqual(a.port, 443, "bracketed ipv6 port")
}

func testServerAddressBracketedIPv6NoPort() {
    R.enter("ServerAddress bracketed IPv6, no port")
    let a = ServerAddress.parse("[2001:db8::1]")
    R.assertEqual(a.host, "2001:db8::1", "bracketed ipv6 host, no port")
    R.assertTrue(a.port == nil, "bracketed ipv6 no port")
}

func testServerAddressRejectsOutOfRangePort() {
    // 70000 is not a valid port → not parsed; the colon stays part of the host.
    R.enter("ServerAddress rejects out-of-range port")
    let a = ServerAddress.parse("vpn.example.com:70000")
    R.assertEqual(a.host, "vpn.example.com:70000", "out-of-range port left as host text")
    R.assertTrue(a.port == nil, "out-of-range port not parsed")
}

func testServerAddressTrimsWhitespace() {
    R.enter("ServerAddress trims whitespace")
    let a = ServerAddress.parse("  vpn.example.com:695/grp  ")
    R.assertEqual(a.host, "vpn.example.com", "trims surrounding whitespace")
    R.assertEqual(a.port, 695, "port after trim")
    R.assertEqual(a.group, "grp", "group after trim")
}
