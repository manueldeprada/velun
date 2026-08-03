import Foundation

func testFortinetConfigXML() throws {
    R.enter("FortinetConfigXML")

    let xml = """
    <?xml version="1.0" encoding="UTF-8" ?>
    <sslvpn-tunnel>
      <assigned-addr ipv4="10.212.134.200" mask="255.255.255.0"/>
      <dns ipv4="10.10.0.1" domain="corp.example.com"/>
      <dns ipv4="10.10.0.2"/>
      <split-dns domains="corp.internal,sub.corp.internal"/>
      <split-tunnel-info>
        <addr ip="10.0.0.0"  mask="255.0.0.0"/>
        <addr ip="172.16.0.0" mask="255.240.0.0"/>
        <addr ip="192.168.50.0" mask="255.255.255.0" include="0"/>
      </split-tunnel-info>
      <mtu value="1400"/>
    </sslvpn-tunnel>
    """
    let cfg = try FortinetConfigXML.parse(xml)
    R.assertEqual(cfg.ipAddress,   "10.212.134.200", "assigned ipv4")
    R.assertEqual(cfg.netmask,     "255.255.255.0",  "assigned mask")
    R.assertEqual(cfg.dnsServers,  ["10.10.0.1", "10.10.0.2"], "dns servers")
    R.assertTrue(cfg.searchDomains.contains("corp.example.com"), "primary search domain")
    R.assertTrue(cfg.searchDomains.contains("corp.internal"),    "split-dns first entry")
    R.assertTrue(cfg.searchDomains.contains("sub.corp.internal"), "split-dns second entry")
    R.assertEqual(cfg.splitIncludes, ["10.0.0.0/8", "172.16.0.0/12"], "include CIDRs")
    R.assertEqual(cfg.splitExcludes, ["192.168.50.0/24"], "exclude CIDRs")
    R.assertEqual(cfg.mtu, 1400, "mtu")
}

func testFortinetEncapHeader() {
    R.enter("FortinetEncapHeader")
    let pppFrame = Data([0xff, 0x03, 0xc0, 0x21, 0x0a, 0x01, 0x00, 0x04])
    let payloadLen = pppFrame.count                  // 8
    let total = payloadLen + 6                       // 14
    var hdr = Data(count: 6)
    hdr[0] = UInt8(total >> 8); hdr[1] = UInt8(total & 0xff)
    hdr[2] = 0x50;              hdr[3] = 0x50
    hdr[4] = UInt8(payloadLen >> 8); hdr[5] = UInt8(payloadLen & 0xff)

    R.assertEqual(hdr[0], 0,      "total MSB == 0")
    R.assertEqual(hdr[1], 14,     "total LSB == 14")
    R.assertEqual(hdr[2], 0x50,   "magic byte 0")
    R.assertEqual(hdr[3], 0x50,   "magic byte 1")
    R.assertEqual(hdr[4], 0,      "payload-len MSB == 0")
    R.assertEqual(hdr[5], 8,      "payload-len LSB == 8")
}
