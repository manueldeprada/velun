import Foundation

func testPPPFraming() {
    R.enter("PPPFraming")

    // 1. Standard frame: ff 03 [00 21] [ip body...]
    do {
        let body = Data([0x45, 0x00, 0x00, 0x14])  // truncated IPv4 header
        let frame = Data([0xff, 0x03, 0x00, 0x21]) + body
        guard let (proto, payload) = PPPFraming.decode(frame) else {
            R.assertTrue(false, "decode returned nil for valid frame")
            return
        }
        R.assertEqual(proto, 0x0021, "IPv4 protocol number")
        R.assertEqual(payload, body, "payload preserved")
    }

    // 2. Compressed PFC: ff 03 [21] [body] (1-byte proto, low bit set)
    do {
        let body = Data([0x45, 0x00])
        let frame = Data([0xff, 0x03, 0x21]) + body
        guard let (proto, payload) = PPPFraming.decode(frame) else {
            R.assertTrue(false, "decode returned nil for PFC frame")
            return
        }
        R.assertEqual(proto, 0x0021, "compressed proto expands to 0x0021")
        R.assertEqual(payload, body, "compressed-proto payload preserved")
    }

    // 3. Frame without 0xff 0x03 prefix (ACFC compressed)
    do {
        let body = Data([0xab, 0xcd])
        let frame = Data([0xc0, 0x21]) + body  // LCP proto without addr/control
        guard let (proto, payload) = PPPFraming.decode(frame) else {
            R.assertTrue(false, "decode returned nil for ACFC-compressed frame")
            return
        }
        R.assertEqual(proto, 0xC021, "LCP proto without ff 03 prefix")
        R.assertEqual(payload, body, "ACFC payload preserved")
    }

    // 4. Empty frame → nil
    R.assertTrue(PPPFraming.decode(Data()) == nil, "empty frame → nil")

    // 5. Truncated to 1 byte (would-be uncompressed proto MSB) → nil
    R.assertTrue(PPPFraming.decode(Data([0xff, 0x03, 0x00])) == nil,
                 "truncated 2-byte proto → nil")

    // 6. Round-trip encode → decode → original
    do {
        let body = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let enc = PPPFraming.encode(proto: 0x8021, body: body)
        guard let (proto, payload) = PPPFraming.decode(enc) else {
            R.assertTrue(false, "round-trip decode failed")
            return
        }
        R.assertEqual(proto, 0x8021, "round-trip IPCP proto")
        R.assertEqual(payload, body, "round-trip body")
    }

    // 7. IPv6 protocol number (0x0057) — important for dual-stack.
    do {
        let frame = PPPFraming.encode(proto: 0x0057, body: Data([0x60, 0x00]))
        if let (p, _) = PPPFraming.decode(frame) {
            R.assertEqual(p, 0x0057, "IPv6 proto preserved")
        } else {
            R.assertTrue(false, "IPv6 frame failed to decode")
        }
    }
}
