import Foundation

func testTOTP() {
    R.enter("TOTPGenerator (RFC 6238 vectors)")

    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    let cases: [(UInt64, String)] = [
        (59,         "287082"),  // RFC 6238 first vector (truncated to 6)
        (1111111109, "081804"),
        (1111111111, "050471"),
        (1234567890, "005924"),
        (2000000000, "279037"),
    ]

    for (t, expected) in cases {
        let actual = TOTPGenerator.generate(secret: secret,
                                            time: t,
                                            digits: 6,
                                            period: 30)
        R.assertEqual(actual, expected, "RFC vector at t=\(t)")
    }
}

func testTOTPBase32Permissiveness() {
    R.enter("TOTP base32 input permissiveness")
    let canonical = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    let variants  = [
        canonical,
        "base32:\(canonical)",
        canonical.lowercased(),
        " \(canonical) ",
        canonical.replacingOccurrences(of: "G", with: " G ")
            .trimmingCharacters(in: .whitespaces),
    ]
    let t: UInt64 = 1234567890
    let ref = TOTPGenerator.generate(secret: canonical, time: t, digits: 6, period: 30)
    for v in variants {
        let got = TOTPGenerator.generate(secret: v, time: t, digits: 6, period: 30)
        R.assertEqual(got, ref, "variant '\(v.prefix(20))…' generates same code")
    }
}
