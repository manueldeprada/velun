import Foundation

// MARK: – Small protobuf encoder, just for tests.

private func varintBytes(_ value: UInt64) -> [UInt8] {
    var v = value
    var out: [UInt8] = []
    while true {
        let byte = UInt8(v & 0x7f)
        v >>= 7
        if v == 0 { out.append(byte); return out }
        out.append(byte | 0x80)
    }
}

private func tag(_ field: Int, wire: UInt64) -> [UInt8] {
    varintBytes(UInt64(field) << 3 | wire)
}

/// `bytes` field (wire = 2): tag, length-varint, payload.
private func encodeBytes(_ field: Int, _ payload: [UInt8]) -> [UInt8] {
    tag(field, wire: 2) + varintBytes(UInt64(payload.count)) + payload
}

private func encodeString(_ field: Int, _ s: String) -> [UInt8] {
    encodeBytes(field, Array(s.utf8))
}

private func encodeVarint(_ field: Int, _ value: UInt64) -> [UInt8] {
    tag(field, wire: 0) + varintBytes(value)
}

// MARK: – OtpParameters builder.

private struct OtpFields {
    var secret:    [UInt8]
    var name:      String
    var issuer:    String
    var algorithm: UInt64 = 1   // 0=unspec, 1=SHA1, 2=SHA256, 3=SHA512, 4=MD5
    var digits:    UInt64 = 1   // 0=unspec, 1=SIX, 2=EIGHT
    var type:      UInt64 = 2   // 0=unspec, 1=HOTP, 2=TOTP
}

private func buildOtpParameters(_ p: OtpFields) -> [UInt8] {
    var out: [UInt8] = []
    out += encodeBytes (1, p.secret)
    out += encodeString(2, p.name)
    out += encodeString(3, p.issuer)
    out += encodeVarint(4, p.algorithm)
    out += encodeVarint(5, p.digits)
    out += encodeVarint(6, p.type)
    return out
}

private func buildMigrationPayload(_ params: [OtpFields]) -> [UInt8] {
    var out: [UInt8] = []
    for p in params {
        let inner = buildOtpParameters(p)
        out += encodeBytes(1, inner)
    }
    out += encodeVarint(2, 1)        // version = 1
    return out
}

private func migrationURL(_ payload: [UInt8]) -> String {
    let b64 = Data(payload).base64EncodedString()
    let pct = b64.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? b64
    return "otpauth-migration://offline?data=\(pct)"
}

private let rfc6238SecretBytes: [UInt8] = Array("12345678901234567890".utf8)
private let rfc6238SecretB32   = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// MARK: – Tests.

func testBase32Encode() {
    R.enter("Base32 encoder (RFC 4648 vectors)")

    R.assertEqual(Base32.encode(Data()), "", "empty")
    R.assertEqual(Base32.encode(Data([0x66])), "MY", "f")
    R.assertEqual(Base32.encode(Data([0x66, 0x6f])), "MZXQ", "fo")
    R.assertEqual(Base32.encode(Data([0x66, 0x6f, 0x6f])), "MZXW6", "foo")
    R.assertEqual(Base32.encode(Data([0x66, 0x6f, 0x6f, 0x62])), "MZXW6YQ", "foob")
    R.assertEqual(Base32.encode(Data([0x66, 0x6f, 0x6f, 0x62, 0x61])), "MZXW6YTB", "fooba")
    R.assertEqual(Base32.encode(Data([0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72])), "MZXW6YTBOI", "foobar")

    R.assertEqual(Base32.encode(Data(rfc6238SecretBytes)), rfc6238SecretB32,
                  "RFC 6238 20-byte secret")
}

func testOTPAuthURLParse() {
    R.enter("otpauth:// URL parser")

    do {
        let url = "otpauth://totp/ACME:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&period=30"
        let accs = try OTPSecretImporter.parse(url)
        R.assertEqual(accs.count, 1, "single account")
        R.assertEqual(accs[0].issuer, "ACME", "issuer from query (matches path)")
        R.assertEqual(accs[0].name, "alice@example.com", "name stripped of issuer prefix")
        R.assertEqual(accs[0].secretBase32, "JBSWY3DPEHPK3PXP", "secret kept as-is")
        R.assertEqual(accs[0].algorithm, .sha1, "alg")
        R.assertEqual(accs[0].digits, 6, "digits")
        R.assertEqual(accs[0].type, .totp, "totp")
        R.assertTrue(accs[0].isStandardTOTP, "isStandardTOTP")
    } catch {
        R.assertTrue(false, "threw: \(error)")
    }

    // Issuer only in the path label, no `issuer=` query param.
    do {
        let url = "otpauth://totp/Foo:bar?secret=AAAA"
        let accs = try OTPSecretImporter.parse(url)
        R.assertEqual(accs[0].issuer, "Foo", "issuer extracted from path")
        R.assertEqual(accs[0].name, "bar", "name after colon")
    } catch {
        R.assertTrue(false, "threw: \(error)")
    }

    // Lowercase secret + whitespace are normalised.
    do {
        let url = "otpauth://totp/x?secret=jbsw%20y3dp"
        let accs = try OTPSecretImporter.parse(url)
        R.assertEqual(accs[0].secretBase32, "JBSWY3DP", "uppercased + whitespace stripped")
    } catch {
        R.assertTrue(false, "threw: \(error)")
    }

    // HOTP (counter-based): preserved, but isStandardTOTP false.
    do {
        let accs = try OTPSecretImporter.parse("otpauth://hotp/x?secret=JBSWY3DP&counter=42")
        R.assertEqual(accs[0].type, .hotp, "hotp scheme detected")
        R.assertTrue(!accs[0].isStandardTOTP, "hotp not standard TOTP")
    } catch {
        R.assertTrue(false, "threw: \(error)")
    }

    // Missing secret throws.
    do {
        _ = try OTPSecretImporter.parse("otpauth://totp/x?issuer=Y")
        R.assertTrue(false, "expected throw for missing secret")
    } catch let OTPSecretImporter.ImportError.missingSecret {
        R.assertTrue(true, "missingSecret thrown")
    } catch {
        R.assertTrue(false, "wrong error: \(error)")
    }

    // Unsupported scheme throws.
    do {
        _ = try OTPSecretImporter.parse("https://example.com/")
        R.assertTrue(false, "expected throw for non-otpauth scheme")
    } catch let OTPSecretImporter.ImportError.unsupportedScheme(s) {
        R.assertEqual(s, "https", "scheme name in error")
    } catch {
        R.assertTrue(false, "wrong error: \(error)")
    }
}

func testMigrationSingleAccount() {
    R.enter("otpauth-migration:// parser — single account")

    let payload = buildMigrationPayload([
        OtpFields(secret: rfc6238SecretBytes, name: "alice@example.com", issuer: "ACME"),
    ])
    let url = migrationURL(payload)

    do {
        let accs = try OTPSecretImporter.parse(url)
        R.assertEqual(accs.count, 1, "one account")
        R.assertEqual(accs[0].name, "alice@example.com", "name")
        R.assertEqual(accs[0].issuer, "ACME", "issuer")
        R.assertEqual(accs[0].secretBase32, rfc6238SecretB32,
                      "secret base32 matches RFC 6238 canonical")
        R.assertEqual(accs[0].algorithm, .sha1, "alg")
        R.assertEqual(accs[0].digits, 6, "digits")
        R.assertEqual(accs[0].type, .totp, "type")

        let t: UInt64 = 1234567890
        let viaParsed   = TOTPGenerator.generate(secret: accs[0].secretBase32, time: t)
        let viaCanonical = TOTPGenerator.generate(secret: rfc6238SecretB32,    time: t)
        R.assertEqual(viaParsed, viaCanonical, "TOTP round-trip")
        R.assertEqual(viaParsed, "005924", "RFC 6238 code at t=1234567890")
    } catch {
        R.assertTrue(false, "threw: \(error)")
    }
}

func testMigrationMultipleAccounts() {
    R.enter("otpauth-migration:// parser — multiple accounts + filtering")

    let payload = buildMigrationPayload([
        OtpFields(secret: [0x01, 0x02, 0x03], name: "primary", issuer: "Issuer1"),
        OtpFields(secret: [0x04, 0x05, 0x06], name: "secondary", issuer: "Issuer2",
                  algorithm: 2 /* SHA256 */),
        OtpFields(secret: [0x07, 0x08, 0x09], name: "counter", issuer: "Issuer3",
                  type: 1 /* HOTP */),
    ])
    let url = migrationURL(payload)

    do {
        let accs = try OTPSecretImporter.parse(url)
        R.assertEqual(accs.count, 3, "three accounts decoded")

        R.assertEqual(accs[0].issuer, "Issuer1", "first issuer")
        R.assertTrue(accs[0].isStandardTOTP, "first is standard TOTP")

        R.assertEqual(accs[1].algorithm, .sha256, "second alg = SHA256")
        R.assertTrue(!accs[1].isStandardTOTP, "second is non-standard (SHA256)")

        R.assertEqual(accs[2].type, .hotp, "third is HOTP")
        R.assertTrue(!accs[2].isStandardTOTP, "third is non-standard (HOTP)")
    } catch {
        R.assertTrue(false, "threw: \(error)")
    }
}

func testMigrationMalformed() {
    R.enter("otpauth-migration:// parser — malformed inputs")

    // Missing data parameter.
    do {
        _ = try OTPSecretImporter.parse("otpauth-migration://offline")
        R.assertTrue(false, "expected throw for missing data")
    } catch let OTPSecretImporter.ImportError.malformedURL {
        R.assertTrue(true, "malformedURL thrown")
    } catch {
        R.assertTrue(false, "wrong error: \(error)")
    }

    // data= present but not valid base64.
    do {
        _ = try OTPSecretImporter.parse("otpauth-migration://offline?data=!!!not-base64!!!")
        R.assertTrue(false, "expected throw for bad base64")
    } catch let OTPSecretImporter.ImportError.malformedMigrationData {
        R.assertTrue(true, "malformedMigrationData thrown")
    } catch {
        R.assertTrue(false, "wrong error: \(error)")
    }

    // data= base64 but truncated protobuf (length-prefix says more than we have).
    do {
        // 0x0a = field 1, wire 2 (length-delimited);  0x05 = length 5; payload = 1 byte "X"
        let payload: [UInt8] = [0x0a, 0x05, 0x58]
        let b64 = Data(payload).base64EncodedString()
        _ = try OTPSecretImporter.parse("otpauth-migration://offline?data=\(b64)")
        R.assertTrue(false, "expected throw for truncated payload")
    } catch let OTPSecretImporter.ImportError.malformedMigrationData {
        R.assertTrue(true, "malformedMigrationData thrown")
    } catch {
        R.assertTrue(false, "wrong error: \(error)")
    }

    // Empty migration payload (valid bytes, but no OtpParameters inside).
    do {
        let payload: [UInt8] = [0x10, 0x01]  // version=1, no otp_parameters
        let b64 = Data(payload).base64EncodedString()
        _ = try OTPSecretImporter.parse("otpauth-migration://offline?data=\(b64)")
        R.assertTrue(false, "expected throw for no accounts")
    } catch let OTPSecretImporter.ImportError.noAccounts {
        R.assertTrue(true, "noAccounts thrown")
    } catch {
        R.assertTrue(false, "wrong error: \(error)")
    }
}

func testMigrationURLSafeBase64() {
    R.enter("otpauth-migration:// parser — URL-safe base64 + missing padding")

    let payload = buildMigrationPayload([
        OtpFields(secret: rfc6238SecretBytes, name: "u", issuer: "I"),
    ])
    let std = Data(payload).base64EncodedString()
    // Convert to URL-safe form, strip padding — what some QR codes produce.
    let urlSafe = std
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")

    do {
        let accs = try OTPSecretImporter.parse("otpauth-migration://offline?data=\(urlSafe)")
        R.assertEqual(accs.count, 1, "URL-safe base64 decodes")
        R.assertEqual(accs[0].secretBase32, rfc6238SecretB32, "secret survives round-trip")
    } catch {
        R.assertTrue(false, "threw on URL-safe input: \(error)")
    }
}
