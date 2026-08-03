import Foundation
import CryptoKit

private func hexD(_ s: String) -> Data { CSTPTunnel.hexDecode(s)! }

func testDTLSPRFKnownAnswerSHA256() {
    R.enter("DTLS: TLS 1.2 PRF known-answer (SHA-256, 100 bytes)")
    let secret = hexD("9bbe436ba940f017b17652849a71db35")
    let seed   = hexD("a0ba9f936cda311827a6f796ffd5198c")
    let expected = hexD("e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a" +
                        "6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab" +
                        "4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701" +
                        "87347b66")
    let out = DTLSPRF.prf(secret: secret, label: "test label", seed: seed, length: 100,
                          cipher: .ecdheRsaAes128GcmSha256)   // SHA-256 suite
    R.assertEqual(out, expected, "PRF-SHA256 matches IETF vector")
}

func testDTLSPRFKnownAnswerSHA384() {
    R.enter("DTLS: TLS 1.2 PRF known-answer (SHA-384, 148 bytes)")
    let secret = hexD("b80b733d6ceefcdc71566ea48e5567df")
    let seed   = hexD("cd665cf6a8447dd6ff8b27555edb7465")
    let expected = hexD("7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cd" +
                        "e9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd" +
                        "8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d918425" +
                        "9b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee6" +
                        "91c8f3a26854308d5eaa3be85e0990703d73e56f")
    let out = DTLSPRF.prf(secret: secret, label: "test label", seed: seed, length: 148,
                          cipher: .ecdheRsaAes256GcmSha384)   // SHA-384 suite
    R.assertEqual(out, expected, "PRF-SHA384 matches IETF vector")
}

// MARK: – Cipher suite mapping

func testDTLSCipherSuiteMapping() {
    R.enter("DTLS: cipher suite mapping")
    R.assertEqual(DTLSCipherSuite.fromOpenSSLName("ECDHE-RSA-AES256-GCM-SHA384"),
                  .ecdheRsaAes256GcmSha384, "256/384 name")
    R.assertEqual(DTLSCipherSuite.fromOpenSSLName("aes128-gcm-sha256"),
                  .rsaAes128GcmSha256, "case-insensitive RSA 128")
    R.assertTrue(DTLSCipherSuite.fromOpenSSLName("DHE-RSA-AES256-SHA") == nil,
                 "unsupported suite → nil")
    R.assertEqual(DTLSCipherSuite.ecdheRsaAes256GcmSha384.rawValue, 0xC030, "C030 codepoint")
    R.assertEqual(DTLSCipherSuite.rsaAes128GcmSha256.rawValue, 0x009C, "009C codepoint")
    R.assertEqual(DTLSCipherSuite.ecdheRsaAes256GcmSha384.keyLen, 32, "AES-256 key length")
    R.assertEqual(DTLSCipherSuite.ecdheRsaAes128GcmSha256.keyLen, 16, "AES-128 key length")
    R.assertEqual(DTLSCipherSuite.rsaAes256GcmSha384.hashLen, 48, "SHA-384 length")
    R.assertEqual(DTLSCipherSuite.rsaAes128GcmSha256.hashLen, 32, "SHA-256 length")
}

// MARK: – Key block derivation

func testDTLSKeyBlockSplit() {
    R.enter("DTLS: key_block split + determinism")
    let ms = Data(repeating: 0x42, count: 48)
    let cr = Data(repeating: 0x01, count: 32)
    let sr = Data(repeating: 0x02, count: 32)

    let k256 = DTLSKeys(masterSecret: ms, clientRandom: cr, serverRandom: sr, cipher: .ecdheRsaAes256GcmSha384)
    R.assertEqual(k256.clientWriteIV.count, 4, "client salt is 4 bytes")
    R.assertEqual(k256.serverWriteIV.count, 4, "server salt is 4 bytes")
    R.assertEqual(k256.clientWriteKey.bitCount, 256, "AES-256 client key")
    R.assertEqual(k256.serverWriteKey.bitCount, 256, "AES-256 server key")
    R.assertTrue(k256.clientWriteIV != k256.serverWriteIV, "client/server salts differ")

    let k128 = DTLSKeys(masterSecret: ms, clientRandom: cr, serverRandom: sr, cipher: .rsaAes128GcmSha256)
    R.assertEqual(k128.clientWriteKey.bitCount, 128, "AES-128 client key")

    let again = DTLSKeys(masterSecret: ms, clientRandom: cr, serverRandom: sr, cipher: .ecdheRsaAes256GcmSha384)
    R.assertEqual(again.clientWriteIV, k256.clientWriteIV, "derivation is deterministic")
}

// MARK: – Record layer

func testDTLSRecordRoundTrip() {
    R.enter("DTLS: GCM record seal → open round-trip")
    let cipher = DTLSCipherSuite.ecdheRsaAes256GcmSha384
    let ms = Data(repeating: 0x42, count: 48)
    let keys = DTLSKeys(masterSecret: ms, clientRandom: Data(repeating: 1, count: 32),
                        serverRandom: Data(repeating: 2, count: 32), cipher: cipher)
    let peerKeys = DTLSKeys(clientWriteKey: keys.serverWriteKey, serverWriteKey: keys.clientWriteKey,
                            clientWriteIV: keys.serverWriteIV, serverWriteIV: keys.clientWriteIV)
    let client = DTLSRecordLayer(cipher: cipher, keys: keys)
    let peer   = DTLSRecordLayer(cipher: cipher, keys: peerKeys)

    let plaintext = Data([0x00]) + Data("hello dtls".utf8)   // 1-byte type prefix + payload
    let rec = try! client.encryptedRecord(type: DTLSWire.ctApplicationData, payload: plaintext)
    let parsed = DTLSRecord.parse(datagram: rec)
    R.assertEqual(parsed.count, 1, "one record parsed")
    R.assertEqual(parsed.first?.epoch ?? 99, 1, "encrypted record is epoch 1")
    R.assertEqual(try? peer.open(parsed[0]), plaintext, "decrypt yields the original plaintext")

    // Second record: sequence advances, still decrypts.
    let rec2 = DTLSRecord.parse(datagram: try! client.encryptedRecord(type: DTLSWire.ctApplicationData, payload: plaintext))
    R.assertEqual(try? peer.open(rec2[0]), plaintext, "second record decrypts")
    R.assertTrue(parsed[0].seq != rec2[0].seq, "record sequence number advances")

    // Tamper the tag → authentication must fail.
    var bad = rec; bad[bad.count - 1] ^= 0xFF
    var threw = false
    do { _ = try peer.open(DTLSRecord.parse(datagram: bad)[0]) } catch { threw = true }
    R.assertTrue(threw, "tampered record fails GCM authentication")
}

func testDTLSRecordHeaderLayout() {
    R.enter("DTLS: record header layout")
    let cipher = DTLSCipherSuite.ecdheRsaAes256GcmSha384
    let keys = DTLSKeys(masterSecret: Data(repeating: 9, count: 48),
                        clientRandom: Data(repeating: 1, count: 32),
                        serverRandom: Data(repeating: 2, count: 32), cipher: cipher)
    let rl = DTLSRecordLayer(cipher: cipher, keys: keys)

    let pt = Data(repeating: 0xAB, count: 20)
    let rec = try! rl.encryptedRecord(type: DTLSWire.ctApplicationData, payload: pt)
    // fragment = explicit_nonce(8) + ciphertext(20) + tag(16) = 44; record = 13 + 44.
    R.assertEqual(rec.count, 57, "record = 13-byte header + 44-byte fragment")
    R.assertEqual(UInt64(rec[rec.startIndex]), 23, "content type = application_data")
    R.assertEqual(rec.readBE(at: 1, width: 2) ?? 0, 0xFEFD, "version = DTLS 1.2")
    R.assertEqual(rec.readBE(at: 3, width: 2) ?? 99, 1, "epoch = 1")
    R.assertEqual(rec.readBE(at: 11, width: 2) ?? 0, 44, "length = fragment length")

    let ph = DTLSRecordLayer.plaintextRecord(type: DTLSWire.ctHandshake, seq: 7, payload: Data([1, 2, 3]))
    R.assertEqual(UInt64(ph[ph.startIndex]), 22, "content type = handshake")
    R.assertEqual(ph.readBE(at: 3, width: 2) ?? 99, 0, "plaintext record is epoch 0")
    R.assertEqual(ph.readBE(at: 5, width: 6) ?? 99, 7, "sequence number honored")
    R.assertEqual(ph.readBE(at: 11, width: 2) ?? 99, 3, "length = payload length")
    R.assertEqual(ph.count, 16, "13-byte header + 3-byte payload")
}

// MARK: – Handshake message framing

func testDTLSHandshakeFraming() {
    R.enter("DTLS: handshake message framing")
    let body = Data([0xAA, 0xBB, 0xCC])
    let msg = DTLSHandshake.encodeMessage(type: DTLSWire.hsClientHello, messageSeq: 5, body: body)
    R.assertEqual(msg.count, 15, "12-byte header + 3-byte body")
    R.assertEqual(UInt64(msg[msg.startIndex]), 1, "msg_type = client_hello")
    R.assertEqual(msg.readBE(at: 1, width: 3) ?? 99, 3, "length")
    R.assertEqual(msg.readBE(at: 4, width: 2) ?? 99, 5, "message_seq")
    R.assertEqual(msg.readBE(at: 6, width: 3) ?? 99, 0, "fragment_offset = 0")
    R.assertEqual(msg.readBE(at: 9, width: 3) ?? 99, 3, "fragment_length = length")

    guard let (parsed, consumed) = DTLSHandshake.parseMessage(msg) else {
        R.assertTrue(false, "parseMessage returns a message"); return
    }
    R.assertEqual(consumed, 15, "consumed whole message")
    R.assertEqual(parsed.type, DTLSWire.hsClientHello, "round-trip type")
    R.assertEqual(parsed.messageSeq, 5, "round-trip message_seq")
    R.assertEqual(parsed.body, body, "round-trip body")
    R.assertEqual(parsed.raw, msg, "raw == encoded bytes (for transcript hashing)")
}

// MARK: – ClientHello / ServerHello / HelloVerifyRequest

func testDTLSClientHelloBody() {
    R.enter("DTLS: ClientHello body layout")
    let cr = Data(repeating: 0x11, count: 32)
    let sid = Data([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04])
    let body = DTLSMessages.clientHelloBody(clientRandom: cr, sessionID: sid, cookie: Data(),
                                            cipherSuites: [.ecdheRsaAes256GcmSha384])
    R.assertEqual(body.readBE(at: 0, width: 2) ?? 0, 0xFEFD, "client_version = DTLS 1.2")
    R.assertEqual(body.slice(2, 32), cr, "client_random echoed")
    R.assertEqual(UInt64(body[body.startIndex + 34]), 8, "session_id length")
    R.assertEqual(body.slice(35, 8), sid, "session_id = X-DTLS-Session-ID")
    R.assertEqual(UInt64(body[body.startIndex + 43]), 0, "cookie length = 0")
    R.assertEqual(body.readBE(at: 44, width: 2) ?? 99, 2, "cipher_suites length = 2")
    R.assertEqual(body.readBE(at: 46, width: 2) ?? 0, 0xC030, "single offered suite")
    R.assertEqual(UInt64(body[body.startIndex + 48]), 1, "one compression method")
    R.assertEqual(UInt64(body[body.startIndex + 49]), 0, "compression = null")
}

func testDTLSServerHelloParse() {
    R.enter("DTLS: ServerHello parse")
    var body = Data()
    body.appendBE(0xFEFD, width: 2)                 // server_version
    let sr = Data(repeating: 0x55, count: 32)
    body += sr                                       // server_random
    body.append(4); body += Data([0xAA, 0xBB, 0xCC, 0xDD])   // session_id
    body.appendBE(0xC030, width: 2)                  // cipher_suite
    body.append(0)                                   // compression
    guard let sh = DTLSMessages.parseServerHello(body) else {
        R.assertTrue(false, "ServerHello parses"); return
    }
    R.assertEqual(sh.serverRandom, sr, "server_random extracted")
    R.assertEqual(sh.sessionID, Data([0xAA, 0xBB, 0xCC, 0xDD]), "session_id extracted")
    R.assertEqual(sh.cipherSuite, 0xC030, "selected cipher extracted")
}

func testDTLSHelloVerifyCookieParse() {
    R.enter("DTLS: HelloVerifyRequest cookie parse")
    var body = Data()
    body.appendBE(0xFEFD, width: 2)                  // server_version
    body.append(3); body += Data([0x0A, 0x0B, 0x0C]) // cookie
    R.assertEqual(DTLSMessages.parseHelloVerifyCookie(body), Data([0x0A, 0x0B, 0x0C]),
                  "cookie extracted for the second ClientHello")
}

// MARK: – Transcript + Finished wiring

func testDTLSTranscriptAndFinishedWiring() {
    R.enter("DTLS: transcript hash + Finished verify_data wiring")
    let cipher = DTLSCipherSuite.ecdheRsaAes256GcmSha384
    var t = DTLSTranscript()
    let m1 = DTLSHandshake.encodeMessage(type: DTLSWire.hsClientHello, messageSeq: 1, body: Data([1, 2]))
    let m2 = DTLSHandshake.encodeMessage(type: DTLSWire.hsServerHello, messageSeq: 1, body: Data([3]))
    t.append(m1); t.append(m2)
    R.assertEqual(t.hash(cipher: cipher), cipher.hash(m1 + m2),
                  "transcript hash = suite hash over concatenated raw messages")

    let ms = Data(repeating: 0x42, count: 48)
    let h = t.hash(cipher: cipher)
    let client = DTLSFinished.verifyData(masterSecret: ms, label: "client finished", transcriptHash: h, cipher: cipher)
    let server = DTLSFinished.verifyData(masterSecret: ms, label: "server finished", transcriptHash: h, cipher: cipher)
    R.assertEqual(client.count, 12, "verify_data is 12 bytes")
    R.assertEqual(client, DTLSPRF.prf(secret: ms, label: "client finished", seed: h, length: 12, cipher: cipher),
                  "verify_data = PRF(master_secret, label, transcript_hash)[0..12]")
    R.assertTrue(client != server, "client vs server Finished labels diverge")
}

// MARK: – Hex coding

func testDTLSHexCoding() {
    R.enter("DTLS: hex encode/decode")
    R.assertEqual(CSTPTunnel.hexDecode("00ff10a0"), Data([0x00, 0xFF, 0x10, 0xA0]), "lowercase decode")
    R.assertEqual(CSTPTunnel.hexDecode("DEADBEEF"), Data([0xDE, 0xAD, 0xBE, 0xEF]), "uppercase decode")
    R.assertTrue(CSTPTunnel.hexDecode("abc") == nil, "odd-length → nil")
    R.assertTrue(CSTPTunnel.hexDecode("zz") == nil, "non-hex → nil")
    let bytes = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
    R.assertEqual(CSTPTunnel.hexDecode(CSTPTunnel.hexEncode(bytes)), bytes, "encode→decode round-trip")
}
