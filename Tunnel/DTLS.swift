import Foundation
import CryptoKit

// MARK: – Wire constants

enum DTLSWire {
    static let version12: UInt16 = 0xFEFD

    // Record content types (the record header `type` field).
    static let ctChangeCipherSpec: UInt8 = 20
    static let ctAlert:            UInt8 = 21
    static let ctHandshake:        UInt8 = 22
    static let ctApplicationData:  UInt8 = 23

    // Handshake message types (the `msg_type` inside a handshake record).
    static let hsClientHello:        UInt8 = 1
    static let hsServerHello:        UInt8 = 2
    static let hsHelloVerifyRequest: UInt8 = 3
    static let hsFinished:           UInt8 = 20

    static let recordHeaderLen = 13   // type(1)+version(2)+epoch(2)+seq(6)+length(2)
    static let hsHeaderLen     = 12   // type(1)+length(3)+msg_seq(2)+frag_off(3)+frag_len(3)
    static let verifyDataLen   = 12   // RFC 5246 default for the negotiated PRF
    static let gcmTagLen       = 16
    static let gcmExplicitNonceLen = 8
}

// MARK: – Cipher suites

enum DTLSCipherSuite: UInt16, CaseIterable {
    case ecdheRsaAes256GcmSha384 = 0xC030
    case ecdheRsaAes128GcmSha256 = 0xC02F
    case rsaAes256GcmSha384       = 0x009D
    case rsaAes128GcmSha256       = 0x009C

    enum HashKind { case sha256, sha384 }

    var hashKind: HashKind {
        switch self {
        case .ecdheRsaAes256GcmSha384, .rsaAes256GcmSha384: return .sha384
        case .ecdheRsaAes128GcmSha256, .rsaAes128GcmSha256: return .sha256
        }
    }

    /// AEAD key length in bytes.
    var keyLen: Int {
        switch self {
        case .ecdheRsaAes256GcmSha384, .rsaAes256GcmSha384: return 32
        case .ecdheRsaAes128GcmSha256, .rsaAes128GcmSha256: return 16
        }
    }

    /// Fixed (implicit) GCM IV / salt length. 4 for all TLS 1.2 GCM suites.
    var fixedIVLen: Int { 4 }

    /// Output length of the suite's hash, used by the PRF and transcript.
    var hashLen: Int { hashKind == .sha384 ? 48 : 32 }

    func hash(_ data: Data) -> Data {
        switch hashKind {
        case .sha256: return Data(SHA256.hash(data: data))
        case .sha384: return Data(SHA384.hash(data: data))
        }
    }

    func hmac(key: Data, _ message: Data) -> Data {
        let k = SymmetricKey(data: key)
        switch hashKind {
        case .sha256: return Data(HMAC<SHA256>.authenticationCode(for: message, using: k))
        case .sha384: return Data(HMAC<SHA384>.authenticationCode(for: message, using: k))
        }
    }

    /// Map an `X-DTLS12-CipherSuite` token (OpenSSL spelling) to a suite.
    static func fromOpenSSLName(_ name: String) -> DTLSCipherSuite? {
        switch name.trimmingCharacters(in: .whitespaces).uppercased() {
        case "ECDHE-RSA-AES256-GCM-SHA384": return .ecdheRsaAes256GcmSha384
        case "ECDHE-RSA-AES128-GCM-SHA256": return .ecdheRsaAes128GcmSha256
        case "AES256-GCM-SHA384":           return .rsaAes256GcmSha384
        case "AES128-GCM-SHA256":           return .rsaAes128GcmSha256
        default:                            return nil
        }
    }

    var opensslName: String {
        switch self {
        case .ecdheRsaAes256GcmSha384: return "ECDHE-RSA-AES256-GCM-SHA384"
        case .ecdheRsaAes128GcmSha256: return "ECDHE-RSA-AES128-GCM-SHA256"
        case .rsaAes256GcmSha384:       return "AES256-GCM-SHA384"
        case .rsaAes128GcmSha256:       return "AES128-GCM-SHA256"
        }
    }

    static let proposalList: [DTLSCipherSuite] =
        [.ecdheRsaAes256GcmSha384, .ecdheRsaAes128GcmSha256, .rsaAes256GcmSha384, .rsaAes128GcmSha256]
}

// MARK: – TLS 1.2 PRF (RFC 5246 §5)

enum DTLSPRF {
    static func prf(secret: Data, label: String, seed: Data, length: Int,
                    cipher: DTLSCipherSuite) -> Data {
        let labelSeed = Data(label.utf8) + seed
        return pHash(secret: secret, seed: labelSeed, length: length, cipher: cipher)
    }

    private static func pHash(secret: Data, seed: Data, length: Int,
                              cipher: DTLSCipherSuite) -> Data {
        var out = Data()
        var a = cipher.hmac(key: secret, seed)               // A(1)
        while out.count < length {
            out += cipher.hmac(key: secret, a + seed)
            a = cipher.hmac(key: secret, a)                  // A(i+1)
        }
        return out.prefix(length)
    }
}

// MARK: – Key schedule

struct DTLSKeys {
    let clientWriteKey: SymmetricKey
    let serverWriteKey: SymmetricKey
    let clientWriteIV:  Data            // fixed GCM salt (4 bytes)
    let serverWriteIV:  Data

    /// Direct construction — used to model the peer (swapped roles) in tests.
    init(clientWriteKey: SymmetricKey, serverWriteKey: SymmetricKey,
         clientWriteIV: Data, serverWriteIV: Data) {
        self.clientWriteKey = clientWriteKey
        self.serverWriteKey = serverWriteKey
        self.clientWriteIV  = clientWriteIV
        self.serverWriteIV  = serverWriteIV
    }

    init(masterSecret: Data, clientRandom: Data, serverRandom: Data, cipher: DTLSCipherSuite) {
        let need = 2 * cipher.keyLen + 2 * cipher.fixedIVLen
        let block = DTLSPRF.prf(secret: masterSecret, label: "key expansion",
                                seed: serverRandom + clientRandom, length: need, cipher: cipher)
        var off = 0
        func take(_ n: Int) -> Data { defer { off += n }; return block.subdata(in: block.startIndex+off ..< block.startIndex+off+n) }
        let cwk = take(cipher.keyLen)
        let swk = take(cipher.keyLen)
        let civ = take(cipher.fixedIVLen)
        let siv = take(cipher.fixedIVLen)
        clientWriteKey = SymmetricKey(data: cwk)
        serverWriteKey = SymmetricKey(data: swk)
        clientWriteIV  = civ
        serverWriteIV  = siv
    }
}

// MARK: – Finished verify_data

enum DTLSFinished {
    static func verifyData(masterSecret: Data, label: String, transcriptHash: Data,
                           cipher: DTLSCipherSuite) -> Data {
        DTLSPRF.prf(secret: masterSecret, label: label, seed: transcriptHash,
                    length: DTLSWire.verifyDataLen, cipher: cipher)
    }
}

// MARK: – Big-endian byte helpers

extension Data {
    /// Append `value` as `width` big-endian bytes (width ≤ 8).
    mutating func appendBE(_ value: UInt64, width: Int) {
        for i in stride(from: width - 1, through: 0, by: -1) {
            append(UInt8((value >> (UInt64(i) * 8)) & 0xff))
        }
    }

    func readBE(at offset: Int, width: Int) -> UInt64? {
        guard offset >= 0, offset + width <= count else { return nil }
        var v: UInt64 = 0
        for i in 0..<width { v = (v << 8) | UInt64(self[startIndex + offset + i]) }
        return v
    }

    /// Subdata by logical (0-based) range, nil if out of bounds.
    func slice(_ offset: Int, _ length: Int) -> Data? {
        guard offset >= 0, length >= 0, offset + length <= count else { return nil }
        return subdata(in: startIndex + offset ..< startIndex + offset + length)
    }
}

// MARK: – Handshake message framing

enum DTLSHandshake {
    static func encodeMessage(type: UInt8, messageSeq: UInt16, body: Data) -> Data {
        var m = Data()
        m.append(type)
        m.appendBE(UInt64(body.count), width: 3)   // length
        m.appendBE(UInt64(messageSeq), width: 2)    // message_seq
        m.appendBE(0, width: 3)                      // fragment_offset
        m.appendBE(UInt64(body.count), width: 3)     // fragment_length
        m += body
        return m
    }

    struct Message {
        let type: UInt8
        let length: Int
        let messageSeq: UInt16
        let fragmentOffset: Int
        let fragmentLength: Int
        let body: Data          // the fragment payload (== full body when unfragmented)
        let raw: Data           // full 12-byte header + body, for transcript inclusion
    }

    static func parseMessage(_ data: Data) -> (Message, consumed: Int)? {
        guard data.count >= DTLSWire.hsHeaderLen,
              let length    = data.readBE(at: 1, width: 3),
              let msgSeq    = data.readBE(at: 4, width: 2),
              let fragOff   = data.readBE(at: 6, width: 3),
              let fragLen   = data.readBE(at: 9, width: 3),
              let body      = data.slice(DTLSWire.hsHeaderLen, Int(fragLen)),
              let raw       = data.slice(0, DTLSWire.hsHeaderLen + Int(fragLen))
        else { return nil }
        let msg = Message(type: data[data.startIndex], length: Int(length),
                          messageSeq: UInt16(msgSeq), fragmentOffset: Int(fragOff),
                          fragmentLength: Int(fragLen), body: body, raw: raw)
        return (msg, DTLSWire.hsHeaderLen + Int(fragLen))
    }
}

// MARK: – ClientHello / ServerHello / HelloVerifyRequest bodies

enum DTLSMessages {
    static func clientHelloBody(clientRandom: Data, sessionID: Data, cookie: Data,
                                cipherSuites: [DTLSCipherSuite]) -> Data {
        var b = Data()
        b.appendBE(UInt64(DTLSWire.version12), width: 2)   // client_version
        b += clientRandom                                   // random[32]
        b.append(UInt8(sessionID.count)); b += sessionID    // session_id
        b.append(UInt8(cookie.count));    b += cookie        // cookie
        b.appendBE(UInt64(cipherSuites.count * 2), width: 2)
        for cs in cipherSuites { b.appendBE(UInt64(cs.rawValue), width: 2) }
        b.append(1); b.append(0)                             // compression: null only
        return b
    }

    struct ServerHello {
        let serverVersion: UInt16
        let serverRandom: Data       // [32]
        let sessionID: Data
        let cipherSuite: UInt16
    }

    static func parseServerHello(_ body: Data) -> ServerHello? {
        guard let ver = body.readBE(at: 0, width: 2),
              let rnd = body.slice(2, 32),
              let sidLen = body.readBE(at: 34, width: 1) else { return nil }
        let sidStart = 35
        guard let sid = body.slice(sidStart, Int(sidLen)),
              let cs = body.readBE(at: sidStart + Int(sidLen), width: 2) else { return nil }
        return ServerHello(serverVersion: UInt16(ver), serverRandom: rnd,
                           sessionID: sid, cipherSuite: UInt16(cs))
    }

    /// HelloVerifyRequest body → the cookie to echo in the second ClientHello.
    static func parseHelloVerifyCookie(_ body: Data) -> Data? {
        guard let cookieLen = body.readBE(at: 2, width: 1),   // skip server_version(2)
              let cookie = body.slice(3, Int(cookieLen)) else { return nil }
        return cookie
    }
}

// MARK: – Transcript accumulator

struct DTLSTranscript {
    private(set) var bytes = Data()
    mutating func append(_ handshakeMessageRaw: Data) { bytes += handshakeMessageRaw }
    func hash(cipher: DTLSCipherSuite) -> Data { cipher.hash(bytes) }
}

// MARK: – Record layer

enum DTLSError: Error, LocalizedError {
    case decryptFailed
    case malformedRecord
    case handshakeFailed(String)
    case unsupportedCipher(UInt16)
    case finishedMismatch
    case timeout

    var errorDescription: String? {
        switch self {
        case .decryptFailed:           return "DTLS record decrypt failed"
        case .malformedRecord:         return "Malformed DTLS record"
        case .handshakeFailed(let m):  return "DTLS handshake failed: \(m)"
        case .unsupportedCipher(let c): return "Unsupported DTLS cipher 0x\(String(c, radix: 16))"
        case .finishedMismatch:        return "DTLS Finished verify_data mismatch"
        case .timeout:                 return "DTLS handshake timed out"
        }
    }
}

struct DTLSRecord {
    let type: UInt8
    let version: UInt16
    let epoch: UInt16
    let seq: UInt64            // 48-bit sequence number
    let seqNum8: Data          // the 8 header bytes epoch(2)‖seq(6) — used as GCM AAD seq_num
    let fragment: Data
}

extension DTLSRecord {
    static func parse(datagram: Data) -> [DTLSRecord] {
        var out: [DTLSRecord] = []
        var rest = datagram
        while rest.count >= DTLSWire.recordHeaderLen {
            guard let ver = rest.readBE(at: 1, width: 2),
                  let epoch = rest.readBE(at: 3, width: 2),
                  let seq = rest.readBE(at: 5, width: 6),
                  let len = rest.readBE(at: 11, width: 2),
                  let seqNum8 = rest.slice(3, 8),
                  let frag = rest.slice(DTLSWire.recordHeaderLen, Int(len)) else { break }
            out.append(DTLSRecord(type: rest[rest.startIndex], version: UInt16(ver),
                                  epoch: UInt16(epoch), seq: seq, seqNum8: seqNum8, fragment: frag))
            let consumed = DTLSWire.recordHeaderLen + Int(len)
            rest = rest.subdata(in: rest.startIndex + consumed ..< rest.endIndex)
        }
        return out
    }
}

final class DTLSRecordLayer {
    let cipher: DTLSCipherSuite
    private let keys: DTLSKeys
    private var sendSeqEpoch1: UInt64 = 0

    init(cipher: DTLSCipherSuite, keys: DTLSKeys) {
        self.cipher = cipher
        self.keys = keys
    }

    static func plaintextRecord(type: UInt8, seq: UInt64, payload: Data) -> Data {
        var r = Data()
        r.append(type)
        r.appendBE(UInt64(DTLSWire.version12), width: 2)
        r.appendBE(0, width: 2)               // epoch 0
        r.appendBE(seq, width: 6)
        r.appendBE(UInt64(payload.count), width: 2)
        r += payload
        return r
    }

    func encryptedRecord(type: UInt8, payload: Data) throws -> Data {
        let seq = sendSeqEpoch1; sendSeqEpoch1 += 1
        var seqNum8 = Data()
        seqNum8.appendBE(1, width: 2)         // epoch 1
        seqNum8.appendBE(seq, width: 6)
        let nonce = keys.clientWriteIV + seqNum8

        var aad = Data()
        aad += seqNum8
        aad.append(type)
        aad.appendBE(UInt64(DTLSWire.version12), width: 2)
        aad.appendBE(UInt64(payload.count), width: 2)   // plaintext length

        let sealed = try AES.GCM.seal(payload, using: keys.clientWriteKey,
                                      nonce: try AES.GCM.Nonce(data: nonce),
                                      authenticating: aad)
        let fragment = seqNum8 + sealed.ciphertext + sealed.tag
        var r = Data()
        r.append(type)
        r.appendBE(UInt64(DTLSWire.version12), width: 2)
        r += seqNum8                          // epoch(2)+seq(6) on the wire
        r.appendBE(UInt64(fragment.count), width: 2)
        r += fragment
        return r
    }

    func open(_ record: DTLSRecord) throws -> Data {
        guard record.epoch == 1 else { return record.fragment }   // epoch 0 = already plaintext
        let frag = record.fragment
        guard frag.count >= DTLSWire.gcmExplicitNonceLen + DTLSWire.gcmTagLen else {
            throw DTLSError.malformedRecord
        }
        let explicit = frag.subdata(in: frag.startIndex ..< frag.startIndex + DTLSWire.gcmExplicitNonceLen)
        let ctStart = frag.startIndex + DTLSWire.gcmExplicitNonceLen
        let tagStart = frag.endIndex - DTLSWire.gcmTagLen
        let ciphertext = frag.subdata(in: ctStart ..< tagStart)
        let tag = frag.subdata(in: tagStart ..< frag.endIndex)
        let nonce = keys.serverWriteIV + explicit

        var aad = Data()
        aad += record.seqNum8
        aad.append(record.type)
        aad.appendBE(UInt64(record.version), width: 2)
        aad.appendBE(UInt64(ciphertext.count), width: 2)

        do {
            let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: nonce),
                                            ciphertext: ciphertext, tag: tag)
            return try AES.GCM.open(box, using: keys.serverWriteKey, authenticating: aad)
        } catch {
            throw DTLSError.decryptFailed
        }
    }
}
