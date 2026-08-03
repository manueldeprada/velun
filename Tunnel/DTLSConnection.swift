import Foundation
import Network
import os.log

private let dtlsLog = Logger(subsystem: "com.manueldeprada.velun.PacketTunnel", category: "DTLS")

struct DTLSParams {
    var host: String
    var port: Int                // X-DTLS-Port (usually 443)
    var sessionID: Data          // X-DTLS-Session-ID (hex-decoded, ~32 bytes)
    var masterSecret: Data       // 48 bytes; the same value sent in X-DTLS-Master-Secret
    var cipher: DTLSCipherSuite  // server's selection from X-DTLS12-CipherSuite
    var mtu: Int                 // X-DTLS-MTU — inner-packet MTU for the DTLS path
    var keepalive: TimeInterval  // X-DTLS-Keepalive
    var dpd: TimeInterval        // X-DTLS-DPD
}

final class DTLSConnection {
    private enum Pkt {
        static let data:       UInt8 = 0
        static let dpdOut:     UInt8 = 3
        static let dpdResp:    UInt8 = 4
        static let disconnect: UInt8 = 5
        static let keepalive:  UInt8 = 7
    }

    let mtu: Int                                   // inner-packet capacity (X-DTLS-MTU)
    private let params: DTLSParams
    private let queue = DispatchQueue(label: "com.manueldeprada.velun.dtls")

    private var conn: NWConnection?
    private var recordLayer: DTLSRecordLayer?
    private let recv = DatagramQueue()

    private var pumpTask: Task<Void, Never>?
    private var processTask: Task<Void, Never>?
    private var dpdTimer: DispatchSourceTimer?

    private let stateLock = NSLock()
    private var _alive = false
    private var _deadFired = false
    private var _lastInbound = Date()
    private var onDead: (() -> Void)?
    private var onData: ((Data) -> Void)?

    var isAlive: Bool { stateLock.lock(); defer { stateLock.unlock() }; return _alive }

    @inline(__always)
    private func withStateLock<T>(_ body: () -> T) -> T {
        stateLock.lock(); defer { stateLock.unlock() }; return body()
    }

    init(params: DTLSParams) {
        self.params = params
        self.mtu = params.mtu
    }

    // MARK: – Bring-up

    func connect(onData: @escaping (Data) -> Void, onDead: @escaping () -> Void) async throws {
        withStateLock { self.onData = onData; self.onDead = onDead }

        let c = try await openUDP()
        self.conn = c
        startReceivePump()

        try await runHandshake()

        withStateLock { _alive = true; _lastInbound = Date() }
        startProcessLoop()
        startDPDTimer()
        dtlsLog.notice("DTLS data channel up (cipher \(self.params.cipher.opensslName, privacy: .public), mtu \(self.mtu, privacy: .public))")
    }

    private func openUDP() async throws -> NWConnection {
        let p = NWParameters.udp
        p.prohibitedInterfaceTypes = [.other]
        p.preferNoProxies = true
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(params.host),
                                           port: NWEndpoint.Port(rawValue: UInt16(params.port))!)
        let c = NWConnection(to: endpoint, using: p)
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            let once = ResumeOnce(cont)
            c.stateUpdateHandler = { state in
                switch state {
                case .ready:            once.resume()
                case .failed(let e):    once.resume(throwing: e)
                case .cancelled:        once.resume(throwing: DTLSError.handshakeFailed("UDP cancelled"))
                case .waiting(let e):   once.resume(throwing: e)
                default: break
                }
            }
            c.start(queue: queue)
        }
        return c
    }

    // MARK: – Handshake

    private static let flightTimeout: TimeInterval = 2.0
    private static let maxFlights = 4   // retransmits of a ClientHello flight

    private func runHandshake() async throws {
        let cipher = params.cipher
        let clientRandom = Self.makeClientRandom()
        var epoch0Seq: UInt64 = 0

        // --- Flight 1: ClientHello (cookieless) -----------------------------
        func clientHelloRecord(cookie: Data, messageSeq: UInt16, seq: inout UInt64) -> (record: Data, raw: Data) {
            let body = DTLSMessages.clientHelloBody(clientRandom: clientRandom,
                                                    sessionID: params.sessionID, cookie: cookie,
                                                    cipherSuites: [cipher])
            let msg = DTLSHandshake.encodeMessage(type: DTLSWire.hsClientHello, messageSeq: messageSeq, body: body)
            let rec = DTLSRecordLayer.plaintextRecord(type: DTLSWire.ctHandshake, seq: seq, payload: msg)
            seq += 1
            return (rec, msg)
        }

        let ch1 = clientHelloRecord(cookie: Data(), messageSeq: 0, seq: &epoch0Seq)

        var transcriptClientHello = ch1.raw     // overwritten by CH2 if HVR happens
        var cookie = Data()
        var gotServerFlight: [DTLSRecord]? = nil

        cookieLoop: for _ in 0..<Self.maxFlights {
            sendDatagram(ch1.record)
            do {
                let records = try await readFlight(timeout: Self.flightTimeout)
                if let hvr = records.first(where: { $0.epoch == 0 && $0.type == DTLSWire.ctHandshake
                                                    && handshakeType($0) == DTLSWire.hsHelloVerifyRequest }),
                   let msg = DTLSHandshake.parseMessage(hvr.fragment)?.0,
                   let ck = DTLSMessages.parseHelloVerifyCookie(msg.body) {
                    cookie = ck
                    break cookieLoop
                }
                // No HVR — maybe the ServerHello flight came directly.
                if records.contains(where: { isServerHello($0) }) {
                    gotServerFlight = records      // CH1 is the transcript ClientHello
                    break cookieLoop
                }
            } catch DTLSError.timeout { continue }
        }

        // --- Flight 3: ClientHello with cookie (if we got an HVR) -----------
        if !cookie.isEmpty {
            let ch2 = clientHelloRecord(cookie: cookie, messageSeq: 1, seq: &epoch0Seq)
            transcriptClientHello = ch2.raw
            var flight: [DTLSRecord]? = nil
            for _ in 0..<Self.maxFlights {
                sendDatagram(ch2.record)
                do {
                    let acc = try await accumulateServerFlight(timeout: Self.flightTimeout)
                    if acc != nil { flight = acc; break }
                } catch DTLSError.timeout { continue }
            }
            guard let f = flight else { throw DTLSError.timeout }
            gotServerFlight = f
        } else if gotServerFlight == nil {
            throw DTLSError.timeout
        } else {
            gotServerFlight = try await topUpServerFlight(have: gotServerFlight!, timeout: Self.flightTimeout)
        }

        guard let serverFlight = gotServerFlight else { throw DTLSError.timeout }

        // --- Process the server flight: ServerHello + CCS + Finished --------
        guard let shRec = serverFlight.first(where: { isServerHello($0) }),
              let shMsg = DTLSHandshake.parseMessage(shRec.fragment)?.0,
              let sh = DTLSMessages.parseServerHello(shMsg.body) else {
            throw DTLSError.handshakeFailed("no ServerHello")
        }
        guard sh.cipherSuite == cipher.rawValue else {
            throw DTLSError.handshakeFailed("server selected 0x\(String(sh.cipherSuite, radix: 16)), expected \(cipher.opensslName)")
        }

        // Derive keys now that we have both randoms.
        let keys = DTLSKeys(masterSecret: params.masterSecret, clientRandom: clientRandom,
                            serverRandom: sh.serverRandom, cipher: cipher)
        let rl = DTLSRecordLayer(cipher: cipher, keys: keys)
        self.recordLayer = rl

        // Server Finished is the lone epoch-1 record in the flight.
        guard let finRec = serverFlight.first(where: { $0.epoch == 1 }) else {
            throw DTLSError.handshakeFailed("no encrypted Finished")
        }
        let finPlain = try rl.open(finRec)
        guard let finMsg = DTLSHandshake.parseMessage(finPlain)?.0,
              finMsg.type == DTLSWire.hsFinished else {
            throw DTLSError.handshakeFailed("epoch-1 record was not a Finished")
        }

        var transcript = DTLSTranscript()
        transcript.append(transcriptClientHello)
        transcript.append(shMsg.raw)
        let expectedServerVD = DTLSFinished.verifyData(masterSecret: params.masterSecret,
                                                       label: "server finished",
                                                       transcriptHash: transcript.hash(cipher: cipher),
                                                       cipher: cipher)
        guard finMsg.body == expectedServerVD else { throw DTLSError.finishedMismatch }

        transcript.append(finMsg.raw)
        let clientVD = DTLSFinished.verifyData(masterSecret: params.masterSecret,
                                               label: "client finished",
                                               transcriptHash: transcript.hash(cipher: cipher),
                                               cipher: cipher)

        // --- Our flight: ChangeCipherSpec + Finished ------------------------
        let ccs = DTLSRecordLayer.plaintextRecord(type: DTLSWire.ctChangeCipherSpec,
                                                  seq: epoch0Seq, payload: Data([0x01]))
        epoch0Seq += 1
        let finishedMsg = DTLSHandshake.encodeMessage(type: DTLSWire.hsFinished, messageSeq: 2, body: clientVD)
        let finishedRec = try rl.encryptedRecord(type: DTLSWire.ctHandshake, payload: finishedMsg)
        sendDatagram(ccs + finishedRec)
    }

    private func accumulateServerFlight(timeout: TimeInterval) async throws -> [DTLSRecord]? {
        var acc: [DTLSRecord] = []
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let remaining = deadline.timeIntervalSinceNow
            if remaining <= 0 { break }
            do {
                let datagram = try await recv.pop(timeout: remaining, on: queue)
                acc += DTLSRecord.parse(datagram: datagram)
                if acc.contains(where: { isServerHello($0) }) && acc.contains(where: { $0.epoch == 1 }) {
                    return acc
                }
            } catch DTLSError.timeout { break }
        }
        return nil   // incomplete flight → caller retransmits the ClientHello
    }

    private func topUpServerFlight(have: [DTLSRecord], timeout: TimeInterval) async throws -> [DTLSRecord] {
        var acc = have
        if acc.contains(where: { $0.epoch == 1 }) { return acc }
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let remaining = deadline.timeIntervalSinceNow
            if remaining <= 0 { break }
            do {
                let datagram = try await recv.pop(timeout: remaining, on: queue)
                acc += DTLSRecord.parse(datagram: datagram)
                if acc.contains(where: { $0.epoch == 1 }) { return acc }
            } catch DTLSError.timeout { break }
        }
        return acc
    }

    /// Read one datagram's worth of records with a timeout (handshake helper).
    private func readFlight(timeout: TimeInterval) async throws -> [DTLSRecord] {
        let datagram = try await recv.pop(timeout: timeout, on: queue)
        return DTLSRecord.parse(datagram: datagram)
    }

    private func handshakeType(_ r: DTLSRecord) -> UInt8? {
        guard r.type == DTLSWire.ctHandshake, let m = DTLSHandshake.parseMessage(r.fragment)?.0 else { return nil }
        return m.type
    }
    private func isServerHello(_ r: DTLSRecord) -> Bool {
        r.epoch == 0 && handshakeType(r) == DTLSWire.hsServerHello
    }

    // MARK: – Receive pump + data processing

    private func startReceivePump() {
        pumpTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, let c = self.conn else { return }
                do {
                    let d: Data = try await withCheckedThrowingContinuation { cont in
                        let once = ResumeOnce(cont)
                        c.receiveMessage { data, _, _, err in
                            if let err { once.resume(throwing: err) }
                            else { once.resume(returning: data ?? Data()) }
                        }
                    }
                    if !d.isEmpty { self.recv.push(d) }
                } catch {
                    self.recv.close(error: error)
                    return
                }
            }
        }
    }

    private func startProcessLoop() {
        processTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, self.isAlive else { return }
                do {
                    let datagram = try await self.recv.pop(timeout: 5, on: self.queue)
                    self.noteInbound()
                    for record in DTLSRecord.parse(datagram: datagram) {
                        self.handleRecord(record)
                    }
                } catch DTLSError.timeout {
                    continue   // idle; the DPD timer decides liveness
                } catch {
                    self.markDead("receive error: \(error.localizedDescription)")
                    return
                }
            }
        }
    }

    private func handleRecord(_ record: DTLSRecord) {
        guard record.epoch == 1, let rl = recordLayer else { return }   // ignore stray epoch-0
        guard let plain = try? rl.open(record), let first = plain.first else { return }
        let payload = plain.count > 1 ? plain.subdata(in: plain.startIndex + 1 ..< plain.endIndex) : Data()
        switch first {
        case Pkt.data:
            if !payload.isEmpty { stateLock.lock(); let cb = onData; stateLock.unlock(); cb?(payload) }
        case Pkt.dpdOut:
            sendControl(Pkt.dpdResp)
        case Pkt.dpdResp, Pkt.keepalive:
            break   // liveness already noted
        case Pkt.disconnect:
            markDead("server sent disconnect")
        default:
            break
        }
    }

    // MARK: – Send

    @discardableResult
    func send(_ ipPacket: Data) -> Bool {
        guard isAlive, let rl = recordLayer else { return false }
        guard let rec = try? rl.encryptedRecord(type: DTLSWire.ctApplicationData,
                                                 payload: Data([Pkt.data]) + ipPacket) else { return false }
        sendDatagram(rec)
        return true
    }

    private func sendControl(_ type: UInt8) {
        guard isAlive, let rl = recordLayer else { return }
        guard let rec = try? rl.encryptedRecord(type: DTLSWire.ctApplicationData, payload: Data([type])) else { return }
        sendDatagram(rec)
    }

    private func sendDatagram(_ d: Data) {
        conn?.send(content: d, completion: .contentProcessed { _ in })
    }

    // MARK: – DPD / liveness

    private func startDPDTimer() {
        let interval = max(5, params.keepalive)
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + interval, repeating: interval)
        timer.setEventHandler { [weak self] in
            guard let self, self.isAlive else { return }
            if self.secondsSinceLastInbound > max(self.params.dpd, interval) * 2 {
                self.markDead("DPD timeout (silent \(Int(self.secondsSinceLastInbound))s)")
                return
            }
            self.sendControl(Pkt.dpdOut)
        }
        timer.resume()
        dpdTimer = timer
    }

    private func noteInbound() { stateLock.lock(); _lastInbound = Date(); stateLock.unlock() }
    private var secondsSinceLastInbound: TimeInterval {
        stateLock.lock(); defer { stateLock.unlock() }; return Date().timeIntervalSince(_lastInbound)
    }

    private func markDead(_ reason: String) {
        stateLock.lock()
        if _deadFired { stateLock.unlock(); return }
        _deadFired = true; _alive = false
        let cb = onDead
        stateLock.unlock()
        dtlsLog.notice("DTLS data channel down: \(reason, privacy: .public) — falling back to TLS")
        teardown()
        cb?()
    }

    func close() {
        stateLock.lock(); _alive = false; _deadFired = true; stateLock.unlock()
        teardown()
    }

    private func teardown() {
        dpdTimer?.cancel(); dpdTimer = nil
        pumpTask?.cancel(); pumpTask = nil
        processTask?.cancel(); processTask = nil
        recv.close(error: DTLSError.handshakeFailed("closed"))
        conn?.cancel(); conn = nil
    }

    // MARK: – Helpers

    private static func makeClientRandom() -> Data {
        var r = Data(count: 32)
        let now = UInt32(truncatingIfNeeded: Int(Date().timeIntervalSince1970))
        r[0] = UInt8(now >> 24 & 0xff); r[1] = UInt8(now >> 16 & 0xff)
        r[2] = UInt8(now >> 8 & 0xff);  r[3] = UInt8(now & 0xff)
        r.withUnsafeMutableBytes { buf in
            _ = SecRandomCopyBytes(kSecRandomDefault, 28, buf.baseAddress!.advanced(by: 4))
        }
        return r
    }
}

// MARK: – DatagramQueue

private final class DatagramQueue {
    private let lock = NSLock()
    private var buffer: [Data] = []
    private var waiter: ResumeOnce<Data>?
    private var closedError: Error?

    func push(_ d: Data) {
        lock.lock()
        if let w = waiter { waiter = nil; lock.unlock(); w.resume(returning: d); return }
        buffer.append(d); lock.unlock()
    }

    func close(error: Error) {
        lock.lock()
        let w = waiter; waiter = nil
        if closedError == nil { closedError = error }
        lock.unlock()
        w?.resume(throwing: error)
    }

    func pop(timeout: TimeInterval, on queue: DispatchQueue) async throws -> Data {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            let once = ResumeOnce(cont)
            lock.lock()
            if !buffer.isEmpty { let d = buffer.removeFirst(); lock.unlock(); once.resume(returning: d); return }
            if let e = closedError { lock.unlock(); once.resume(throwing: e); return }
            waiter = once
            lock.unlock()
            queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
                guard let self else { return }
                self.lock.lock()
                if self.waiter === once { self.waiter = nil }
                self.lock.unlock()
                once.resume(throwing: DTLSError.timeout)
            }
        }
    }
}
