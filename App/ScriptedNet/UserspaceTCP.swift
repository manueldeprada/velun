import Foundation

enum TCPState: String, Equatable {
    case closed
    case synSent
    case established
    case finWait1   // we sent FIN, awaiting ACK
    case finWait2   // we sent FIN, peer ACKed; awaiting peer FIN
    case closeWait  // peer sent FIN; our app may still write
    case lastAck    // we sent FIN after peer FIN; awaiting final ACK
    case timeWait
}

protocol UserspaceTCPDelegate: AnyObject {
    /// A fully-formed IP+TCP packet ready to send into the tunnel.
    func tcpDidEmitPacket(_ packet: Data, connection: UserspaceTCPConnection)

    func tcpDidReceiveData(_ data: Data, connection: UserspaceTCPConnection)

    func tcpDidEstablish(_ connection: UserspaceTCPConnection)

    func tcpDidClose(_ connection: UserspaceTCPConnection, error: Error?)
}

enum TCPError: LocalizedError {
    case rstReceived
    case connectionTimeout
    case retransmitsExhausted
    var errorDescription: String? {
        switch self {
        case .rstReceived:           return "Peer reset the connection"
        case .connectionTimeout:     return "Connection timed out"
        case .retransmitsExhausted:  return "Too many retransmits, giving up"
        }
    }
}

final class UserspaceTCPConnection {

    let localIP: UInt32
    let localPort: UInt16
    let remoteIP: UInt32
    let remotePort: UInt16

    weak var delegate: UserspaceTCPDelegate?

    private(set) var state: TCPState = .closed

    private var sndUna: UInt32 = 0   // oldest unacked sequence
    private var sndNxt: UInt32 = 0   // next sequence to send
    private var sndIss: UInt32 = 0   // initial send sequence
    private var sndWnd: UInt16 = 65535

    // Receive sequence space.
    private var rcvNxt: UInt32 = 0   // next byte we expect from peer
    private var rcvIrs: UInt32 = 0   // initial received sequence

    private var sendBuffer = Data()
    private var finQueued = false
    private var finSent = false

    private let mss: UInt16

    // Retransmit policy. Single-shot timer on the oldest unacked segment.
    private let rto: TimeInterval = 1.0
    private let maxRetransmits = 8
    private var retransmitCount = 0
    private var retransmitTask: Task<Void, Never>?

    init(localIP: UInt32, localPort: UInt16,
         remoteIP: UInt32, remotePort: UInt16,
         mss: UInt16 = 1380) {
        self.localIP = localIP
        self.localPort = localPort
        self.remoteIP = remoteIP
        self.remotePort = remotePort
        self.mss = mss
    }

    // MARK: – Public API

    /// Initiate the connection. Emits SYN.
    func open() {
        guard state == .closed else { return }
        sndIss = UInt32.random(in: 0...UInt32.max)
        sndUna = sndIss
        sndNxt = sndIss &+ 1                        // SYN consumes one seq number
        state = .synSent
        emit(flags: [.syn], payload: Data(), seqOverride: sndIss, mss: mss)
        scheduleRetransmit()
    }

    /// Bytes from the local app to send to the peer.
    func send(_ data: Data) {
        guard state == .established || state == .closeWait else { return }
        sendBuffer.append(data)
        flushSendBuffer()
    }

    func close() {
        guard !finQueued else { return }
        finQueued = true
        flushSendBuffer()
    }

    /// Hard reset.
    func abort() {
        emit(flags: [.rst], payload: Data())
        teardown(error: TCPError.rstReceived)
    }

    func handle(_ seg: TCPSegment) {
        if seg.flags.contains(.rst) {
            teardown(error: TCPError.rstReceived)
            return
        }

        switch state {

        case .synSent:
            // Expecting SYN-ACK.
            if seg.flags.contains(.syn), seg.flags.contains(.ack),
               seg.ackNumber == sndIss &+ 1 {
                rcvIrs = seg.sequenceNumber
                rcvNxt = seg.sequenceNumber &+ 1
                sndUna = seg.ackNumber
                sndWnd = seg.window
                state = .established
                cancelRetransmit()
                // Reply with ACK to complete the handshake.
                emit(flags: [.ack], payload: Data())
                delegate?.tcpDidEstablish(self)
                flushSendBuffer()
            } else {
                emit(flags: [.rst], payload: Data())
                teardown(error: TCPError.rstReceived)
            }

        case .established, .finWait1, .finWait2, .closeWait, .lastAck:
            // ACK processing (advance sndUna, drop acked bytes from buffer).
            if seg.flags.contains(.ack) {
                let acked = seqDiff(seg.ackNumber, minus: sndUna)
                if acked > 0, acked <= sendBufferOutstandingCount() {
                    let consumeFromBuffer = min(acked, sendBuffer.count)
                    if consumeFromBuffer > 0 {
                        sendBuffer.removeFirst(consumeFromBuffer)
                    }
                    sndUna = sndUna &+ UInt32(acked)
                    retransmitCount = 0
                    if hasOutstandingData() {
                        scheduleRetransmit()
                    } else {
                        cancelRetransmit()
                    }
                }
                sndWnd = seg.window

                // FIN-related transitions on receipt of an ACK.
                if state == .finWait1, finSent, sndUna == sndNxt {
                    state = .finWait2
                }
                if state == .lastAck, sndUna == sndNxt {
                    teardown(error: nil)
                    return
                }
            }

            // In-order data?
            if !seg.payload.isEmpty {
                if seg.sequenceNumber == rcvNxt {
                    rcvNxt = rcvNxt &+ UInt32(seg.payload.count)
                    delegate?.tcpDidReceiveData(seg.payload, connection: self)
                }
                emit(flags: [.ack], payload: Data())
            }

            // Peer FIN handling.
            if seg.flags.contains(.fin), seg.sequenceNumber == rcvNxt {
                rcvNxt = rcvNxt &+ 1
                emit(flags: [.ack], payload: Data())
                delegate?.tcpDidReceiveData(Data(), connection: self)
                if state == .established {
                    state = .closeWait
                } else if state == .finWait1 || state == .finWait2 {
                    teardown(error: nil)
                }
            }

            flushSendBuffer()

        case .timeWait, .closed:
            // Stale segments — ignore. (No 2*MSL hold; we tear down sooner.)
            break
        }
    }

    // MARK: – Private

    private func emit(flags: TCPFlags, payload: Data,
                      seqOverride: UInt32? = nil, mss: UInt16? = nil) {
        let seq = seqOverride ?? sndNxt
        let pkt = PacketBuilder.ipv4TCP(
            srcIP: localIP, dstIP: remoteIP,
            srcPort: localPort, dstPort: remotePort,
            seq: seq,
            ack: rcvNxt,
            flags: flags.contains(.syn) && !flags.contains(.ack) ? flags : flags.union(.ack),
            window: 65535,
            payload: payload,
            mss: mss
        )
        delegate?.tcpDidEmitPacket(pkt, connection: self)
    }

    private func flushSendBuffer() {
        guard state == .established || state == .closeWait else {
            return
        }

        let outstanding = sendBufferOutstandingCount()
        let unsent = sendBuffer.count - outstanding
        let usable = Int(sndWnd)
        var canSend = max(0, min(unsent, usable - outstanding))

        while canSend > 0 {
            let chunk = min(canSend, Int(mss))
            let start = sendBuffer.startIndex.advanced(by: outstanding + (sendBuffer.count - outstanding - canSend))
            let end = start.advanced(by: chunk)
            let payload = sendBuffer[start..<end]
            emit(flags: [.psh, .ack], payload: payload)
            sndNxt = sndNxt &+ UInt32(chunk)
            canSend -= chunk
            scheduleRetransmit()
        }

        // Send FIN once buffer is fully on the wire.
        if finQueued, !finSent, sendBufferOutstandingCount() == sendBuffer.count {
            emit(flags: [.fin, .ack], payload: Data())
            sndNxt = sndNxt &+ 1
            finSent = true
            if state == .established {
                state = .finWait1
            } else if state == .closeWait {
                state = .lastAck
            }
            scheduleRetransmit()
        }
    }

    private func sendBufferOutstandingCount() -> Int {
        Int(seqDiff(sndNxt, minus: sndUna))
            .clamped(to: 0...sendBuffer.count + (finSent ? 1 : 0))
    }
    private func hasOutstandingData() -> Bool {
        sndUna != sndNxt
    }

    private func seqDiff(_ a: UInt32, minus b: UInt32) -> Int {
        // Wrapping signed difference: positive if a is "after" b.
        Int(Int32(bitPattern: a &- b))
    }

    // MARK: – Retransmit timer

    private func scheduleRetransmit() {
        cancelRetransmit()
        retransmitTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(self?.rto ?? 1.0) * 1_000_000_000)
            guard let self else { return }
            if Task.isCancelled { return }
            self.handleRetransmit()
        }
    }

    private func cancelRetransmit() {
        retransmitTask?.cancel()
        retransmitTask = nil
    }

    private func handleRetransmit() {
        guard hasOutstandingData() || state == .synSent || state == .finWait1 || state == .lastAck else {
            return
        }
        retransmitCount += 1
        if retransmitCount > maxRetransmits {
            teardown(error: TCPError.retransmitsExhausted)
            return
        }

        if state == .synSent {
            emit(flags: [.syn], payload: Data(), seqOverride: sndIss, mss: mss)
        } else if !sendBuffer.isEmpty {
            let outstanding = sendBufferOutstandingCount()
            let head = sendBuffer.prefix(min(outstanding, Int(mss)))
            emit(flags: [.psh, .ack], payload: head, seqOverride: sndUna)
        } else if finSent {
            emit(flags: [.fin, .ack], payload: Data(), seqOverride: sndNxt &- 1)
        }
        scheduleRetransmit()
    }

    private func teardown(error: Error?) {
        guard state != .closed else { return }
        cancelRetransmit()
        state = .closed
        delegate?.tcpDidClose(self, error: error)
    }
}

private extension Comparable {
    func clamped(to range: ClosedRange<Self>) -> Self {
        min(max(self, range.lowerBound), range.upperBound)
    }
}
