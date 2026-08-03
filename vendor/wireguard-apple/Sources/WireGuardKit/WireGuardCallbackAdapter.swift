// SPDX-License-Identifier: MIT
//
// velun extension: a WireGuard adapter that drives wireguard-go through a
// callback tun (no utun fd of its own). The velun unified system extension owns
// one shared utun and policy-routes every tunnel internally; this adapter lets
// WireGuard join that model:
//
//   host -> peer:  velun NATs a packet and calls `inject`; wireguard-go reads,
//                  encrypts, and sends it.
//   peer -> host:  wireguard-go decrypts and calls `onDeliver`; velun NATs it
//                  back and writes it to the shared utun.
//
// It mirrors the fd-based WireGuardAdapter's UAPI generation, endpoint DNS
// resolution, and IP_BOUND_IF bind pinning, but drops everything tied to
// NEPacketTunnelProvider (no tunnelFileDescriptor, no setTunnelNetworkSettings —
// the host applies network settings itself for the unified utun).

import Foundation
#if SWIFT_PACKAGE
import WireGuardKitGo
#endif

/// Process-global sink for wireguard-go log lines. The Go side keeps ONE
/// global (context, fn) logger pair; the old code stored an *unretained*
/// adapter pointer there, which dangled the moment the adapter deallocated —
/// and wireguard-go's device goroutines still log while winding down after
/// Close ("Routine: … stopped"), so tearing down a busy tunnel dereferenced
/// freed memory and killed the whole extension (heap-corruption SIGTRAP,
/// 2026-07-05). An immortal relay with no object context can't dangle; a
/// late line after teardown just goes to the last-registered handler.
private enum WGLogRelay {
    private static let lock = NSLock()
    private static var handler: ((WireGuardLogLevel, String) -> Void)?

    static func set(_ h: @escaping (WireGuardLogLevel, String) -> Void) {
        lock.lock(); handler = h; lock.unlock()
    }

    static func emit(_ level: Int32, _ message: UnsafePointer<CChar>) {
        lock.lock(); let h = handler; lock.unlock()
        guard let h else { return }
        h(WireGuardLogLevel(rawValue: level) ?? .verbose,
          String(cString: message).trimmingCharacters(in: .newlines))
    }
}

public final class WireGuardCallbackAdapter {
    public typealias DeliverHandler = (Data) -> Void

    private let logHandler: (WireGuardLogLevel, String) -> Void
    private let workQueue = DispatchQueue(label: "WireGuardCallbackAdapter.workQueue")
    private var handle: Int32 = -1
    private var deliver: DeliverHandler?
    /// Keeps the adapter alive for the wireguard-go device's lifetime: the C
    /// deliver callback resolves its context back to `self` without retaining,
    /// so we hold a +1 here from start() until stop() turns the device off.
    private var selfRetain: Unmanaged<WireGuardCallbackAdapter>?

    public init(logHandler: @escaping (WireGuardLogLevel, String) -> Void) {
        self.logHandler = logHandler
        setupLogHandler()
    }

    /// Bring up the WireGuard backend over a callback tun.
    /// - Parameters:
    ///   - tunnelConfiguration: the WG config; AllowedIPs should already be
    ///     widened (the host owns routing, the kernel/router enforces splits).
    ///   - mtu: tunnel MTU.
    ///   - ifindex: physical interface to pin the UDP bind to (0 = no pinning).
    ///   - onDeliver: called for each decrypted peer->host packet (copied).
    public func start(tunnelConfiguration: TunnelConfiguration,
                      mtu: Int,
                      ifindex: Int32,
                      onDeliver: @escaping DeliverHandler,
                      completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            guard self.handle < 0 else { completionHandler(.invalidState); return }
            self.deliver = onDeliver
            do {
                let resolved = try self.resolvePeers(for: tunnelConfiguration)
                let generator = PacketTunnelSettingsGenerator(
                    tunnelConfiguration: tunnelConfiguration, resolvedEndpoints: resolved)
                let (wgConfig, _) = generator.uapiConfiguration()

                let retained = Unmanaged.passRetained(self)
                let ctx = retained.toOpaque()
                let h = wgConfig.withCString { cfg in
                    wgTurnOnCallback(cfg, Int32(mtu), ifindex, { ctx, buf, len in
                        guard let ctx, let buf, len > 0 else { return }
                        let me = Unmanaged<WireGuardCallbackAdapter>.fromOpaque(ctx).takeUnretainedValue()
                        me.deliver?(Data(bytes: buf, count: Int(len)))
                    }, ctx)
                }
                if h < 0 {
                    retained.release()
                    completionHandler(.startWireGuardBackend(h))
                    return
                }
                self.selfRetain = retained
                self.handle = h
                completionHandler(nil)
            } catch let error as WireGuardAdapterError {
                completionHandler(error)
            } catch {
                completionHandler(.startWireGuardBackend(-1))
            }
        }
    }

    /// Queue a host->peer packet for encryption + send. Non-blocking, drops on a
    /// full queue (inner TCP/DNS retransmits cover the rare loss).
    public func inject(_ packet: Data) {
        let h = handle
        guard h >= 0, !packet.isEmpty else { return }
        packet.withUnsafeBytes { raw in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return }
            _ = wgInject(h, base, Int32(packet.count))
        }
    }

    /// Synchronous so the wireguard-go device (and its deliver callbacks) is
    /// fully stopped before the caller drops its reference to this adapter.
    public func stop() {
        workQueue.sync {
            if self.handle >= 0 {
                wgTurnOff(self.handle)
                self.handle = -1
            }
            self.deliver = nil
            self.selfRetain?.release()
            self.selfRetain = nil
        }
    }

    // MARK: - private (mirrors WireGuardAdapter)

    private func setupLogHandler() {
        WGLogRelay.set(logHandler)
        wgSetLogger(nil) { _, level, message in
            guard let message else { return }
            WGLogRelay.emit(level, message)
        }
    }

    private func resolvePeers(for tunnelConfiguration: TunnelConfiguration) throws -> [Endpoint?] {
        let endpoints = tunnelConfiguration.peers.map { $0.endpoint }
        let results = DNSResolver.resolveSync(endpoints: endpoints)
        let errors = results.compactMap { r -> DNSResolutionError? in
            if case .failure(let e) = r { return e } else { return nil }
        }
        guard errors.isEmpty else { throw WireGuardAdapterError.dnsResolution(errors) }
        return results.map { try! $0?.get() }
    }
}
