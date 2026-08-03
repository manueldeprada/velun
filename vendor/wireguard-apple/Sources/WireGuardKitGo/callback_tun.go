/* SPDX-License-Identifier: MIT
 *
 * velun extension: a tun.Device whose packet I/O crosses the cgo boundary
 * instead of a utun file descriptor.
 *
 * The velun unified system extension owns ONE utun and policy-routes every
 * active tunnel (OpenConnect-family + WireGuard) internally. wireguard-go
 * normally insists on owning its own utun fd; CallbackTun lets velun drive
 * it from the outside instead:
 *
 *   host → peer:  velun NATs a packet and calls wgInject; CallbackTun.Read
 *                 hands it to wireguard-go to encrypt and send.
 *   peer → host:  wireguard-go decrypts and calls CallbackTun.Write, which
 *                 invokes a C callback velun registered; velun NATs it back
 *                 and writes it to the shared utun.
 *
 * ifindex pins the UDP bind to a physical interface exactly as the fd path
 * does (NewPinnedBind), so casa's UDP can't be diverted onto a sibling utun.
 */

package main

// #include <stdint.h>
// static void wgCallDeliver(void *func, void *ctx, const uint8_t *buf, int len) {
//     ((void(*)(void *, const uint8_t *, int))func)(ctx, buf, len);
// }
import "C"

import (
	"os"
	"sync"
	"unsafe"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type CallbackTun struct {
	mtu       int
	events    chan tun.Event
	inbound   chan []byte
	closeOnce sync.Once
	closed    chan struct{}
	// deliverMu gates every use of the callback pointers. Close() severs them
	// under the write lock, so after Close returns no deliver is running or
	// can start — wireguard-go's device.Close() does NOT join
	// RoutineReadFromTUN, so without this a decrypted packet can still hit
	// the C callback a beat after wgTurnOff returned, when the Swift adapter
	// has already released the callback context (use-after-free).
	deliverMu  sync.RWMutex
	deliverFn  unsafe.Pointer
	deliverCtx unsafe.Pointer
}

func NewCallbackTun(mtu int, deliverFn, deliverCtx unsafe.Pointer) *CallbackTun {
	t := &CallbackTun{
		mtu:        mtu,
		events:     make(chan tun.Event, 1),
		inbound:    make(chan []byte, 1024),
		closed:     make(chan struct{}),
		deliverFn:  deliverFn,
		deliverCtx: deliverCtx,
	}
	// Tell wireguard-go the interface is up (mirrors the fd tun's behavior).
	t.events <- tun.EventUp
	return t
}

func (t *CallbackTun) File() *os.File { return nil }

// Read returns the next host→peer packet for wireguard-go to encrypt. Blocks
// until one is injected or the device is closed. The packet is placed at
// buf[offset:] (wireguard-go reserves `offset` bytes for its transport header).
func (t *CallbackTun) Read(buf []byte, offset int) (int, error) {
	select {
	case pkt := <-t.inbound:
		return copy(buf[offset:], pkt), nil
	case <-t.closed:
		return 0, os.ErrClosed
	}
}

// Write hands a decrypted peer→host packet (buf[offset:]) to velun via the
// registered C callback, which must copy it synchronously (the buffer is reused
// once Write returns).
func (t *CallbackTun) Write(buf []byte, offset int) (int, error) {
	if offset > len(buf) {
		return 0, nil
	}
	pkt := buf[offset:]
	if len(pkt) == 0 {
		return 0, nil
	}
	t.deliverMu.RLock()
	if t.deliverFn != nil {
		C.wgCallDeliver(t.deliverFn, t.deliverCtx,
			(*C.uint8_t)(unsafe.Pointer(&pkt[0])), C.int(len(pkt)))
	}
	t.deliverMu.RUnlock()
	return len(pkt), nil
}

func (t *CallbackTun) Flush() error             { return nil }
func (t *CallbackTun) MTU() (int, error)        { return t.mtu, nil }
func (t *CallbackTun) Name() (string, error)    { return "velun-wg", nil }
func (t *CallbackTun) Events() <-chan tun.Event { return t.events }

func (t *CallbackTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		close(t.events)
	})
	// Sever the callback under the write lock: a Write mid-deliver finishes
	// first (its RLock blocks us), and nothing can start one afterwards. This
	// is the guarantee that makes it safe for the Swift adapter to drop its
	// self-retain right after wgTurnOff returns.
	t.deliverMu.Lock()
	t.deliverFn = nil
	t.deliverCtx = nil
	t.deliverMu.Unlock()
	return nil
}

// inject queues a host→peer packet. Non-blocking: drops on a full queue (inner
// TCP / DNS retransmits cover the rare loss) or after close.
func (t *CallbackTun) inject(b []byte) bool {
	select {
	case <-t.closed:
		return false
	default:
	}
	select {
	case t.inbound <- b:
		return true
	default:
		return false
	}
}

// wgTurnOnCallback is the callback-tun analog of wgTurnOnPinned: it brings up a
// wireguard-go device backed by a CallbackTun instead of a utun fd. `deliverFn`
// is a C function pointer `void(*)(void *ctx, const uint8_t *buf, int len)`
// invoked for every decrypted peer→host packet; `deliverCtx` is passed back
// verbatim.
//
//export wgTurnOnCallback
func wgTurnOnCallback(settings *C.char, mtu int32, ifindex int32, deliverFn uintptr, deliverCtx uintptr) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	cbTun := NewCallbackTun(int(mtu), unsafe.Pointer(deliverFn), unsafe.Pointer(deliverCtx))
	bind := NewPinnedBind(ifindex)
	dev := device.NewDevice(cbTun, bind, logger)

	if err := dev.IpcSet(C.GoString(settings)); err != nil {
		logger.Errorf("Unable to set IPC settings: %v", err)
		dev.Close()
		return -1
	}
	dev.Up()
	logger.Verbosef("Callback device started (ifindex=%d mtu=%d)", ifindex, mtu)

	i := insertTunnelHandle(tunnelHandle{dev, logger, bind, cbTun})
	if i < 0 {
		dev.Close()
		return -1
	}
	return i
}

// wgInject queues a host→peer packet for the callback device identified by
// tunnelHandle. Returns 0 on success, -1 for an unknown/non-callback handle,
// -2 if the inject queue is full (dropped).
//
//export wgInject
func wgInject(tunnelHandle int32, packet unsafe.Pointer, length int32) int32 {
	// Per-packet path: must take the handle-table lock — an unguarded read
	// racing wgTurnOff's delete is a runtime-fatal map race (see api-apple.go).
	h, ok := lookupTunnelHandle(tunnelHandle)
	if !ok || h.cbTun == nil {
		return -1
	}
	b := C.GoBytes(packet, C.int(length))
	if h.cbTun.inject(b) {
		return 0
	}
	return -2
}
