/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

// #include <stdlib.h>
// #include <sys/types.h>
// static void callLogger(void *func, void *ctx, int level, const char *msg)
// {
// 	((void(*)(void *, int, const char *))func)(ctx, level, msg);
// }
import "C"

import (
	"fmt"
	"math"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

var loggerFunc unsafe.Pointer
var loggerCtx unsafe.Pointer

type CLogger int

func cstring(s string) *C.char {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		b := [1]C.char{}
		return &b[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func (l CLogger) Printf(format string, args ...interface{}) {
	if uintptr(loggerFunc) == 0 {
		return
	}
	C.callLogger(loggerFunc, loggerCtx, C.int(l), cstring(fmt.Sprintf(format, args...)))
}

type tunnelHandle struct {
	*device.Device
	*device.Logger
	bind  *PinnedBind
	cbTun *CallbackTun // non-nil only for callback-tun (velun unified) devices
}

// tunnelHandles is read on the per-packet hot path (wgInject, from velun's
// router queue) while wgTurnOn*/wgTurnOff mutate it from the control path.
// An unguarded map here is a Go runtime fatal ("concurrent map read and map
// write") that exits the whole extension process — and because c-archive
// fatals print only to stderr, it dies with no crash report. Every access
// goes through tunnelHandlesMu.
var tunnelHandles = make(map[int32]tunnelHandle)
var tunnelHandlesMu sync.RWMutex

func lookupTunnelHandle(i int32) (tunnelHandle, bool) {
	tunnelHandlesMu.RLock()
	defer tunnelHandlesMu.RUnlock()
	h, ok := tunnelHandles[i]
	return h, ok
}

// insertTunnelHandle stores h in the first free slot and returns it, or -1
// if the table is full.
func insertTunnelHandle(h tunnelHandle) int32 {
	tunnelHandlesMu.Lock()
	defer tunnelHandlesMu.Unlock()
	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		return -1
	}
	tunnelHandles[i] = h
	return i
}

func init() {
	// A Go runtime fatal normally prints to stderr and exits via libc
	// exit(2) — in a system extension that's an invisible death (no crash
	// report, stderr goes nowhere). "crash" makes fatals abort() instead,
	// so macOS writes a crash report with the Go stacks in it.
	debug.SetTraceback("crash")
	signals := make(chan os.Signal)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for {
			select {
			case <-signals:
				n := runtime.Stack(buf, true)
				buf[n] = 0
				if uintptr(loggerFunc) != 0 {
					C.callLogger(loggerFunc, loggerCtx, 0, (*C.char)(unsafe.Pointer(&buf[0])))
				}
			}
		}
	}()
}

//export wgSetLogger
func wgSetLogger(context, loggerFn uintptr) {
	loggerCtx = unsafe.Pointer(context)
	loggerFunc = unsafe.Pointer(loggerFn)
}

//export wgTurnOn
func wgTurnOn(settings *C.char, tunFd int32) int32 {
	return wgTurnOnPinned(settings, tunFd, 0)
}

// wgTurnOnPinned is the velun extension to wgTurnOn that takes an
// `ifindex` for binding the WireGuard UDP socket to a specific
// physical interface via setsockopt(IP_BOUND_IF / IPV6_BOUND_IF).
// ifindex == 0 preserves the legacy "no pinning" behavior.
//
//export wgTurnOnPinned
func wgTurnOnPinned(settings *C.char, tunFd int32, ifindex int32) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Errorf("Unable to dup tun fd: %v", err)
		return -1
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		logger.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	tun, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupTunFd), "/dev/tun"), 0)
	if err != nil {
		logger.Errorf("Unable to create new tun device from fd: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	logger.Verbosef("Attaching to interface")
	bind := NewPinnedBind(ifindex)
	dev := device.NewDevice(tun, bind, logger)

	err = dev.IpcSet(C.GoString(settings))
	if err != nil {
		logger.Errorf("Unable to set IPC settings: %v", err)
		unix.Close(dupTunFd)
		return -1
	}

	dev.Up()
	logger.Verbosef("Device started (ifindex=%d)", ifindex)

	i := insertTunnelHandle(tunnelHandle{dev, logger, bind, nil})
	if i < 0 {
		unix.Close(dupTunFd)
		return -1
	}
	return i
}

// wgSetBoundInterface re-pins the existing UDP bind sockets to the
// given physical interface ifindex without re-opening them. Call this
// from Swift when NWPathMonitor sees the primary physical interface
// change (e.g. Wi-Fi → Ethernet handover, sleep/wake). Returns 0 on
// success, -1 if the handle is unknown, or the errno-encoded value
// from setsockopt on failure.
//
//export wgSetBoundInterface
func wgSetBoundInterface(tunnelHandle int32, ifindex int32) int32 {
	h, ok := lookupTunnelHandle(tunnelHandle)
	if !ok {
		return -1
	}
	if h.bind == nil {
		return -1
	}
	if err := h.bind.SetBoundInterface(ifindex); err != nil {
		h.Errorf("wgSetBoundInterface(ifindex=%d) failed: %v", ifindex, err)
		return -2
	}
	h.Verbosef("Rebound UDP sockets to ifindex=%d", ifindex)
	return 0
}

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	tunnelHandlesMu.Lock()
	dev, ok := tunnelHandles[tunnelHandle]
	if ok {
		delete(tunnelHandles, tunnelHandle)
	}
	tunnelHandlesMu.Unlock()
	if !ok {
		return
	}
	// Close outside the lock: it waits for the device's goroutines, and an
	// in-flight wgInject that already fetched the handle just drops its
	// packet into the closing device's queue harmlessly.
	dev.Close()
}

//export wgSetConfig
func wgSetConfig(tunnelHandle int32, settings *C.char) int64 {
	dev, ok := lookupTunnelHandle(tunnelHandle)
	if !ok {
		return 0
	}
	err := dev.IpcSet(C.GoString(settings))
	if err != nil {
		dev.Errorf("Unable to set IPC settings: %v", err)
		if ipcErr, ok := err.(*device.IPCError); ok {
			return ipcErr.ErrorCode()
		}
		return -1
	}
	return 0
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	device, ok := lookupTunnelHandle(tunnelHandle)
	if !ok {
		return nil
	}
	settings, err := device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export wgBumpSockets
func wgBumpSockets(tunnelHandle int32) {
	dev, ok := lookupTunnelHandle(tunnelHandle)
	if !ok {
		return
	}
	go func() {
		for i := 0; i < 10; i++ {
			err := dev.BindUpdate()
			if err == nil {
				dev.SendKeepalivesToPeersWithCurrentKeypair()
				return
			}
			dev.Errorf("Unable to update bind, try %d: %v", i+1, err)
			time.Sleep(time.Second / 2)
		}
		dev.Errorf("Gave up trying to update bind; tunnel is likely dysfunctional")
	}()
}

//export wgDisableSomeRoamingForBrokenMobileSemantics
func wgDisableSomeRoamingForBrokenMobileSemantics(tunnelHandle int32) {
	dev, ok := lookupTunnelHandle(tunnelHandle)
	if !ok {
		return
	}
	dev.DisableSomeRoamingForBrokenMobileSemantics()
}

//export wgVersion
func wgVersion() *C.char {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return C.CString("unknown")
	}
	for _, dep := range info.Deps {
		if dep.Path == "golang.zx2c4.com/wireguard" {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return C.CString(parts[2][:7])
			}
			return C.CString(dep.Version)
		}
	}
	return C.CString("unknown")
}

func main() {}
