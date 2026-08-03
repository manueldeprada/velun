/* SPDX-License-Identifier: MIT
 *
 * Apple physical-interface-pinned Bind for wireguard-go.
 *
 * Mirrors NWConnection's `prohibitedInterfaceTypes = [.other]` behavior
 * by calling setsockopt(IP_BOUND_IF / IPV6_BOUND_IF) on the bind sockets
 * with a caller-supplied ifindex (typically the primary physical
 * interface — en0 / en1). This keeps WireGuard UDP traffic on
 * Wi-Fi / Ethernet / cellular regardless of what utun interfaces a
 * sibling VPN (another velun profile, Tailscale, …) brings up later.
 *
 * Without pinning, when a sibling VPN comes up and changes the kernel's
 * default route, NWPath inside wireguard-go's `wgBumpSockets` rebinds
 * the UDP socket onto whichever path the kernel now thinks is best —
 * which can be another utun. The result observed in production was
 * "casa (full WG) stops routing public traffic when MPI (partial OC)
 * is also active": packets ingress utun_casa, never egress en0.
 *
 * ifindex == 0 means "no pinning" — behaves identically to StdNetBind.
 */

package main

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

type PinnedBind struct {
	mu         sync.Mutex
	ipv4       *net.UDPConn
	ipv6       *net.UDPConn
	blackhole4 bool
	blackhole6 bool
	ifindex    atomic.Int32
}

func NewPinnedBind(ifindex int32) *PinnedBind {
	b := &PinnedBind{}
	b.ifindex.Store(ifindex)
	return b
}

type pinnedEndpoint netip.AddrPort

var (
	_ conn.Bind     = (*PinnedBind)(nil)
	_ conn.Endpoint = pinnedEndpoint{}
)

func (*PinnedBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	return pinnedEndpoint(e), err
}

func (pinnedEndpoint) ClearSrc()             {}
func (e pinnedEndpoint) DstIP() netip.Addr   { return netip.AddrPort(e).Addr() }
func (e pinnedEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e pinnedEndpoint) DstToBytes() []byte  { b, _ := netip.AddrPort(e).MarshalBinary(); return b }
func (e pinnedEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e pinnedEndpoint) SrcToString() string { return "" }

func (bind *PinnedBind) pinSocket(c *net.UDPConn, v6 bool) error {
	if c == nil {
		return nil
	}
	idx := int(bind.ifindex.Load())
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	err = raw.Control(func(fd uintptr) {
		if v6 {
			setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, idx)
		} else {
			setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, idx)
		}
	})
	if err != nil {
		return err
	}
	return setErr
}

// SetBoundInterface updates the target ifindex and re-applies the
// setsockopt to existing sockets without closing them. Safe to call
// from any goroutine.
func (bind *PinnedBind) SetBoundInterface(ifindex int32) error {
	bind.ifindex.Store(ifindex)
	bind.mu.Lock()
	defer bind.mu.Unlock()
	if err := bind.pinSocket(bind.ipv4, false); err != nil {
		return err
	}
	return bind.pinSocket(bind.ipv6, true)
}

func listenPinnedNet(network string, port int) (*net.UDPConn, int, error) {
	c, err := net.ListenUDP(network, &net.UDPAddr{Port: port})
	if err != nil {
		return nil, 0, err
	}
	laddr := c.LocalAddr()
	uaddr, err := net.ResolveUDPAddr(laddr.Network(), laddr.String())
	if err != nil {
		c.Close()
		return nil, 0, err
	}
	return c, uaddr.Port, nil
}

func (bind *PinnedBind) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	if bind.ipv4 != nil || bind.ipv6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	var (
		ipv4, ipv6 *net.UDPConn
		err        error
		tries      int
		port       int
	)
again:
	port = int(uport)
	ipv4, port, err = listenPinnedNet("udp4", port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, err
	}
	ipv6, port, err = listenPinnedNet("udp6", port)
	if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
		if ipv4 != nil {
			ipv4.Close()
			ipv4 = nil
		}
		tries++
		goto again
	}
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		if ipv4 != nil {
			ipv4.Close()
		}
		return nil, 0, err
	}

	if err := bind.pinSocket(ipv4, false); err != nil {
		if ipv4 != nil {
			ipv4.Close()
		}
		if ipv6 != nil {
			ipv6.Close()
		}
		return nil, 0, err
	}
	if err := bind.pinSocket(ipv6, true); err != nil {
		if ipv4 != nil {
			ipv4.Close()
		}
		if ipv6 != nil {
			ipv6.Close()
		}
		return nil, 0, err
	}

	var fns []conn.ReceiveFunc
	if ipv4 != nil {
		fns = append(fns, bind.makeReceive(ipv4))
		bind.ipv4 = ipv4
	}
	if ipv6 != nil {
		fns = append(fns, bind.makeReceive(ipv6))
		bind.ipv6 = ipv6
	}
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}
	return fns, uint16(port), nil
}

func (bind *PinnedBind) Close() error {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	var err1, err2 error
	if bind.ipv4 != nil {
		err1 = bind.ipv4.Close()
		bind.ipv4 = nil
	}
	if bind.ipv6 != nil {
		err2 = bind.ipv6.Close()
		bind.ipv6 = nil
	}
	bind.blackhole4 = false
	bind.blackhole6 = false
	if err1 != nil {
		return err1
	}
	return err2
}

func (*PinnedBind) makeReceive(c *net.UDPConn) conn.ReceiveFunc {
	return func(buff []byte) (int, conn.Endpoint, error) {
		n, ap, err := c.ReadFromUDPAddrPort(buff)
		return n, pinnedEndpoint(ap), err
	}
}

func (bind *PinnedBind) SetMark(uint32) error { return nil }

func (bind *PinnedBind) Send(buff []byte, endpoint conn.Endpoint) error {
	nend, ok := endpoint.(pinnedEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	ap := netip.AddrPort(nend)

	bind.mu.Lock()
	blackhole := bind.blackhole4
	c := bind.ipv4
	if ap.Addr().Is6() {
		blackhole = bind.blackhole6
		c = bind.ipv6
	}
	bind.mu.Unlock()

	if blackhole {
		return nil
	}
	if c == nil {
		return syscall.EAFNOSUPPORT
	}
	_, err := c.WriteToUDPAddrPort(buff, ap)
	return err
}
