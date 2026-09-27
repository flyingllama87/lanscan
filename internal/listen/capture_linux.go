//go:build linux

package listen

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Linux packet types (linux/if_packet.h).
const (
	packetBroadcast = 1
	packetMulticast = 2
	packetOutgoing  = 4
)

// filter admits received broadcast and multicast frames and ARP addressed to
// this host; it drops everything this host sends and all other unicast.
var filter = []bpf.Instruction{
	bpf.LoadExtension{Num: bpf.ExtType},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: packetOutgoing, SkipTrue: 4},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: packetBroadcast, SkipTrue: 4},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: packetMulticast, SkipTrue: 3},
	bpf.LoadExtension{Num: bpf.ExtProto},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: ProtoARP, SkipTrue: 1},
	bpf.RetConstant{Val: 0},
	bpf.RetConstant{Val: 1 << 16},
}

// Capture is a receive-only AF_PACKET socket.
type Capture struct {
	fd int
	// AllMulti lists interfaces set to receive all multicast groups for the
	// socket's lifetime; this changes the NIC filter and sends nothing.
	AllMulti []string
	names    map[int]string
	loopback map[int]bool
}

// Frame is one received network-layer payload.
type Frame struct {
	Proto     uint16
	Interface string
	Data      []byte
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Open starts a capture on iface, or on every non-loopback interface when
// iface is empty. It needs CAP_NET_RAW.
func Open(iface string) (*Capture, error) {
	// Protocol 0 receives nothing until bind, so no frame bypasses the filter.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, fmt.Errorf("packet capture needs CAP_NET_RAW (run as root or grant the capability): %w", err)
		}
		return nil, fmt.Errorf("packet socket: %w", err)
	}
	c := &Capture{fd: fd, names: map[int]string{}, loopback: map[int]bool{}}
	if err := c.setup(iface); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return c, nil
}

func (c *Capture) setup(iface string) error {
	raw, err := bpf.Assemble(filter)
	if err != nil {
		return err
	}
	prog := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		prog[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	if err := unix.SetsockoptSockFprog(c.fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}); err != nil {
		return fmt.Errorf("attach capture filter: %w", err)
	}
	_ = unix.SetsockoptInt(c.fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	tv := unix.NsecToTimeval(int64(200 * time.Millisecond))
	if err := unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	bound := 0
	for _, ifc := range interfaces {
		c.names[ifc.Index] = ifc.Name
		c.loopback[ifc.Index] = ifc.Flags&net.FlagLoopback != 0
		if iface != "" && ifc.Name != iface {
			continue
		}
		if iface == "" && (ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0) {
			continue
		}
		if iface != "" {
			bound = ifc.Index
		}
		mreq := unix.PacketMreq{Ifindex: int32(ifc.Index), Type: unix.PACKET_MR_ALLMULTI}
		if unix.SetsockoptPacketMreq(c.fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq) == nil {
			c.AllMulti = append(c.AllMulti, ifc.Name)
		}
	}
	if iface != "" && bound == 0 {
		return fmt.Errorf("interface %q not found", iface)
	}
	return unix.Bind(c.fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: bound})
}

// Run delivers frames to fn until deadline or ctx ends. Frames from loopback
// are ignored.
func (c *Capture) Run(ctx context.Context, deadline time.Time, fn func(Frame) error) error {
	buf := make([]byte, 1<<16)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		n, from, err := unix.Recvfrom(c.fd, buf, 0)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("capture: %w", err)
		}
		ll, ok := from.(*unix.SockaddrLinklayer)
		if !ok || ll.Pkttype == packetOutgoing {
			continue
		}
		name, ok := c.names[ll.Ifindex]
		if !ok {
			// An interface that appeared after Open.
			if ifc, err := net.InterfaceByIndex(ll.Ifindex); err == nil {
				name = ifc.Name
				c.names[ll.Ifindex] = name
				c.loopback[ll.Ifindex] = ifc.Flags&net.FlagLoopback != 0
			}
		}
		if c.loopback[ll.Ifindex] {
			continue
		}
		if err := fn(Frame{Proto: htons(ll.Protocol), Interface: name, Data: buf[:n]}); err != nil {
			return err
		}
	}
	return nil
}

// Close ends the capture and its all-multicast memberships.
func (c *Capture) Close() error { return unix.Close(c.fd) }

// Supported reports whether this platform can capture.
const Supported = true
