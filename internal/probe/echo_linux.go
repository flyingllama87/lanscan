package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"lanscan/internal/platform"
)

// pingSocket opens a ping socket, or a raw socket when ping sockets are not
// permitted. A nonzero port asks a ping socket for that echo identifier.
func pingSocket(source netip.Addr, iface string, port uint16) (net.PacketConn, bool, int, error) {
	family, protocol := unix.AF_INET, unix.IPPROTO_ICMP
	if source.Is6() {
		family, protocol = unix.AF_INET6, unix.IPPROTO_ICMPV6
	}
	raw := false
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		raw = true
		fd, err = unix.Socket(family, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	}
	if err != nil {
		return nil, false, 0, err
	}
	f := os.NewFile(uintptr(fd), "lanscan-icmp")
	defer f.Close()
	// IP_RECVERR delivers correlated ICMP errors to ping sockets for traces.
	if source.Is6() {
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1)
	} else {
		err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1)
	}
	if err != nil {
		return nil, raw, 0, err
	}
	if iface != "" {
		if err = unix.BindToDevice(fd, iface); err != nil {
			return nil, raw, 0, err
		}
	}
	if raw {
		port = 0
	}
	if source.Is6() {
		s := &unix.SockaddrInet6{Addr: source.As16(), Port: int(port)}
		if source.Zone() != "" {
			i, e := net.InterfaceByName(source.Zone())
			if e != nil {
				return nil, raw, 0, e
			}
			s.ZoneId = uint32(i.Index)
		}
		err = unix.Bind(fd, s)
		if err == unix.EADDRINUSE && port != 0 {
			// Another socket holds the identifier; the probe loses flow stability.
			s.Port = 0
			err = unix.Bind(fd, s)
		}
	} else {
		err = unix.Bind(fd, &unix.SockaddrInet4{Addr: source.As4(), Port: int(port)})
		if err == unix.EADDRINUSE && port != 0 {
			err = unix.Bind(fd, &unix.SockaddrInet4{Addr: source.As4()})
		}
	}
	if err != nil {
		return nil, raw, 0, err
	}
	id := 0
	if !raw {
		addr, e := unix.Getsockname(fd)
		if e != nil {
			return nil, raw, 0, e
		}
		switch v := addr.(type) {
		case *unix.SockaddrInet4:
			id = v.Port
		case *unix.SockaddrInet6:
			id = v.Port
		}
	}
	c, err := net.FilePacketConn(f)
	return c, raw, id, err
}

func EchoCapability(ipv6 bool) error {
	a := netip.IPv4Unspecified()
	if ipv6 {
		a = netip.IPv6Unspecified()
	}
	c, _, _, err := pingSocket(a, "", 0)
	if err == nil {
		err = c.Close()
	}
	return err
}

// FlowStableTrace reports that EchoFlow can hold a trace's flow identifiers.
const FlowStableTrace = true

func Echo(ctx context.Context, target netip.Addr, route platform.Route, hopLimit int) Result {
	return EchoFlow(ctx, target, route, hopLimit, Flow{})
}

// EchoFlow sends one echo; a nonzero flow keeps the identifier and checksum
// of every probe in a trace constant (see Flow).
func EchoFlow(ctx context.Context, target netip.Addr, route platform.Route, hopLimit int, flow Flow) Result {
	start := time.Now()
	result := Result{Backend: "linux_ping_socket"}
	c, raw, id, err := pingSocket(route.Source, route.Interface, flow.ID)
	if err != nil {
		result.Outcome = "unavailable"
		result.Error = err.Error()
		return result
	}
	defer c.Close()
	if raw {
		result.Backend = "linux_raw_icmp"
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err = c.SetDeadline(deadline); err != nil {
			result.Outcome = "local_error"
			result.Error = err.Error()
			return result
		}
	}
	proto := 1
	var typ icmp.Type = ipv4.ICMPTypeEcho
	if target.Is6() {
		proto = 58
		typ = ipv6.ICMPTypeEchoRequest
	}
	if hopLimit > 0 {
		if target.Is6() {
			err = ipv6.NewPacketConn(c).SetHopLimit(hopLimit)
		} else {
			err = ipv4.NewPacketConn(c).SetTTL(hopLimit)
		}
		if err != nil {
			result.Outcome = "unavailable"
			result.Error = err.Error()
			return result
		}
	}
	var nonce []byte
	var seq int
	if flow.IsZero() {
		nonce = make([]byte, 20)
		if _, err = rand.Read(nonce); err != nil {
			result.Outcome = "local_error"
			result.Error = err.Error()
			return result
		}
		if raw {
			id = int(binary.BigEndian.Uint16(nonce[:2]))
		}
		seq = int(binary.BigEndian.Uint16(nonce[2:4]))
	} else {
		if raw {
			id = int(flow.ID)
		}
		s := flow.seq(hopLimit)
		seq, nonce = int(s), flow.payload(s)
	}
	flowLabel := ""
	if !flow.IsZero() && id == int(flow.ID) {
		flowLabel = FlowParis
	}
	request := icmp.Message{Type: typ, Body: &icmp.Echo{ID: id, Seq: seq, Data: nonce}}
	b, err := request.Marshal(nil)
	if err != nil {
		result.Outcome = "local_error"
		result.Error = err.Error()
		return result
	}
	var dest net.Addr = &net.UDPAddr{IP: net.IP(target.AsSlice()), Zone: target.Zone()}
	if raw {
		dest = &net.IPAddr{IP: net.IP(target.AsSlice()), Zone: target.Zone()}
	}
	if _, err = c.WriteTo(b, dest); err != nil {
		result.Outcome = "send_error"
		result.Error = err.Error()
		return result
	}
	sc, ok := c.(syscall.Conn)
	if !ok {
		result.Outcome = "local_error"
		result.Error = "ICMP socket lacks raw access"
		return result
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		result.Outcome = "local_error"
		result.Error = err.Error()
		return result
	}
	m := matcher{proto: proto, target: target, id: id, seq: seq, nonce: nonce, raw: raw}
	var matched *Result
	buffer := make([]byte, 2048)
	oob := make([]byte, 512)
	readErr := rc.Read(func(fd uintptr) bool {
		// Drain both queues: the poller is edge-triggered, so returning early
		// with queued data could stall until the deadline.
		for {
			progress := false
			n, oobn, _, _, err := unix.Recvmsg(int(fd), buffer, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
			if err == nil {
				progress = true
				if r, ok := m.errorQueue(buffer[:n], oob[:oobn]); ok {
					matched = &r
					return true
				}
			}
			n, from, err := unix.Recvfrom(int(fd), buffer, unix.MSG_DONTWAIT)
			if err == nil {
				progress = true
				if r, ok := m.packet(buffer[:n], sockaddrAddr(from)); ok {
					matched = &r
					return true
				}
			} else if err != unix.EAGAIN && err != unix.EWOULDBLOCK && err != unix.EINTR && !isICMPErrno(err) {
				return true
			}
			if !progress {
				return false
			}
		}
	})
	if matched != nil {
		matched.Backend = result.Backend
		matched.RTT = time.Since(start)
		matched.Flow = flowLabel
		return *matched
	}
	result.Flow = flowLabel
	result.Outcome = "timeout"
	if ctx.Err() == context.Canceled {
		result.Outcome = "canceled"
	}
	if readErr != nil {
		result.Error = readErr.Error()
	}
	return result
}

// isICMPErrno reports errors that IP_RECVERR surfaces on ordinary reads while
// the details wait in the error queue.
func isICMPErrno(err error) bool {
	switch err {
	case unix.EHOSTUNREACH, unix.ENETUNREACH, unix.ECONNREFUSED, unix.EACCES, unix.EPERM, unix.EPROTO, unix.EMSGSIZE:
		return true
	}
	return false
}

type matcher struct {
	proto  int
	target netip.Addr
	id     int
	seq    int
	nonce  []byte
	raw    bool
}

func (m matcher) packet(data []byte, peer netip.Addr) (Result, bool) {
	// Raw IPv4 readers normally include the IPv4 header.
	if m.proto == 1 && len(data) >= 20 && data[0]>>4 == 4 {
		off := int(data[0]&15) * 4
		if off < 20 || off > len(data) {
			return Result{}, false
		}
		data = data[off:]
	}
	message, err := icmp.ParseMessage(m.proto, data)
	if err != nil {
		return Result{}, false
	}
	var result Result
	if echo, ok := message.Body.(*icmp.Echo); ok {
		reply := message.Type == ipv4.ICMPTypeEchoReply || message.Type == ipv6.ICMPTypeEchoReply
		if !reply || peer.WithZone("") != m.target.WithZone("") || echo.Seq != m.seq || !bytes.Equal(echo.Data, m.nonce) {
			return Result{}, false
		}
		result.Outcome = "echo_reply"
		result.Response = true
		result.Correlation = "echo_id_seq_nonce"
	} else {
		var quote []byte
		switch body := message.Body.(type) {
		case *icmp.DstUnreach:
			quote = body.Data
		case *icmp.TimeExceeded:
			quote = body.Data
		default:
			return Result{}, false
		}
		if !matchQuote(quote, m.target, m.id, m.seq) {
			return Result{}, false
		}
		result.Correlation = "quoted_header"
	}
	result.Responder = peer.String()
	result.ICMPCode = message.Code
	switch typ := message.Type.(type) {
	case ipv4.ICMPType:
		result.ICMPType = int(typ)
	case ipv6.ICMPType:
		result.ICMPType = int(typ)
	}
	if !result.Response {
		result.Outcome = icmpErrorOutcome(m.target.Is6(), result.ICMPType, result.ICMPCode)
	}
	return result, true
}

// errorQueue decodes an IP_RECVERR entry. The kernel associates the entry with
// this socket; the returned original payload must still carry our seq/nonce.
func (m matcher) errorQueue(payload, oob []byte) (Result, bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return Result{}, false
	}
	for _, msg := range msgs {
		v4 := msg.Header.Level == unix.SOL_IP && msg.Header.Type == unix.IP_RECVERR
		v6 := msg.Header.Level == unix.SOL_IPV6 && msg.Header.Type == unix.IPV6_RECVERR
		if !v4 && !v6 {
			continue
		}
		ee, offender, ok := parseExtendedErr(msg.Data)
		if !ok {
			continue
		}
		if ee.Origin != unix.SO_EE_ORIGIN_ICMP && ee.Origin != unix.SO_EE_ORIGIN_ICMP6 {
			continue
		}
		if !m.ownPayload(payload) {
			continue
		}
		r := Result{Responder: offender.String(), ICMPType: int(ee.Type), ICMPCode: int(ee.Code), Correlation: "socket_error_queue_payload"}
		r.Outcome = icmpErrorOutcome(ee.Origin == unix.SO_EE_ORIGIN_ICMP6, r.ICMPType, r.ICMPCode)
		return r, true
	}
	return Result{}, false
}

func (m matcher) ownPayload(payload []byte) bool {
	if m.proto == 1 && len(payload) >= 20 && payload[0]>>4 == 4 {
		off := int(payload[0]&15) * 4
		if off < 20 || off > len(payload) {
			return false
		}
		payload = payload[off:]
	}
	message, err := icmp.ParseMessage(m.proto, payload)
	if err != nil {
		return false
	}
	echo, ok := message.Body.(*icmp.Echo)
	return ok && echo.Seq == m.seq && bytes.Equal(echo.Data, m.nonce)
}

func parseExtendedErr(b []byte) (unix.SockExtendedErr, netip.Addr, bool) {
	var ee unix.SockExtendedErr
	size := int(unsafe.Sizeof(ee))
	if len(b) < size {
		return ee, netip.Addr{}, false
	}
	ee = *(*unix.SockExtendedErr)(unsafe.Pointer(&b[0]))
	rest := b[size:]
	var offender netip.Addr
	if len(rest) >= 2 {
		switch binary.NativeEndian.Uint16(rest[:2]) {
		case unix.AF_INET:
			if len(rest) >= 8 {
				offender = netip.AddrFrom4([4]byte(rest[4:8]))
			}
		case unix.AF_INET6:
			if len(rest) >= 24 {
				offender = netip.AddrFrom16([16]byte(rest[8:24])).Unmap()
			}
		}
	}
	return ee, offender, true
}

// icmpErrorOutcome keeps administrative denial distinct from other path failures.
func icmpErrorOutcome(v6 bool, typ, code int) string {
	if v6 {
		switch {
		case typ == 3:
			return "time_exceeded"
		case typ == 1 && (code == 1 || code == 5 || code == 6):
			return "administratively_prohibited"
		case typ == 1:
			return "path_unreachable"
		}
		return "icmp_error"
	}
	switch {
	case typ == 11:
		return "time_exceeded"
	case typ == 3 && (code == 9 || code == 10 || code == 13):
		return "administratively_prohibited"
	case typ == 3:
		return "path_unreachable"
	}
	return "icmp_error"
}

func sockaddrAddr(sa unix.Sockaddr) netip.Addr {
	switch v := sa.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrFrom4(v.Addr)
	case *unix.SockaddrInet6:
		return netip.AddrFrom16(v.Addr).Unmap()
	}
	return netip.Addr{}
}

func matchQuote(b []byte, target netip.Addr, id, seq int) bool {
	if len(b) < 1 {
		return false
	}
	offset := 0
	switch b[0] >> 4 {
	case 4:
		if !target.Is4() || len(b) < 20 || b[9] != 1 {
			return false
		}
		offset = int(b[0]&15) * 4
		if offset < 20 || offset+8 > len(b) {
			return false
		}
		if netip.AddrFrom4([4]byte(b[16:20])) != target {
			return false
		}
		if b[offset] != 8 {
			return false
		}
	case 6:
		if !target.Is6() || len(b) < 48 || b[6] != 58 {
			return false
		}
		offset = 40
		if netip.AddrFrom16([16]byte(b[24:40])) != target.WithZone("") {
			return false
		}
		if b[offset] != 128 {
			return false
		}
	default:
		return false
	}
	return int(binary.BigEndian.Uint16(b[offset+4:offset+6])) == id && int(binary.BigEndian.Uint16(b[offset+6:offset+8])) == seq
}
