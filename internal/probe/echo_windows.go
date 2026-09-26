package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"lanscan/internal/platform"
)

var (
	icmpDLL           = windows.NewLazySystemDLL("iphlpapi.dll")
	icmpCreateFile    = icmpDLL.NewProc("IcmpCreateFile")
	icmp6CreateFile   = icmpDLL.NewProc("Icmp6CreateFile")
	icmpCloseHandle   = icmpDLL.NewProc("IcmpCloseHandle")
	icmpSendEcho2Ex   = icmpDLL.NewProc("IcmpSendEcho2Ex")
	icmp6SendEcho2    = icmpDLL.NewProc("Icmp6SendEcho2")
	icmp6ParseReplies = icmpDLL.NewProc("Icmp6ParseReplies")
)

// Native status codes from ipexport.h. The ICMP API exposes status only, not
// the quoted packet, so error correlation is by API call rather than quotation.
const (
	ipSuccess             = 0
	ipBufTooSmall         = 11001
	ipDestNetUnreachable  = 11002
	ipDestHostUnreachable = 11003
	ipDestProtUnreachable = 11004 // IPv6: administratively prohibited
	ipDestPortUnreachable = 11005
	ipReqTimedOut         = 11010
	ipBadRoute            = 11012
	ipTTLExpiredTransit   = 11013
	ipTTLExpiredReassem   = 11014
	ipDestUnreachable     = 11040
	ipDestScopeMismatch   = 11045
)

// ipOptionInformation mirrors IP_OPTION_INFORMATION for 64-bit processes.
type ipOptionInformation struct {
	TTL         uint8
	TOS         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

// icmpEchoReply mirrors ICMP_ECHO_REPLY for 64-bit processes.
type icmpEchoReply struct {
	Address       [4]byte
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

// sockaddrIn6 mirrors SOCKADDR_IN6.
type sockaddrIn6 struct {
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte
	ScopeID  uint32
}

// ICMPV6_ECHO_REPLY begins with a packed 26-byte IPV6_ADDRESS_EX, then Status
// and RoundTripTime. Offsets are read explicitly rather than via a Go struct.
const (
	icmp6ReplyAddrOffset   = 6
	icmp6ReplyScopeOffset  = 22
	icmp6ReplyStatusOffset = 28
	icmp6ReplySize         = 36
)

func layoutOK() error {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return errors.New("native ICMP layouts require a 64-bit build")
	}
	if unsafe.Sizeof(ipOptionInformation{}) != 16 || unsafe.Sizeof(icmpEchoReply{}) != 40 || unsafe.Sizeof(sockaddrIn6{}) != 28 {
		return errors.New("native ICMP structure layout mismatch")
	}
	return nil
}

func openICMP(v6 bool) (uintptr, error) {
	if err := layoutOK(); err != nil {
		return 0, err
	}
	proc := icmpCreateFile
	if v6 {
		proc = icmp6CreateFile
	}
	if err := proc.Find(); err != nil {
		return 0, err
	}
	h, _, err := proc.Call()
	if windows.Handle(h) == windows.InvalidHandle {
		return 0, err
	}
	return h, nil
}

func EchoCapability(ipv6 bool) error {
	h, err := openICMP(ipv6)
	if err != nil {
		return err
	}
	icmpCloseHandle.Call(h)
	return nil
}

func statusOutcome(status uint32, v6 bool) string {
	switch status {
	case ipSuccess:
		return "echo_reply"
	case ipReqTimedOut:
		return "timeout"
	case ipTTLExpiredTransit, ipTTLExpiredReassem:
		return "time_exceeded"
	case ipDestProtUnreachable:
		if v6 {
			return "administratively_prohibited"
		}
		return "path_unreachable"
	case ipDestNetUnreachable, ipDestHostUnreachable, ipDestPortUnreachable, ipBadRoute, ipDestUnreachable, ipDestScopeMismatch:
		return "path_unreachable"
	}
	return "icmp_error"
}

func sockaddr6(a netip.Addr) sockaddrIn6 {
	s := sockaddrIn6{Family: windows.AF_INET6, Addr: a.As16()}
	if a.Zone() != "" {
		if i, err := platformInterfaceIndex(a.Zone()); err == nil {
			s.ScopeID = i
		}
	}
	return s
}

// Echo sends one synchronous native echo. The call runs on its own goroutine
// that owns every buffer until the API returns, so cancellation never frees
// memory still referenced by the OS.
func Echo(ctx context.Context, target netip.Addr, route platform.Route, hopLimit int) Result {
	backend := "windows_icmp4"
	if target.Is6() {
		backend = "windows_icmp6"
	}
	result := Result{Backend: backend, Correlation: "native_api_status"}
	timeout := time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	if timeout <= 0 {
		result.Outcome = "timeout"
		return result
	}
	if timeout < time.Millisecond {
		timeout = time.Millisecond
	}
	nonce := make([]byte, 20)
	if _, err := rand.Read(nonce); err != nil {
		result.Outcome = "local_error"
		result.Error = err.Error()
		return result
	}
	done := make(chan Result, 1)
	go func() { done <- nativeEcho(target, route, hopLimit, nonce, timeout, result) }()
	select {
	case r := <-done:
		return r
	case <-ctx.Done():
		result.Outcome = "timeout"
		if ctx.Err() == context.Canceled {
			result.Outcome = "canceled"
		}
		return result
	}
}

func nativeEcho(target netip.Addr, route platform.Route, hopLimit int, nonce []byte, timeout time.Duration, result Result) Result {
	v6 := target.Is6()
	h, err := openICMP(v6)
	if err != nil {
		result.Outcome = "unavailable"
		result.Error = err.Error()
		return result
	}
	defer icmpCloseHandle.Call(h)
	options := ipOptionInformation{TTL: 128}
	if hopLimit > 0 {
		if hopLimit > 255 {
			hopLimit = 255
		}
		options.TTL = uint8(hopLimit)
	}
	reply := make([]byte, 64+len(nonce)+8+32+icmp6ReplySize)
	ms := uint32(timeout / time.Millisecond)
	start := time.Now()
	var n uintptr
	var callErr error
	if v6 {
		source := sockaddrIn6{Family: windows.AF_INET6}
		if route.Source.IsValid() && route.Source.Is6() {
			source = sockaddr6(route.Source)
		}
		dest := sockaddr6(target)
		n, _, callErr = icmp6SendEcho2.Call(h, 0, 0, 0, uintptr(unsafe.Pointer(&source)), uintptr(unsafe.Pointer(&dest)), uintptr(unsafe.Pointer(&nonce[0])), uintptr(len(nonce)), uintptr(unsafe.Pointer(&options)), uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(ms))
		if n != 0 {
			n, _, callErr = icmp6ParseReplies.Call(uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)))
		}
	} else {
		var source [4]byte
		if route.Source.IsValid() && route.Source.Is4() {
			source = route.Source.As4()
		}
		dest := target.As4()
		n, _, callErr = icmpSendEcho2Ex.Call(h, 0, 0, 0, uintptr(binary.LittleEndian.Uint32(source[:])), uintptr(binary.LittleEndian.Uint32(dest[:])), uintptr(unsafe.Pointer(&nonce[0])), uintptr(len(nonce)), uintptr(unsafe.Pointer(&options)), uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(ms))
	}
	elapsed := time.Since(start)
	result.RTT = elapsed
	if n == 0 {
		// With no parsed reply, the API reports its status via GetLastError.
		var errno syscall.Errno
		if errors.As(callErr, &errno) && errno != 0 {
			result.Status = uint32(errno)
			result.Outcome = statusOutcome(uint32(errno), v6)
			if result.Outcome == "icmp_error" {
				result.Outcome = "local_error"
			}
			result.Error = fmt.Sprintf("native status %d", uint32(errno))
			return result
		}
		result.Outcome = "timeout"
		return result
	}
	var status uint32
	var responder netip.Addr
	if v6 {
		status = binary.LittleEndian.Uint32(reply[icmp6ReplyStatusOffset:])
		var addr [16]byte
		// IPV6_ADDRESS_EX stores sin6_addr as USHORT words in network order.
		copy(addr[:], reply[icmp6ReplyAddrOffset:icmp6ReplyAddrOffset+16])
		responder = netip.AddrFrom16(addr)
		result.RTT = time.Duration(binary.LittleEndian.Uint32(reply[icmp6ReplyStatusOffset+4:])) * time.Millisecond
	} else {
		r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
		status = r.Status
		responder = netip.AddrFrom4(r.Address)
		result.RTT = time.Duration(r.RoundTripTime) * time.Millisecond
		if status == ipSuccess {
			// Data points into the reply buffer; bounds-check it as an offset.
			base := uintptr(unsafe.Pointer(&reply[0]))
			off := int(r.Data - base)
			if r.Data < base || off+int(r.DataSize) > len(reply) || !bytes.Equal(reply[off:off+int(r.DataSize)], nonce) {
				result.Outcome = "uncorrelated_reply"
				return result
			}
		}
	}
	// Native RTT has millisecond resolution; keep the measured call time when
	// it rounds to zero so LAN paths still inform adaptive timeouts.
	if result.RTT == 0 {
		result.RTT = elapsed
	}
	result.Status = status
	result.Outcome = statusOutcome(status, v6)
	result.Responder = responder.String()
	if status == ipSuccess {
		if responder.WithZone("") != target.WithZone("") {
			result.Outcome = "uncorrelated_reply"
			return result
		}
		result.Response = true
		result.Correlation = "native_api_status_payload"
	}
	return result
}

func platformInterfaceIndex(name string) (uint32, error) {
	i, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return uint32(i.Index), nil
}
