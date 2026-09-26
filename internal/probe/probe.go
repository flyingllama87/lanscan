package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"lanscan/internal/platform"
)

type Result struct {
	Outcome   string        `json:"outcome"`
	Response  bool          `json:"response"`
	Responder string        `json:"responder,omitempty"`
	Backend   string        `json:"backend"`
	Error     string        `json:"error,omitempty"`
	RTT       time.Duration `json:"rtt_ns"`
	ICMPType  int           `json:"icmp_type,omitempty"`
	ICMPCode  int           `json:"icmp_code,omitempty"`
	// Status is a native API status when the backend exposes no ICMP quotation.
	Status uint32 `json:"status,omitempty"`
	// Correlation describes how a response was attributed to this probe.
	Correlation string `json:"correlation,omitempty"`
}

func TCP(ctx context.Context, target netip.Addr, route platform.Route, port int) Result {
	start := time.Now()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(route.Source.AsSlice()), Zone: route.Source.Zone()}, Control: func(network, address string, c syscall.RawConn) error {
		var bindErr error
		err := c.Control(func(fd uintptr) { bindErr = platform.BindSocket(fd, target.Is6(), route.Interface) })
		if err != nil {
			return err
		}
		return bindErr
	}}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(target.String(), strconv.Itoa(port)))
	result := Result{Backend: "tcp_connect", RTT: time.Since(start)}
	if err == nil {
		conn.Close()
		result.Outcome = "connected"
		result.Response = true
		result.Responder = target.String()
		return result
	}
	result.Error = err.Error()
	switch {
	case isAny(err, refusedErrors):
		result.Outcome = "refused"
		result.Response = true
		result.Responder = target.String()
	case errors.Is(err, context.Canceled):
		result.Outcome = "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		result.Outcome = "timeout"
	case isAny(err, unreachableErrors):
		result.Outcome = "path_unreachable"
	default:
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			result.Outcome = "timeout"
		} else {
			result.Outcome = "local_or_transport_error"
		}
	}
	return result
}

func isAny(err error, targets []error) bool {
	for _, t := range targets {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}
