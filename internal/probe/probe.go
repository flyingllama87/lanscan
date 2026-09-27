package probe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
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
	// Flow is FlowParis when the probe held its trace's flow identifiers.
	Flow string `json:"flow,omitempty"`
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

// flowNonceBytes is the fixed per-trace payload before the compensation word.
const flowNonceBytes = 18

// Flow keeps the ICMP echo fields that per-flow load balancers hash constant
// across the probes of one trace (Paris traceroute): the identifier and the
// checksum. Probes differ only in the sequence number, and a trailing payload
// word of ^seq keeps the ones-complement sum, hence the checksum, unchanged.
// The zero Flow sends an independent flow per probe.
type Flow struct {
	ID      uint16
	SeqBase uint16
	Nonce   [flowNonceBytes]byte
}

// NewFlow returns a random flow for one trace.
func NewFlow() (Flow, error) {
	var b [4 + flowNonceBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Flow{}, err
	}
	f := Flow{ID: binary.BigEndian.Uint16(b[:2]), SeqBase: binary.BigEndian.Uint16(b[2:4])}
	if f.ID == 0 {
		f.ID = 1
	}
	copy(f.Nonce[:], b[4:])
	return f, nil
}

// IsZero reports whether f requests no flow stability.
func (f Flow) IsZero() bool { return f.ID == 0 }

// seq returns the sequence number for a hop-limited probe.
func (f Flow) seq(hopLimit int) uint16 { return f.SeqBase + uint16(hopLimit) }

// payload returns the echo data for seq: the trace nonce, then ^seq.
func (f Flow) payload(seq uint16) []byte {
	b := make([]byte, flowNonceBytes+2)
	copy(b, f.Nonce[:])
	binary.BigEndian.PutUint16(b[flowNonceBytes:], ^seq)
	return b
}

// FlowParis marks a result whose probe kept its trace's identifier and checksum.
const FlowParis = "paris_constant_id_checksum"
