package probe

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"lanscan/internal/platform"
)

func TestEchoLoopbackCorrelation(t *testing.T) {
	if err := EchoCapability(false); err != nil {
		t.Skipf("ICMP unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := Echo(ctx, netip.MustParseAddr("127.0.0.1"), platform.Route{Source: netip.MustParseAddr("127.0.0.1")}, 0)
	if !result.Response || result.Outcome != "echo_reply" {
		t.Fatalf("%+v", result)
	}
}
func TestTCPLoopback(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := TCP(ctx, netip.MustParseAddr("127.0.0.1"), platform.Route{Source: netip.MustParseAddr("127.0.0.1")}, listener.Addr().(*net.TCPAddr).Port)
	if !result.Response || result.Outcome != "connected" {
		t.Fatalf("%+v", result)
	}
}
func TestICMPQuoteRequiresTargetAndIdentity(t *testing.T) {
	b := make([]byte, 28)
	b[0] = 0x45
	b[9] = 1
	copy(b[16:20], []byte{10, 1, 2, 3})
	b[20] = 8
	binary.BigEndian.PutUint16(b[24:26], 123)
	binary.BigEndian.PutUint16(b[26:28], 456)
	target := netip.MustParseAddr("10.1.2.3")
	if !matchQuote(b, target, 123, 456) {
		t.Fatal("valid quotation rejected")
	}
	if matchQuote(b, target, 124, 456) || matchQuote(b, netip.MustParseAddr("10.1.2.4"), 123, 456) || matchQuote(b[:27], target, 123, 456) {
		t.Fatal("uncorrelated or truncated quotation accepted")
	}
}
func FuzzICMPQuote(f *testing.F) {
	f.Add([]byte{0x45})
	f.Add(make([]byte, 48))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = matchQuote(b, netip.MustParseAddr("10.1.2.3"), 1, 2)
		_ = matchQuote(b, netip.MustParseAddr("2001:db8::1"), 1, 2)
	})
}

func echoPayload(t *testing.T, id, seq int, nonce []byte) []byte {
	t.Helper()
	b, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: seq, Data: nonce}}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func errorQueueOOB(origin, typ, code uint8, offender [4]byte) []byte {
	ee := make([]byte, 16+16)
	ee[4] = origin
	ee[5] = typ
	ee[6] = code
	binary.NativeEndian.PutUint16(ee[16:], unix.AF_INET)
	copy(ee[20:24], offender[:])
	oob := make([]byte, unix.CmsgSpace(len(ee)))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = unix.SOL_IP
	h.Type = unix.IP_RECVERR
	h.SetLen(unix.CmsgLen(len(ee)))
	copy(oob[unix.CmsgLen(0):], ee)
	return oob
}

func TestErrorQueueCorrelatesOwnPayload(t *testing.T) {
	nonce := []byte("0123456789abcdefghij")
	m := matcher{proto: 1, target: netip.MustParseAddr("10.9.9.9"), id: 7, seq: 42, nonce: nonce}
	oob := errorQueueOOB(unix.SO_EE_ORIGIN_ICMP, 11, 0, [4]byte{10, 0, 0, 254})
	r, ok := m.errorQueue(echoPayload(t, 7, 42, nonce), oob)
	if !ok || r.Outcome != "time_exceeded" || r.Responder != "10.0.0.254" || r.Response {
		t.Fatalf("%+v %v", r, ok)
	}
	if _, ok := m.errorQueue(echoPayload(t, 7, 43, nonce), oob); ok {
		t.Fatal("accepted another probe's error")
	}
	oob = errorQueueOOB(unix.SO_EE_ORIGIN_ICMP, 3, 13, [4]byte{10, 0, 0, 1})
	if r, ok := m.errorQueue(echoPayload(t, 7, 42, nonce), oob); !ok || r.Outcome != "administratively_prohibited" {
		t.Fatalf("%+v", r)
	}
	if _, ok := m.errorQueue(echoPayload(t, 7, 42, nonce), errorQueueOOB(unix.SO_EE_ORIGIN_LOCAL, 0, 0, [4]byte{})); ok {
		t.Fatal("accepted a local error as an ICMP response")
	}
}

func TestICMPErrorOutcomes(t *testing.T) {
	for _, test := range []struct {
		v6        bool
		typ, code int
		want      string
	}{{false, 11, 0, "time_exceeded"}, {false, 3, 1, "path_unreachable"}, {false, 3, 10, "administratively_prohibited"}, {true, 3, 0, "time_exceeded"}, {true, 1, 1, "administratively_prohibited"}, {true, 1, 3, "path_unreachable"}, {false, 5, 0, "icmp_error"}} {
		if got := icmpErrorOutcome(test.v6, test.typ, test.code); got != test.want {
			t.Errorf("%+v: %s", test, got)
		}
	}
}

func FuzzErrorQueue(f *testing.F) {
	f.Add([]byte{8, 0, 0, 0, 0, 7, 0, 42}, []byte{})
	f.Fuzz(func(t *testing.T, payload, oob []byte) {
		m := matcher{proto: 1, target: netip.MustParseAddr("10.9.9.9"), id: 7, seq: 42, nonce: []byte("x")}
		m.errorQueue(payload, oob)
		m.packet(payload, netip.MustParseAddr("10.9.9.9"))
	})
}
