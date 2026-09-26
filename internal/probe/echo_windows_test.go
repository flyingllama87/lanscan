package probe

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"lanscan/internal/platform"
)

// These run only on native Windows; cross-compilation does not exercise them.
func TestNativeEchoLoopback(t *testing.T) {
	for _, target := range []string{"127.0.0.1", "::1"} {
		a := netip.MustParseAddr(target)
		if err := EchoCapability(a.Is6()); err != nil {
			t.Fatalf("%s capability: %v", target, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		result := Echo(ctx, a, platform.Route{Source: a}, 0)
		cancel()
		if !result.Response || result.Outcome != "echo_reply" || result.Responder != target {
			t.Fatalf("%s: %+v", target, result)
		}
	}
}

func TestNativeEchoCancellationReturnsPromptly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	// TEST-NET-1 is not routed on the public internet; silence is expected.
	result := Echo(ctx, netip.MustParseAddr("192.0.2.1"), platform.Route{}, 0)
	if time.Since(start) > time.Second || result.Response {
		t.Fatalf("%+v after %v", result, time.Since(start))
	}
}

func TestTCPLoopbackWindows(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r := TCP(ctx, netip.MustParseAddr("127.0.0.1"), platform.Route{Source: netip.MustParseAddr("127.0.0.1")}, l.Addr().(*net.TCPAddr).Port)
	if r.Outcome != "connected" {
		t.Fatalf("%+v", r)
	}
}

func TestTCPRefusedIsEndpointResponse(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r := TCP(ctx, netip.MustParseAddr("127.0.0.1"), platform.Route{Source: netip.MustParseAddr("127.0.0.1")}, port)
	if r.Outcome != "refused" || !r.Response {
		t.Fatalf("%+v", r)
	}
}
