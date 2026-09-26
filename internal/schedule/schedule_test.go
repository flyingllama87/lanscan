package schedule

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"lanscan/internal/discover"
	"lanscan/internal/model"
	"lanscan/internal/platform"
	"lanscan/internal/probe"
)

func fakeRunner() *Runner {
	return &Runner{
		Config: Config{Rate: 10000, Concurrency: 4, MaxOperations: 10, Timeout: time.Second, Port: 443},
		Emit:   func(model.Event) error { return nil }, Reserve: func(model.Event) error { return nil },
		Lookup: func(target, source netip.Addr, iface string) (platform.Route, error) {
			return platform.Route{Source: netip.MustParseAddr("10.0.0.1"), Interface: target.String()}, nil
		},
		Echo: func(context.Context, netip.Addr, platform.Route, int) probe.Result {
			return probe.Result{Outcome: "timeout"}
		},
		TCP: func(context.Context, netip.Addr, platform.Route, int) probe.Result {
			return probe.Result{Outcome: "connected", Response: true}
		},
	}
}
func candidates(n int) []discover.Candidate {
	out := make([]discover.Candidate, n)
	a := netip.MustParseAddr("10.1.1.1")
	for i := range out {
		out[i].Address = a
		a = a.Next()
	}
	return out
}
func TestBudgetNeverExceededWithConcurrentFallback(t *testing.T) {
	r := fakeRunner()
	r.Config.MaxOperations = 3
	var mu sync.Mutex
	reservations := 0
	r.Reserve = func(e model.Event) error { mu.Lock(); defer mu.Unlock(); reservations++; return nil }
	summary, err := r.Run(context.Background(), candidates(20))
	if err != nil || summary.Operations != 3 || reservations != 3 || summary.StopReason != "operation_budget_exhausted" {
		t.Fatalf("%+v reservations=%d error=%v", summary, reservations, err)
	}
}
func TestFailedReservationPreventsProbe(t *testing.T) {
	r := fakeRunner()
	boom := errors.New("disk full")
	r.Reserve = func(model.Event) error { return boom }
	r.Echo = func(context.Context, netip.Addr, platform.Route, int) probe.Result {
		t.Error("sent after failed reservation")
		return probe.Result{}
	}
	summary, err := r.Run(context.Background(), candidates(1))
	if !errors.Is(err, boom) || summary.Operations != 0 {
		t.Fatalf("%+v %v", summary, err)
	}
}
func TestEchoSuccessAvoidsTCP(t *testing.T) {
	r := fakeRunner()
	r.Echo = func(context.Context, netip.Addr, platform.Route, int) probe.Result {
		return probe.Result{Response: true, Outcome: "echo_reply"}
	}
	r.TCP = func(context.Context, netip.Addr, platform.Route, int) probe.Result {
		t.Error("unnecessary fallback")
		return probe.Result{}
	}
	summary, err := r.Run(context.Background(), candidates(1))
	if err != nil || summary.Operations != 1 || summary.Responded != 1 {
		t.Fatalf("%+v %v", summary, err)
	}
}
func TestChangedRouteSkipsDispatch(t *testing.T) {
	r := fakeRunner()
	n := 0
	r.Lookup = func(target, source netip.Addr, iface string) (platform.Route, error) {
		n++
		return platform.Route{Source: netip.MustParseAddr("10.0.0.1"), Interface: string(rune('a' + n))}, nil
	}
	r.Echo = func(context.Context, netip.Addr, platform.Route, int) probe.Result {
		t.Error("sent on changed route")
		return probe.Result{}
	}
	summary, err := r.Run(context.Background(), candidates(1))
	if err != nil || summary.Skipped["route_changed_before_dispatch"] != 1 {
		t.Fatalf("%+v %v", summary, err)
	}
}
func TestCancellationDuringPacing(t *testing.T) {
	r := fakeRunner()
	r.Config.Rate = 0.1
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	summary, err := r.Run(ctx, candidates(4))
	if err != nil || time.Since(start) > time.Second || summary.Operations > 1 {
		t.Fatalf("%+v %v", summary, err)
	}
}
func TestFirstAttemptsFollowPlannedOrder(t *testing.T) {
	r := fakeRunner()
	r.Config.Concurrency = 16
	r.Config.MaxOperations = 100
	var mu sync.Mutex
	var order []string
	r.Reserve = func(e model.Event) error {
		mu.Lock()
		defer mu.Unlock()
		if e.Protocol == "icmp" {
			order = append(order, e.Address)
		}
		return nil
	}
	// Later jobs look up routes faster, which previously let them jump ahead.
	r.Lookup = func(target, source netip.Addr, iface string) (platform.Route, error) {
		time.Sleep(time.Duration(20-int(target.As4()[3])) * 100 * time.Microsecond)
		return platform.Route{Source: netip.MustParseAddr("10.0.0.1"), Interface: "eth0"}, nil
	}
	r.Config.PathRate = 100000
	c := candidates(12)
	for i := range c {
		p := netip.PrefixFrom(c[i].Address, 32)
		c[i].Prefix = &p
	}
	c[0].Synthetic = true
	if _, err := r.Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if len(order) != 12 || order[len(order)-1] != c[0].Address.String() {
		t.Fatalf("synthetic sample not last: %v", order)
	}
	for i := 0; i < 10; i++ {
		if order[i] >= order[i+1] {
			t.Fatalf("out of order: %v", order)
		}
	}
}
func TestUnavailableEchoReservesNoBudget(t *testing.T) {
	r := fakeRunner()
	r.Config.NoEcho4 = true
	var protocols []string
	r.Reserve = func(e model.Event) error { protocols = append(protocols, e.Protocol); return nil }
	r.Echo = func(context.Context, netip.Addr, platform.Route, int) probe.Result {
		t.Error("echo attempted without capability")
		return probe.Result{}
	}
	summary, err := r.Run(context.Background(), candidates(1))
	if err != nil || len(protocols) != 1 || protocols[0] != "tcp" || summary.Skipped["icmp_unavailable"] != 1 || summary.Responded != 1 {
		t.Fatalf("%+v %v %v", summary, protocols, err)
	}
}
