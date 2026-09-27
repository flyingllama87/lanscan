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

func TestRetryOnlySilentTargetsAfterFirstAttempts(t *testing.T) {
	r := fakeRunner()
	r.Config.Retry, r.Config.MaxOperations = 1, 100
	silent, refused, flaky := netip.MustParseAddr("10.1.1.1"), netip.MustParseAddr("10.1.1.2"), netip.MustParseAddr("10.1.1.3")
	var mu sync.Mutex
	var order []string
	echoes := map[netip.Addr]int{}
	r.Echo = func(_ context.Context, a netip.Addr, _ platform.Route, _ int) probe.Result {
		mu.Lock()
		defer mu.Unlock()
		echoes[a]++
		order = append(order, "echo:"+a.String())
		if a == flaky && echoes[a] == 2 {
			return probe.Result{Outcome: "echo_reply", Response: true}
		}
		return probe.Result{Outcome: "timeout"}
	}
	r.TCP = func(_ context.Context, a netip.Addr, _ platform.Route, _ int) probe.Result {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, "tcp:"+a.String())
		if a == refused {
			return probe.Result{Outcome: "path_unreachable"}
		}
		return probe.Result{Outcome: "timeout"}
	}
	var retried []string
	r.Emit = func(e model.Event) error {
		if e.Type == "observation" && e.Details["retry"] == true {
			mu.Lock()
			retried = append(retried, e.Address)
			mu.Unlock()
		}
		return nil
	}
	r.Config.Concurrency = 1
	cands := []discover.Candidate{{Address: silent}, {Address: refused}, {Address: flaky}}
	summary, err := r.Run(context.Background(), cands)
	if err != nil {
		t.Fatal(err)
	}
	// First attempts (echo, tcp) for all three, then one echo retry for the
	// two silent targets; the path_unreachable target is not retried.
	if len(order) != 8 || order[6] != "echo:10.1.1.1" || order[7] != "echo:10.1.1.3" {
		t.Fatalf("order %v", order)
	}
	if summary.Retried != 2 || summary.Responded != 1 || summary.Operations != 8 || len(retried) != 2 {
		t.Fatalf("%+v retried=%v", summary, retried)
	}
}

func TestRetryDisabledByDefault(t *testing.T) {
	r := fakeRunner()
	r.TCP = func(context.Context, netip.Addr, platform.Route, int) probe.Result {
		return probe.Result{Outcome: "timeout"}
	}
	summary, err := r.Run(context.Background(), candidates(2))
	if err != nil || summary.Retried != 0 || summary.Operations != 4 {
		t.Fatalf("%+v %v", summary, err)
	}
}

func TestBreadthFirstRoundRobinsInterfaces(t *testing.T) {
	var cands []discover.Candidate
	for i := range 4 {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16)
		cands = append(cands, discover.Candidate{Address: p.Addr().Next(), Prefix: &p, InterfaceID: "eth0"})
	}
	p := netip.MustParsePrefix("192.168.1.0/24")
	cands = append(cands, discover.Candidate{Address: netip.MustParseAddr("192.168.1.5"), Prefix: &p, InterfaceID: "wg0"})
	var got []string
	for _, c := range breadthFirst(cands) {
		got = append(got, c.InterfaceID)
	}
	if got[0] != "eth0" || got[1] != "wg0" {
		t.Fatalf("wg0 waited behind eth0: %v", got)
	}
}
