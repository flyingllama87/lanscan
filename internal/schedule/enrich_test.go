package schedule

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"lanscan/internal/model"
	"lanscan/internal/platform"
	"lanscan/internal/probe"
)

type fakeResolver struct {
	mu      sync.Mutex
	forward map[string][]netip.Addr
	reverse map[string][]string
	queries []string
}

func (f *fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, network+" "+host)
	var out []netip.Addr
	for _, a := range f.forward[host] {
		if (network == "ip4") == a.Is4() {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return out, nil
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, "ptr "+addr)
	return f.reverse[addr], nil
}

type recorder struct {
	mu     sync.Mutex
	events []model.Event
	ops    []model.Event
}

func (r *recorder) emit(e model.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}
func (r *recorder) reserve(e model.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ops = append(r.ops, e)
	return nil
}

func enrichRunner(rec *recorder) *Runner {
	r := fakeRunner()
	r.Config.MaxOperations = 100
	r.Config.EnrichmentLimit = 50
	r.Config.DNSBudget = 50
	r.Config.DNSRate = 10000
	r.Config.PathRate = 10000
	r.Config.TraceBudget = 50
	r.Emit = rec.emit
	r.Reserve = rec.reserve
	return r
}

func TestForwardDNSChargesEachQueryAndUsesAbsoluteNames(t *testing.T) {
	rec := &recorder{}
	r := enrichRunner(rec)
	res := &fakeResolver{forward: map[string][]netip.Addr{"app.corp.example.": {netip.MustParseAddr("10.1.1.5"), netip.MustParseAddr("fd00::5")}}}
	answers, err := r.Forward(context.Background(), DNSContext{Resolver: res, Policy: "system"}, []string{"app.corp.example", "missing.corp.example"})
	if err != nil || answers != 2 {
		t.Fatalf("answers=%d err=%v", answers, err)
	}
	if len(rec.ops) != 4 || r.ByMethod()["dns"] != 4 {
		t.Fatalf("expected A+AAAA reservation per name, got %d", len(rec.ops))
	}
	for _, q := range res.queries {
		if q[len(q)-1] != '.' {
			t.Fatalf("relative query %q could expand via search list", q)
		}
	}
	addresses := 0
	for _, e := range rec.events {
		if e.Address != "" {
			addresses++
			if e.Reachability != "unknown" || e.Prefix != nil {
				t.Fatalf("DNS answer promoted: %+v", e)
			}
		}
		if e.Details["operation_id"] == nil {
			t.Fatal("DNS result lacks operation identity for recovery")
		}
	}
	if addresses != 2 {
		t.Fatalf("addresses=%d", addresses)
	}
}

func TestDNSBudgetAndEnrichmentReservation(t *testing.T) {
	rec := &recorder{}
	r := enrichRunner(rec)
	r.Config.DNSBudget = 3
	names := []string{"a.corp", "b.corp", "c.corp", "d.corp"}
	if _, err := r.Forward(context.Background(), DNSContext{Resolver: &fakeResolver{}}, names); err != nil {
		t.Fatal(err)
	}
	if len(rec.ops) != 3 {
		t.Fatalf("DNS budget exceeded: %d", len(rec.ops))
	}
	rec2 := &recorder{}
	r2 := enrichRunner(rec2)
	r2.Config.EnrichmentLimit = 2
	if _, err := r2.Forward(context.Background(), DNSContext{Resolver: &fakeResolver{}}, names); err != nil {
		t.Fatal(err)
	}
	if len(rec2.ops) != 2 {
		t.Fatalf("enrichment reservation exceeded: %d", len(rec2.ops))
	}
	// Validation can still use the remainder of the budget.
	summary, err := r2.Run(context.Background(), candidates(1))
	if err != nil || summary.Operations == 0 {
		t.Fatalf("validation starved: %+v %v", summary, err)
	}
}

func TestReverseForwardConfirmsOnlyApprovedSuffix(t *testing.T) {
	rec := &recorder{}
	r := enrichRunner(rec)
	res := &fakeResolver{reverse: map[string][]string{
		"10.1.1.5": {"host.corp.example.", "evil.attacker.test.", "bad name"},
	}, forward: map[string][]netip.Addr{"host.corp.example.": {netip.MustParseAddr("10.1.1.5")}}}
	err := r.Reverse(context.Background(), DNSContext{Resolver: res, Suffixes: []string{"corp.example"}}, []netip.Addr{netip.MustParseAddr("10.1.1.5")})
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range res.queries {
		if q == "ip4 evil.attacker.test." || q == "ip6 evil.attacker.test." {
			t.Fatal("expanded a name outside the approved suffix")
		}
	}
	names := map[string]bool{}
	for _, e := range rec.events {
		if e.Source == "dns_reverse" {
			names[e.Name] = true
		}
	}
	if !names["host.corp.example"] || !names["evil.attacker.test"] || names["bad name"] {
		t.Fatalf("naming evidence %v", names)
	}
	if len(rec.ops) != 2 {
		t.Fatalf("expected PTR plus one forward confirmation, got %d", len(rec.ops))
	}
}

func TestInSuffix(t *testing.T) {
	for _, test := range []struct {
		name string
		want bool
	}{{"a.corp.example", true}, {"corp.example", true}, {"CORP.example.", true}, {"xcorp.example", false}, {"corp.example.evil", false}} {
		if got := InSuffix(test.name, []string{"corp.example"}); got != test.want {
			t.Errorf("%s: %v", test.name, got)
		}
	}
	if InSuffix("a.corp.example", nil) {
		t.Fatal("empty suffix list approves names")
	}
}

func hopEcho(hops map[int]probe.Result) func(context.Context, netip.Addr, platform.Route, int) probe.Result {
	return func(_ context.Context, _ netip.Addr, _ platform.Route, ttl int) probe.Result {
		if r, ok := hops[ttl]; ok {
			return r
		}
		return probe.Result{Outcome: "timeout"}
	}
}

func traceStops(t *testing.T, r *Runner, rec *recorder) string {
	t.Helper()
	target := netip.MustParseAddr("10.9.9.9")
	route, _ := r.Lookup(target, netip.Addr{}, "")
	if err := r.Trace(context.Background(), []TraceTarget{{Target: target, Route: route}}, 16); err != nil {
		t.Fatal(err)
	}
	last := rec.events[len(rec.events)-1]
	if last.Type != "trace_finished" {
		t.Fatalf("missing trace summary: %+v", last)
	}
	return last.Outcome
}

func TestTraceStopConditions(t *testing.T) {
	rec := &recorder{}
	r := enrichRunner(rec)
	r.Echo = hopEcho(map[int]probe.Result{
		1: {Outcome: "time_exceeded", Responder: "10.0.0.254"},
		2: {Outcome: "echo_reply", Response: true, Responder: "10.9.9.9"},
	})
	if stop := traceStops(t, r, rec); stop != "destination_reached" || len(rec.ops) != 2 {
		t.Fatalf("stop=%s ops=%d", stop, len(rec.ops))
	}
	hop := rec.events[0]
	if hop.Address != "10.0.0.254" || hop.Reachability != "unknown" || hop.ActivityBasis != "transit_response" || hop.Prefix != nil {
		t.Fatalf("transit hop misclassified: %+v", hop)
	}

	rec = &recorder{}
	r = enrichRunner(rec)
	r.Echo = hopEcho(map[int]probe.Result{1: {Outcome: "time_exceeded", Responder: "10.0.0.254"}})
	if stop := traceStops(t, r, rec); stop != "silent_hops" || len(rec.ops) != 4 {
		t.Fatalf("stop=%s ops=%d", stop, len(rec.ops))
	}

	rec = &recorder{}
	r = enrichRunner(rec)
	r.Config.TraceBudget = 2
	if stop := traceStops(t, r, rec); stop != "budget_exhausted" || len(rec.ops) != 2 {
		t.Fatalf("stop=%s ops=%d", stop, len(rec.ops))
	}

	rec = &recorder{}
	r = enrichRunner(rec)
	r.Echo = hopEcho(map[int]probe.Result{1: {Outcome: "administratively_prohibited", Responder: "10.0.0.254"}})
	if stop := traceStops(t, r, rec); stop != "terminal_failure" {
		t.Fatalf("stop=%s", stop)
	}
}

func TestSelectTraceTargetsPrefersDistinctPaths(t *testing.T) {
	gw := netip.MustParseAddr("10.0.0.254")
	route := func(iface string) platform.Route { return platform.Route{Interface: iface, Gateway: gw} }
	results := []Result{
		{Target: netip.MustParseAddr("10.0.0.0"), Route: platform.Route{Interface: "eth9"}, Response: true},
		{Target: netip.MustParseAddr("10.0.0.1"), Route: route("eth0"), Response: true},
		{Target: netip.MustParseAddr("10.0.0.2"), Route: route("eth0"), Response: true},
		{Target: netip.MustParseAddr("10.0.0.3"), Route: route("tun0"), Outcome: "timeout"},
		{Target: netip.MustParseAddr("10.0.0.4"), Route: route("tun1"), Response: true},
	}
	got := SelectTraceTargets(results, 3)
	if len(got) != 3 || got[0].Target.String() != "10.0.0.1" || got[1].Target.String() != "10.0.0.4" || got[2].Target.String() != "10.0.0.3" {
		t.Fatalf("%+v", got)
	}
}

func TestAdaptiveTimeoutNeverExceedsConfigured(t *testing.T) {
	r := fakeRunner()
	r.init()
	r.observe("p", probe.Result{Response: true, RTT: 10 * time.Millisecond})
	if got := r.timeout("p"); got != minAdaptiveTimeout {
		t.Fatalf("got %v", got)
	}
	r.Config.Timeout = 100 * time.Millisecond
	if got := r.timeout("p"); got != 100*time.Millisecond {
		t.Fatalf("exceeded configured timeout: %v", got)
	}
	base := r.pathInterval("q")
	for i := 0; i < 30; i++ {
		r.observe("q", probe.Result{Outcome: "timeout"})
	}
	if got := r.pathInterval("q"); got != 8*base {
		t.Fatalf("backoff %v, want %v", got, 8*base)
	}
	r.observe("q", probe.Result{Response: true})
	if r.pathInterval("q") != base {
		t.Fatal("response did not reset backoff")
	}
}

func TestSyntheticSamplesFollowEvidence(t *testing.T) {
	c := candidates(3)
	c[0].Synthetic = true
	out := breadthFirst(c)
	if out[len(out)-1].Address != c[0].Address {
		t.Fatalf("synthetic candidate scheduled before evidence: %+v", out)
	}
}
