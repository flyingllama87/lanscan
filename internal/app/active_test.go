package app

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"lanscan/internal/journal"
	"lanscan/internal/model"
	"lanscan/internal/platform"
	"lanscan/internal/probe"
)

var (
	fakeSource  = netip.MustParseAddr("192.0.2.1")
	fakeGateway = netip.MustParseAddr("192.0.2.254")
	echoHost    = netip.MustParseAddr("198.51.100.10")
	refusedHost = netip.MustParseAddr("198.51.100.11")
	dnsHost     = netip.MustParseAddr("198.51.100.12")
	silentHost  = netip.MustParseAddr("198.51.100.13")
)

type fakeResolver struct{}

func (fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if host == "seed.corp.example." {
		return []netip.Addr{dnsHost}, nil
	}
	return nil, errors.New("no such host")
}

func (fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if addr == echoHost.String() {
		return []string{"echo.corp.example."}, nil
	}
	return nil, errors.New("no such host")
}

// fakeNetwork replaces every network primitive for the test's duration. Echo
// answers from echoHost and dnsHost; hop-limited echoes below two hops expire
// at the gateway; TCP is refused by refusedHost; everything else is silent.
func fakeNetwork(t *testing.T) {
	saved := probes
	t.Cleanup(func() { probes = saved })
	probes.capability = func(bool) error { return nil }
	probes.lookup = func(target, _ netip.Addr, _ string) (platform.Route, error) {
		return platform.Route{Source: fakeSource, Interface: "test0", Gateway: fakeGateway}, nil
	}
	probes.echo = func(_ context.Context, target netip.Addr, _ platform.Route, hops int) probe.Result {
		r := probe.Result{Backend: "fake_echo", RTT: time.Millisecond}
		switch {
		case hops > 0 && hops < 2:
			r.Outcome, r.Responder, r.ICMPType = "time_exceeded", fakeGateway.String(), 11
		case target == echoHost || target == dnsHost:
			r.Outcome, r.Response, r.Responder = "echo_reply", true, target.String()
		default:
			r.Outcome = "timeout"
		}
		return r
	}
	probes.echoFlow = func(ctx context.Context, target netip.Addr, route platform.Route, hops int, _ probe.Flow) probe.Result {
		r := probes.echo(ctx, target, route, hops)
		r.Flow = probe.FlowParis
		return r
	}
	probes.tcp = func(_ context.Context, target netip.Addr, _ platform.Route, _ int) probe.Result {
		r := probe.Result{Backend: "fake_tcp", RTT: time.Millisecond, Outcome: "timeout"}
		if target == refusedHost {
			r.Outcome, r.Response, r.Responder = "refused", true, target.String()
		}
		return r
	}
	probes.resolver = fakeResolver{}
}

func activeRun(t *testing.T, extra ...string) (int, string, []model.Event) {
	t.Helper()
	dir := t.TempDir()
	seeds := filepath.Join(dir, "seeds.txt")
	lines := []string{echoHost.String(), refusedHost.String(), silentHost.String(), "seed.corp.example"}
	if err := os.WriteFile(seeds, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "run.jsonl")
	args := append([]string{"discover", "--active", "--include", "198.51.100.0/24", "--seeds", seeds, "--dns-suffix", "corp.example",
		"--journal", path, "--format", "jsonl", "--realm", "lab", "--rate", "1000", "--timeout", "100ms", "--refresh-interval", "0"}, extra...)
	var out, stderr bytes.Buffer
	code := Run(context.Background(), args, &out, &stderr)
	var events []model.Event
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Replay(bytes.NewReader(data), func(e model.Event) error { events = append(events, e); return nil }); err != nil {
		t.Fatal(err)
	}
	return code, stderr.String(), events
}

func TestActivePipelineReservesBeforeEveryOperation(t *testing.T) {
	fakeNetwork(t)
	code, stderr, events := activeRun(t, "--trace", "1")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	reserved := map[string]bool{}
	reachable := map[string]string{}
	var reservations, traces int
	var ptr, forward bool
	var finished *model.Event
	for i, e := range events {
		id, _ := e.Details["operation_id"].(string)
		switch {
		case e.Type == "operation_reserved":
			reservations++
			reserved[id] = true
		case e.Type == "observation" && (e.Source == "probe" || e.Source == "trace" || e.Source == "dns_forward" || e.Source == "dns_reverse") && id != "":
			if !reserved[id] {
				t.Errorf("%s observation %s has no earlier reservation", e.Source, id)
			}
		case e.Type == "finding_upsert" && e.Prefix == nil && e.Address != "":
			// Each address has several findings (seed, echo, TCP); keep any response.
			if reachable[e.Address] != "endpoint_response" {
				reachable[e.Address] = e.Reachability
			}
		case e.Type == "trace_finished":
			traces++
		case e.Type == "run_finished":
			finished = &events[i]
		}
		if e.Source == "dns_reverse" && e.Name == "echo.corp.example" {
			ptr = true
		}
		if e.Source == "dns_forward" && e.Address == dnsHost.String() {
			forward = true
		}
	}
	for addr, want := range map[netip.Addr]string{echoHost: "endpoint_response", refusedHost: "endpoint_response", dnsHost: "endpoint_response", silentHost: "unknown"} {
		if reachable[addr.String()] != want {
			t.Errorf("%s reachability %q, want %q", addr, reachable[addr.String()], want)
		}
	}
	if !forward || !ptr || traces != 1 {
		t.Errorf("forward=%v ptr=%v traces=%d", forward, ptr, traces)
	}
	if finished == nil || finished.Outcome != "completed" {
		t.Fatalf("run_finished: %+v", finished)
	}
	if ops, _ := finished.Details["operations"].(interface{ String() string }); ops == nil || ops.String() != strconv.Itoa(reservations) {
		t.Errorf("run_finished operations %v, journal has %d reservations", finished.Details["operations"], reservations)
	}
}

func TestActivePipelineStopsAtOperationBudget(t *testing.T) {
	fakeNetwork(t)
	code, _, events := activeRun(t, "--max-operations", "1", "--dns-budget", "0")
	reservations := 0
	var reason string
	for _, e := range events {
		if e.Type == "operation_reserved" {
			reservations++
		}
		if e.Type == "run_finished" {
			reason = e.Outcome
		}
	}
	if code != 3 || reason != "operation_budget_exhausted" || reservations != 1 {
		t.Fatalf("code %d reason %q reservations %d", code, reason, reservations)
	}
}
