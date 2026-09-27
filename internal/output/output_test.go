package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"lanscan/internal/model"
)

func TestCSVStreamingAndFormulaNeutralization(t *testing.T) {
	var b bytes.Buffer
	r, err := New(&b, "csv", false)
	if err != nil {
		t.Fatal(err)
	}
	e := model.Event{Type: "finding_upsert", EntityID: "=DANGER()", EvidenceIDs: []string{"r:1", "r:2"}}
	if err = r.Write(e); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(b.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1][3] != "'=DANGER()" || rows[1][17] != `["r:1","r:2"]` {
		t.Fatalf("%v", rows)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestOutputFailurePropagates(t *testing.T) {
	for _, format := range []string{"jsonl", "csv", "text"} {
		r, err := New(brokenWriter{}, format, false)
		if err == nil {
			err = r.Write(model.Event{Type: "finding_upsert"})
		}
		if err == nil {
			// Text writes its summary when the run finishes.
			err = r.Write(model.Event{Type: "run_finished"})
		}
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("%s: %v", format, err)
		}
	}
}

func pfx(s string) *netip.Prefix { p := netip.MustParsePrefix(s); return &p }

// activeRun is a small intensity-1 run with the noise a real host produces.
func activeRun() []model.Event {
	return []model.Event{
		{Type: "run_started", Details: map[string]any{"version": "9.9.9", "config": map[string]any{"intensity": 1, "tuning": map[string]any{"tcp_port": 443}}}},
		{Type: "observation", Source: "interfaces", Prefix: pfx("192.168.1.0/24"), Address: "192.168.1.50", InterfaceID: "eth0"},
		{Type: "observation", Source: "interfaces", Prefix: pfx("127.0.0.0/8"), Address: "127.0.0.1", InterfaceID: "lo"},
		{Type: "observation", Source: "interfaces", Prefix: pfx("fe80::/64"), Address: "fe80::1", InterfaceID: "eth0"},
		{Type: "observation", Source: "routes", Prefix: pfx("0.0.0.0/0"), InterfaceID: "eth0", Details: map[string]any{"route_type": "unicast", "gateway": "192.168.1.1"}},
		{Type: "observation", Source: "routes", Prefix: pfx("10.20.0.0/16"), InterfaceID: "tun0", Details: map[string]any{"route_type": "unicast", "gateway": "10.8.0.1"}},
		{Type: "observation", Source: "routes", Prefix: pfx("192.168.1.50/32"), InterfaceID: "eth0", Details: map[string]any{"route_type": "local"}},
		{Type: "observation", Source: "route_gateway", Address: "192.168.1.1", InterfaceID: "eth0"},
		{Type: "observation", Source: "neighbors", Address: "192.168.1.1", Details: map[string]any{"state_name": "reachable", "mac": "aa:bb:cc:00:00:01"}},
		{Type: "observation", Source: "neighbors", Address: "192.168.1.7", Details: map[string]any{"state_name": "stale", "mac": "aa:bb:cc:00:00:07"}},
		{Type: "observation", Source: "neighbors", Address: "192.168.1.9", Details: map[string]any{"state_name": "failed"}},
		{Type: "observation", Source: "neighbors", Address: "224.0.0.251", Details: map[string]any{"state_name": "noarp"}},
		{Type: "observation", Source: "neighbors", Address: "192.168.1.255", Details: map[string]any{"state_name": "noarp"}},
		{Type: "observation", Source: "hosts", Address: "192.168.1.7", Name: "printer"},
		{Type: "observation", Source: "hosts", Address: "fe00::", Name: "ip6-localnet"},
		{Type: "observation", Source: "resolver_config", Address: "127.0.0.53"},
		{Type: "observation", Source: "resolver_config", Address: "192.168.1.1"},
		{Type: "collector_status", Source: "dns_cache", Outcome: "denied", Details: map[string]any{"error": "Permission denied"}},
		{Type: "capability", Source: "icmp4", Outcome: "unavailable", Details: map[string]any{"error": "socket: operation not permitted"}},
		{Type: "observation", Source: "probe", Address: "192.168.1.1", Protocol: "tcp", Port: 443, Outcome: "refused", Reachability: "endpoint_response", Details: map[string]any{"rtt_ns": 1200000}},
		{Type: "observation", Source: "probe", Address: "192.168.1.7", Protocol: "tcp", Port: 443, Outcome: "timeout", Reachability: "unknown"},
		{Type: "observation", Source: "dns_reverse", Address: "192.168.1.1", Name: "evil\x1b[31m.example."},
		{Type: "observation", Source: "trace", Address: "10.8.0.1", Details: map[string]any{"trace_target": "10.20.0.5", "hop_limit": 1}},
		{Type: "observation", Source: "trace", Address: "10.20.0.5", Outcome: "echo_reply", Details: map[string]any{"trace_target": "10.20.0.5", "hop_limit": 2}},
		{Type: "trace_finished", Address: "10.20.0.5", Outcome: "destination_reached"},
		{Type: "run_finished", Outcome: "operation_budget_exhausted", Details: map[string]any{"elapsed_ms": 1500, "operations": 3}},
	}
}

func render(t *testing.T, events []model.Event, deferred bool) string {
	t.Helper()
	var b bytes.Buffer
	r, err := New(&b, "text", false)
	if err != nil {
		t.Fatal(err)
	}
	if deferred {
		r.Deferred()
	}
	for _, e := range events {
		if err := r.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestTextSummary(t *testing.T) {
	out := render(t, activeRun(), false)
	for _, want := range []string{
		"lanscan 9.9.9 · intensity 1 · 1.5s",
		"SUBNETS (2)",
		"HOSTS (4)",
		`evil\x1b[31m.example`,
		"DNS, gateway, neighbour cache",
		"responded tcp/443 refused 1.2ms",
		"router on a traced path",
		"printer",
		"responded icmp (trace)",
		"silent",
		"10.20.0.5: 10.8.0.1 → 10.20.0.5",
		"Default route: 192.168.1.1 on eth0",
		"DNS servers: 127.0.0.53 (local resolver), 192.168.1.1",
		"DNS cache: not readable without more permission",
		"ICMPv4 echo unavailable (socket: operation not permitted); used only a TCP connect to port 443",
		"Result: stopped early: the operation budget ran out (raise --max-operations).",
		"3 network operations; 2 hosts responded.",
		"For more coverage: lanscan -i 2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// Noise stays out of the summary: loopback, link-local, multicast, the
	// subnet broadcast, failed neighbours, this host and its /32 route.
	for _, noise := range []string{"127.0.0.1", "fe80::", "224.0.0.251", "192.168.1.255", "192.168.1.9", "192.168.1.50/32", "fe00::", "\x1b"} {
		if strings.Contains(out, noise) {
			t.Errorf("summary shows %q:\n%s", noise, out)
		}
	}
	for _, row := range []string{`192\.168\.1\.0/24 +eth0 +192\.168\.1\.50 +192\.168\.1\.1 +2 \(1\) +interface`, `10\.20\.0\.0/16 +tun0 +- +10\.8\.0\.1 +1 \(1\) +route`} {
		if !regexp.MustCompile(row).MatchString(out) {
			t.Errorf("no row %s in:\n%s", row, out)
		}
	}
	if strings.Count(out, "192.168.1.50") != 1 {
		t.Errorf("this host listed as a host:\n%s", out)
	}
}

func TestTextSummaryPassiveAndPlan(t *testing.T) {
	passive := []model.Event{
		{Type: "run_started", Details: map[string]any{"config": map[string]any{"intensity": 0}}},
		{Type: "observation", Source: "interfaces", Prefix: pfx("10.0.0.0/24"), Address: "10.0.0.2", InterfaceID: "eth0"},
		{Type: "run_finished", Outcome: "completed"},
	}
	out := render(t, passive, false)
	if !strings.Contains(out, "passive (nothing sent)") || !strings.Contains(out, "Next: lanscan -i 1") || !strings.Contains(out, "HOSTS (0)\n  none found") {
		t.Fatal(out)
	}
	plan := []model.Event{
		{Type: "run_started", Details: map[string]any{"config": map[string]any{"intensity": 3, "plan": true}}},
		{Type: "plan", Details: map[string]any{"candidates": 10, "synthetic_samples": 6, "neighbour_guesses": 4, "trace_destinations": 16, "max_operations": 10000, "targets": []any{map[string]any{"address": "10.0.1.1", "kind": "guess: neighbour of 10.0.0.0/24"}}}},
		{Type: "run_finished", Outcome: "completed"},
	}
	out = render(t, plan, false)
	for _, want := range []string{"intensity 3 plan (nothing sent)", "would probe 10 addresses (4 known, 2 guessed in known subnets, 4 in neighbouring subnets)", "WOULD PROBE (10)", "10.0.1.1", "guess: neighbour of 10.0.0.0/24", "… 9 more"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

func TestDeferredSummaryPrintsOnceAtClose(t *testing.T) {
	events := append(activeRun(), activeRun()...)
	out := render(t, events, true)
	if strings.Count(out, "SUBNETS") != 1 {
		t.Fatal(out)
	}
	// A journal without run_finished still gets a summary at Close.
	out = render(t, activeRun()[:5], false)
	if !strings.Contains(out, "SUBNETS (1)") {
		t.Fatal(out)
	}
}

func TestJSONLAndCSVFiltering(t *testing.T) {
	var b bytes.Buffer
	r, err := New(&b, "jsonl", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Write(model.Event{Type: "observation", Source: "routes"}); err != nil {
		t.Fatal(err)
	}
	var e model.Event
	if err := json.Unmarshal(b.Bytes(), &e); err != nil || e.Source != "routes" || !strings.HasSuffix(b.String(), "\n") {
		t.Fatalf("%q %v", b.String(), err)
	}
	b.Reset()
	r, err = New(&b, "csv", true)
	if err != nil {
		t.Fatal(err)
	}
	header := b.Len()
	if err := r.Write(model.Event{Type: "observation"}); err != nil || b.Len() != header {
		t.Fatalf("csv wrote a non-finding: %q %v", b.String(), err)
	}
	observed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := r.Write(model.Event{Type: "finding_upsert", EntityID: "=raw", Port: 443, ObservedAt: &observed}); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(b.String())).ReadAll()
	if err != nil || len(rows) != 2 || rows[1][3] != "=raw" || rows[1][15] != "443" || rows[1][8] != "2026-01-02T03:04:05Z" {
		t.Fatalf("%v %v", rows, err)
	}
	if _, err := New(&b, "xml", false); err == nil {
		t.Fatal("unknown format accepted")
	}
}
