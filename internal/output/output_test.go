package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
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
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("%s: %v", format, err)
		}
	}
}

func TestTextRendering(t *testing.T) {
	var b bytes.Buffer
	r, err := New(&b, "text", false)
	if err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("10.1.0.0/16")
	events := []model.Event{
		{Type: "finding_upsert", Prefix: &prefix, PrefixBasis: "route", ActivityBasis: "unknown", Reachability: "unknown", Source: "routes"},
		{Type: "finding_upsert", Address: "10.1.2.3", PrefixBasis: "unknown", ActivityBasis: "active_response", Reachability: "endpoint_response", Source: "probe"},
		{Type: "finding_upsert", Name: "evil\x1b[31m.example", Source: "seed\n"},
		{Type: "routing_epoch", RoutingEpoch: 2, Details: map[string]any{"reason": "topology_change", "detection": "notification"}},
		{Type: "resolver_change", Details: map[string]any{"detection": "polling"}},
		{Type: "trace_finished", Address: "10.9.9.9", Outcome: "destination", Details: map[string]any{"hops_sent": 3}},
		{Type: "capability", Source: "icmp4", Outcome: "available"},
		{Type: "run_finished", Details: map[string]any{"stop_reason": "completed", "coverage": map[string]any{"known_prefixes": 4, "prefixes_with_responding_target": 1, "candidate_prefixes_tested": 2, "candidate_prefixes_untested": 1, "observed_addresses": 5}}},
		{Type: "observation", Source: "ignored"},
	}
	for _, e := range events {
		if err := r.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		`"10.1.0.0/16"  basis=route activity=unknown reachability=unknown source="routes"`,
		`"10.1.2.3"  basis=unknown activity=active_response reachability=endpoint_response source="probe"`,
		`"evil\x1b[31m.example"  basis= activity= reachability= source="seed\n"`,
		`routing_epoch 2 reason=topology_change detection=notification`,
		`resolver_change detection=polling`,
		`trace "10.9.9.9" stop=destination hops=3`,
		`capability "icmp4" available`,
		`coverage known_prefixes=4 responding_prefixes=1 candidate_prefixes_tested=2 untested=1 observed_addresses=5 (relative to known evidence, not the organisation)`,
	}
	lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	if len(lines) != len(want)+1 {
		t.Fatalf("got %d lines:\n%s", len(lines), b.String())
	}
	for i, w := range want {
		if lines[i] != w {
			t.Errorf("line %d:\n got %s\nwant %s", i, lines[i], w)
		}
	}
	if !strings.HasPrefix(lines[len(want)], `run_finished {"coverage":`) {
		t.Errorf("run_finished line: %s", lines[len(want)])
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
