package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"lanscan/internal/journal"
	"lanscan/internal/model"
)

func TestPlanReportsDNSTraceAndSamplingWithoutTraffic(t *testing.T) {
	dir := t.TempDir()
	seeds := filepath.Join(dir, "seeds.txt")
	inventory := filepath.Join(dir, "inventory.csv")
	if err := os.WriteFile(seeds, []byte("app.corp.example\nother.test\n192.0.2.7\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inventory, []byte("realm,prefix,kind,source,observed_at\nlab,198.51.100.0/24,subnet,ipam,\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	code := Run(context.Background(), []string{"discover", "--no-journal", "--format", "jsonl", "--realm", "lab", "--active", "--plan", "--include", "198.51.100.0/24", "--include", "192.0.2.0/24", "--seeds", seeds, "--inventory", inventory, "--dns-suffix", "corp.example", "--sample-per-prefix", "2", "--trace", "2"}, &out, &stderr)
	if code != 0 {
		t.Fatalf("%d %s", code, stderr.String())
	}
	var plan model.Event
	_, err := journal.Replay(bytes.NewReader(out.Bytes()), func(e model.Event) error {
		switch e.Type {
		case "plan":
			plan = e
		case "operation_reserved", "capability":
			t.Errorf("plan performed active work: %+v", e)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	num := func(k string) int64 {
		n, err := plan.Details[k].(json.Number).Int64()
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		return n
	}
	if num("dns_names_eligible") != 1 || num("unresolved_names") != 2 || num("synthetic_samples") != 2 || num("trace_destinations") != 2 || num("network_operations") != 0 {
		t.Fatalf("%+v", plan.Details)
	}
}

func TestEnrichmentFlagValidation(t *testing.T) {
	for _, args := range [][]string{
		{"--resolver", "not-an-ip"},
		{"--resolver", "224.0.0.251"},
		{"--dns-suffix", "bad suffix"},
		{"--sample-per-prefix", "4"},
		{"--trace", "1", "--trace-hops", "0"},
		{"--dns-budget", "-1"},
		{"--refresh-interval", "10ms"},
	} {
		var out, stderr bytes.Buffer
		if code := Run(context.Background(), append([]string{"discover", "--no-journal"}, args...), &out, &stderr); code != 2 {
			t.Errorf("%v: code %d", args, code)
		}
	}
}

// Journals written before enrichment settings existed must still verify.
func TestConfigHashCompatibleWithEarlierSchema(t *testing.T) {
	c := defaults()
	c.DNSBudget, c.TraceHops, c.TraceBudget, c.Refresh = 0, 0, 0, 0
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"dns_suffix", "resolver", "dns_budget", "trace", "trace_hops", "trace_budget", "sample_per_prefix", "refresh_interval"} {
		if _, ok := fields[k]; ok {
			t.Fatalf("zero-valued %s changes earlier configuration hashes", k)
		}
	}
	var decoded config
	if err := decodeValue(fields, &decoded); err != nil {
		t.Fatal(err)
	}
	h1, _ := hashValue(c)
	h2, _ := hashValue(decoded)
	if h1 != h2 {
		t.Fatal("hash changed across decode")
	}
}

func TestRequireCapabilityAcceptsCollectors(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"discover", "--no-journal", "--require-capability", "interfaces"}, &out, &stderr); code != 0 {
		t.Fatalf("%d %s", code, stderr.String())
	}
}
