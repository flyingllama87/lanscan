package app

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	code := Run(context.Background(), []string{"discover", "--no-journal", "--format", "jsonl", "--realm", "lab", "--intensity", "1", "--plan", "--include", "198.51.100.0/24", "--include", "192.0.2.0/24", "--seeds", seeds, "--inventory", inventory, "--dns-suffix", "corp.example", "--sample-per-prefix", "2", "--trace", "2"}, &out, &stderr)
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
		{"--intensity", "1", "--sample-per-prefix", "4"},
		{"--intensity", "1", "--trace", "1", "--trace-hops", "0"},
		{"--intensity", "1", "--dns-budget", "-1"},
		{"--intensity", "1", "--refresh-interval", "10ms"},
		{"--intensity", "3", "--neighbours", "9"},
		{"--intensity", "4"},
		{"--intensity", "-1"},
		{"--trace", "2"},
		{"--listen", "-1s"},
		{"--listen", "5m", "--duration", "1m"},
	} {
		var out, stderr bytes.Buffer
		if code := Run(context.Background(), append([]string{"discover", "--no-journal"}, args...), &out, &stderr); code != 2 {
			t.Errorf("%v: code %d", args, code)
		}
	}
}

func TestIntensityPresetsAndOverrides(t *testing.T) {
	c, err := parseConfig([]string{"--intensity", "2", "--trace", "0"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	want := Preset(2)
	want.Trace = 0
	if c.Tuning != want {
		t.Fatalf("%+v", c.Tuning)
	}
	if c, err = parseConfig(nil, io.Discard); err != nil || c.Tuning != (Tuning{}) || c.active() {
		t.Fatalf("passive default: %+v %v", c, err)
	}
	if c, _ = parseConfig([]string{"--intensity=3"}, io.Discard); c.Neighbours == 0 || !c.active() {
		t.Fatalf("%+v", c.Tuning)
	}
	// A configuration file overrides the preset field by field; flags win.
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(`{"intensity":2,"tuning":{"retry":0}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = parseConfig([]string{"--config", path, "--rate", "7"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	want = Preset(2)
	want.Retry, want.Rate = 0, 7
	if c.Intensity != 2 || c.Tuning != want {
		t.Fatalf("%+v", c)
	}
	// Library callers may set only the intensity.
	lib := DefaultConfig()
	lib.Intensity = 2
	if lib.resolved().Tuning != Preset(2) {
		t.Fatal("zero tuning not filled from preset")
	}
	h1, _ := hashValue(c)
	var decoded config
	if err := decodeValue(c, &decoded); err != nil {
		t.Fatal(err)
	}
	if h2, _ := hashValue(decoded); h1 != h2 {
		t.Fatal("configuration hash changed across decode")
	}
}

func TestRequireCapabilityAcceptsCollectors(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"discover", "--no-journal", "--require-capability", "interfaces"}, &out, &stderr); code != 0 {
		t.Fatalf("%d %s", code, stderr.String())
	}
}

func TestHelpListsEveryFlagOnce(t *testing.T) {
	var out bytes.Buffer
	fs := discoverFlags(&config{}, &out)
	fs.Usage()
	fs.VisitAll(func(f *flag.Flag) {
		if n := strings.Count(out.String(), "  --"+f.Name+"\n"); n != 1 {
			t.Errorf("--%s listed %d times", f.Name, n)
		}
	})
}
