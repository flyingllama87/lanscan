package app

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"testing"

	"lanscan/internal/model"
)

// writeScaleFixtures writes the acceptance-scale inputs: 100,000 seeded
// addresses and 10,000 inventory prefixes.
func writeScaleFixtures(tb testing.TB, dir string) (seeds, inventory string) {
	tb.Helper()
	seeds, inventory = filepath.Join(dir, "seeds.txt"), filepath.Join(dir, "inventory.csv")
	for _, spec := range []struct {
		path string
		fill func(*bufio.Writer)
	}{
		{seeds, func(w *bufio.Writer) {
			for i := range 100000 {
				fmt.Fprintf(w, "10.%d.%d.%d\n", i/62500, i/250%250, i%250+1)
			}
		}},
		{inventory, func(w *bufio.Writer) {
			w.WriteString("realm,prefix,kind,source,observed_at\n")
			for i := range 10000 {
				fmt.Fprintf(w, "scale,10.%d.%d.0/24,subnet,ipam,\n", i/250, i%250)
			}
		}},
	} {
		f, err := os.Create(spec.path)
		if err != nil {
			tb.Fatal(err)
		}
		w := bufio.NewWriter(f)
		spec.fill(w)
		if err := w.Flush(); err != nil {
			tb.Fatal(err)
		}
		f.Close()
	}
	return seeds, inventory
}

// TestAcceptanceScalePlan plans the resource-target workload: every prefix and
// candidate must be retained, and the live heap must stay well inside the
// 150 MiB resident target.
func TestAcceptanceScalePlan(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	seeds, inventory := writeScaleFixtures(t, t.TempDir())
	c := DefaultConfig()
	c.Plan, c.Intensity, c.Realm = true, 1, "scale"
	c.Include = []string{"10.0.0.0/8"}
	c.Seeds, c.Inventory = seeds, inventory
	// Headroom for this host's own interface, neighbor and hosts-file entries.
	c.Limit = 101000
	var finished model.Event
	var peak uint64
	var events int
	code, err := Discover(context.Background(), c, func(e model.Event) error {
		events++
		if events%20000 == 0 {
			runtime.GC()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			peak = max(peak, m.HeapInuse)
		}
		if e.Type == "run_finished" {
			finished = e
			if path := os.Getenv("LANSCAN_HEAP_PROFILE"); path != "" {
				f, err := os.Create(path)
				if err == nil {
					runtime.GC()
					pprof.WriteHeapProfile(f)
					f.Close()
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	d := finished.Details
	t.Logf("code=%d findings=%v prefixes=%v candidates=%v dropped=%v peak_heap=%.1fMiB", code, d["findings"], d["known_prefixes"], d["candidate_addresses"], d["capacity_dropped"], float64(peak)/(1<<20))
	if code != 0 || d["capacity_dropped"] != 0 || d["candidate_addresses"].(int) < 100000 || d["known_prefixes"].(int) < 10000 {
		t.Fatalf("scale workload truncated: code %d %v", code, d["stop_reason"])
	}
	if peak > 100<<20 {
		t.Errorf("peak live heap %.1f MiB leaves too little headroom under 150 MiB RSS", float64(peak)/(1<<20))
	}
}
