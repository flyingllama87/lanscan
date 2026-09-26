package platform

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"lanscan/internal/model"
)

func collectAll(t *testing.T, fn func(context.Context, Emit) error) (map[string]string, []model.Event) {
	t.Helper()
	var mu sync.Mutex
	statuses := map[string]string{}
	var events []model.Event
	err := fn(context.Background(), func(e model.Event) error {
		mu.Lock()
		defer mu.Unlock()
		if e.Type == "collector_status" {
			statuses[e.Source] = e.Outcome
		} else {
			events = append(events, e)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return statuses, events
}

// Validates native structure layouts against the running OS.
func TestNativeRouteAndNeighborTables(t *testing.T) {
	statuses, events := collectAll(t, Network)
	if statuses["routes"] != "complete" || statuses["neighbors"] != "complete" {
		t.Fatalf("statuses %v", statuses)
	}
	loopback := false
	for _, e := range events {
		if e.Source == "routes" && e.Prefix != nil && e.Prefix.Contains(netip.MustParseAddr("127.0.0.1")) {
			loopback = true
		}
	}
	if !loopback {
		t.Fatal("no route covers 127.0.0.1; native row layout is likely wrong")
	}
}

func TestNativeBestRoute(t *testing.T) {
	r, err := LookupRoute(netip.MustParseAddr("127.0.0.1"), netip.Addr{}, "")
	if err != nil || !r.Source.IsLoopback() {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestNativeResolverConfig(t *testing.T) {
	statuses, _ := collectAll(t, Resolvers)
	if statuses["resolver_config"] != "complete" {
		t.Fatalf("%v", statuses)
	}
	statuses, _ = collectAll(t, DNSCache)
	if s := statuses["dns_cache"]; s != "complete" && s != "partial" && s != "denied" && s != "unsupported" && s != "timed_out" {
		t.Fatalf("dns_cache %q", s)
	}
}
