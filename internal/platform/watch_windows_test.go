package platform

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// TestWatchTopologyNotifies adds and removes a loopback route (administrator
// only) and expects an IP Helper notification for each change.
func TestWatchTopologyNotifies(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	notify, err := WatchTopology(ctx)
	if err != nil {
		t.Fatal(err)
	}
	route := func(verb string) error {
		return exec.Command("netsh", "interface", "ipv4", verb, "route", "203.0.113.0/24", "interface=1", "store=active").Run()
	}
	if err := route("add"); err != nil {
		cancel()
		t.Skipf("cannot change routes (needs administrator): %v", err)
	}
	defer route("delete")
	for _, step := range []string{"add", "delete"} {
		if step == "delete" {
			if err := route("delete"); err != nil {
				t.Fatal(err)
			}
		}
		select {
		case <-notify:
		case <-time.After(5 * time.Second):
			t.Fatalf("no notification after route %s", step)
		}
		// Drain the burst one change produces before the next step.
		for drained := false; !drained; {
			select {
			case <-notify:
			case <-time.After(300 * time.Millisecond):
				drained = true
			}
		}
	}
	cancel()
	select {
	case _, ok := <-notify:
		for ok {
			_, ok = <-notify
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch channel not closed after cancellation")
	}
}
