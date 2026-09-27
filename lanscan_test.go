package lanscan_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"lanscan"
)

func TestPassiveLibrary(t *testing.T) {
	cfg := lanscan.DefaultConfig()
	cfg.Include = []string{"10.0.0.0/8"}
	cfg.Realm = "library-test"
	var events []lanscan.Event
	result, err := lanscan.Discover(context.Background(), cfg, func(e lanscan.Event) error {
		if e.Type == "operation_reserved" {
			t.Error("passive discovery reserved a network operation")
		}
		if err := e.Validate(); err != nil {
			t.Error(err)
		}
		events = append(events, e)
		// Mutation must not corrupt internal configuration or findings.
		if e.Details != nil {
			e.Details["consumer_annotation"] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Finished == nil || len(events) < 2 || result.ExitCode != 0 {
		t.Fatalf("incomplete result: %+v", result)
	}
}

func TestLibraryErrors(t *testing.T) {
	sentinel := errors.New("sink stopped")
	_, err := lanscan.Discover(context.Background(), lanscan.DefaultConfig(), func(lanscan.Event) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("sink error lost: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = lanscan.Discover(ctx, lanscan.DefaultConfig(), func(lanscan.Event) error { t.Fatal("callback after pre-cancellation"); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	cfg := lanscan.DefaultConfig()
	cfg.Intensity = lanscan.MaxIntensity + 1
	_, err = lanscan.Discover(context.Background(), cfg, func(lanscan.Event) error { t.Fatal("callback with invalid intensity"); return nil })
	if err == nil {
		t.Fatal("intensity validation bypassed")
	}
	cfg = lanscan.DefaultConfig()
	cfg.Require = []string{"missing"}
	result, err := lanscan.Discover(context.Background(), cfg, func(lanscan.Event) error { return nil })
	if !errors.Is(err, lanscan.ErrPartial) || result.Finished == nil {
		t.Fatalf("partial result lost: %+v %v", result, err)
	}
}

// planConfig runs a library plan and returns the resolved configuration from
// run_started and the plan event.
func planConfig(t *testing.T, cfg lanscan.Config) (map[string]any, lanscan.Event) {
	t.Helper()
	cfg.Plan = true
	cfg.Realm = "library-plan"
	cfg.Include = []string{"192.0.2.0/24"}
	var started map[string]any
	var plan lanscan.Event
	_, err := lanscan.Discover(context.Background(), cfg, func(e lanscan.Event) error {
		switch e.Type {
		case "run_started":
			started, _ = e.Details["config"].(map[string]any)
		case "plan":
			plan = e
		case "operation_reserved":
			t.Error("plan reserved a network operation")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return started, plan
}

func TestLibraryIntensityPresetAndOverride(t *testing.T) {
	cfg := lanscan.DefaultConfig()
	cfg.Intensity = 3
	cfg.NoIPv6 = true
	started, plan := planConfig(t, cfg)
	tuning, _ := started["tuning"].(map[string]any)
	if fmt.Sprintf("%v %v %v %v", started["intensity"], started["no_ipv6"], tuning["neighbours"], tuning["trace"]) != "3 true 2 16" {
		t.Fatalf("preset not applied: %v", started)
	}
	if fmt.Sprint(plan.Details["intensity"]) != "3" {
		t.Fatalf("plan: %v", plan.Details)
	}

	cfg = lanscan.DefaultConfig()
	cfg.Intensity = 2
	cfg.Tuning = lanscan.Preset(2)
	cfg.Tuning.Trace = 0
	started, _ = planConfig(t, cfg)
	tuning, _ = started["tuning"].(map[string]any)
	if fmt.Sprintf("%v %v", tuning["trace"], tuning["sample_per_prefix"]) != "0 2" {
		t.Fatalf("override lost: %v", tuning)
	}
}

func TestLibraryListenFailsWithoutCapture(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can capture")
	}
	cfg := lanscan.DefaultConfig()
	cfg.Listen = time.Second
	_, err := lanscan.Discover(context.Background(), cfg, func(lanscan.Event) error {
		t.Fatal("event emitted although capture is impossible")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("got %v", err)
	}
}
