package lanscan_test

import (
	"context"
	"errors"
	"testing"

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
	cfg.Active = true
	_, err = lanscan.Discover(context.Background(), cfg, func(lanscan.Event) error { t.Fatal("callback with invalid scope"); return nil })
	if err == nil {
		t.Fatal("active scope validation bypassed")
	}
	cfg = lanscan.DefaultConfig()
	cfg.Require = []string{"missing"}
	result, err := lanscan.Discover(context.Background(), cfg, func(lanscan.Event) error { return nil })
	if !errors.Is(err, lanscan.ErrPartial) || result.Finished == nil {
		t.Fatalf("partial result lost: %+v %v", result, err)
	}
}
