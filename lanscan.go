// Package lanscan discovers local network evidence and optionally validates
// scoped endpoints on Linux and Windows. Discovery is passive by default.
package lanscan

import (
	"context"
	"errors"

	"lanscan/internal/app"
	"lanscan/internal/model"
)

// Config controls discovery. Start with DefaultConfig, then override fields.
// Include/Exclude contain CIDRs; Seeds and Inventory are input file paths.
// Output is CLI-only. Journal is optional; set NoJournal=false to enable it.
// Format controls journal configuration metadata; events are always typed.
type Config = app.Config

// Event is a versioned observation, finding update, or lifecycle event.
// A nil Prefix means the subnet mask is unknown. Details holds event-specific
// data; numeric values in library events use json.Number.
type Event = model.Event

// ErrPartial indicates incomplete discovery, for example a required collector
// being unavailable or the runtime/candidate limit being reached. Results and
// previously delivered events remain usable.
var ErrPartial = errors.New("discovery incomplete")

// Result records completion. Finished is nil if discovery failed before emitting
// run_finished. Its Details contains coverage, collector status and budgets.
type Result struct {
	ExitCode int
	Finished *Event
}

// DefaultConfig returns passive defaults with journaling disabled. Each caller
// owns its configuration; do not modify it while Discover is running.
func DefaultConfig() Config {
	c := app.DefaultConfig()
	c.NoJournal = true
	return c
}

// Discover runs the same pipeline as the CLI without invoking a subprocess,
// installing signal handlers, or exiting the process. emit must be non-nil.
// Callbacks are serialized and receive independent event snapshots which may
// be retained. A callback error stops discovery and is returned unchanged.
// Callbacks must return promptly: cancellation cannot interrupt caller code.
// Context cancellation returns ctx.Err(); incomplete runs return ErrPartial.
func Discover(ctx context.Context, cfg Config, emit func(Event) error) (Result, error) {
	var result Result
	if emit == nil {
		return result, errors.New("event handler required")
	}
	code, err := app.Discover(ctx, cfg, func(e model.Event) error {
		// The reducer retains maps and slices from internal events. Copy across the
		// public boundary so consumers cannot alter evidence or race with the engine.
		copied, err := snapshot(e)
		if err != nil {
			return err
		}
		if copied.Type == "run_finished" {
			result.Finished = &copied
		}
		return emit(copied)
	})
	result.ExitCode = code
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if code != 0 {
		return result, ErrPartial
	}
	return result, nil
}
