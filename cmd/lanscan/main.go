package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"lanscan/internal/app"
)

// shutdownGrace bounds draining after an interrupt, even when a sink blocks.
const shutdownGrace = 5 * time.Second

// softMemoryLimit keeps the resident set near the 150 MiB target at 100,000
// candidates by collecting earlier instead of letting the heap double. It is a
// soft limit: live data beyond it is never refused. GOMEMLIMIT overrides it.
const softMemoryLimit = 128 << 20

func main() {
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(softMemoryLimit)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := runWithGrace(ctx, shutdownGrace, os.Stderr, os.Exit, func() int {
		return app.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	})
	stop()
	os.Exit(code)
}

// runWithGrace runs fn and, once ctx is canceled, allows it grace to return
// before calling exit(130). Complete journal records are already independently
// readable; the missing run_finished marks the run incomplete.
func runWithGrace(ctx context.Context, grace time.Duration, stderr io.Writer, exit func(int), fn func() int) int {
	finished := make(chan struct{})
	go func() {
		select {
		case <-finished:
			return
		case <-ctx.Done():
		}
		timer := time.NewTimer(grace)
		defer timer.Stop()
		select {
		case <-finished:
		case <-timer.C:
			fmt.Fprintln(stderr, "lanscan: shutdown grace period expired; output sink blocked; exiting")
			exit(130)
		}
	}()
	code := fn()
	close(finished)
	return code
}
