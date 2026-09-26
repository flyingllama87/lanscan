package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lanscan/internal/app"
)

// shutdownGrace bounds draining after an interrupt, even when a sink blocks.
const shutdownGrace = 5 * time.Second

var version = "development"

func main() {
	if version != "" {
		app.Version = version
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	finished := make(chan struct{})
	go func() {
		select {
		case <-finished:
			return
		case <-ctx.Done():
		}
		select {
		case <-finished:
		case <-time.After(shutdownGrace):
			// Complete journal records are already independently readable;
			// the missing run_finished marks this run incomplete.
			fmt.Fprintln(os.Stderr, "lanscan: shutdown grace period expired; output sink blocked; exiting")
			os.Exit(130)
		}
	}()
	code := app.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	close(finished)
	stop()
	os.Exit(code)
}
