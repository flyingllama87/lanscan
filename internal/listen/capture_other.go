//go:build !linux

package listen

import (
	"context"
	"errors"
	"time"
)

// Capture is unavailable on this platform.
type Capture struct{ AllMulti []string }

// Frame is one received network-layer payload.
type Frame struct {
	Proto     uint16
	Interface string
	Data      []byte
}

var errUnsupported = errors.New("listening is supported on Linux only")

// Open always fails on this platform.
func Open(string) (*Capture, error) { return nil, errUnsupported }

// Run always fails on this platform.
func (*Capture) Run(context.Context, time.Time, func(Frame) error) error { return errUnsupported }

// Close does nothing on this platform.
func (*Capture) Close() error { return nil }

// Supported reports whether this platform can capture.
const Supported = false
