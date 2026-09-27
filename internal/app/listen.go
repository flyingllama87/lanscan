package app

import (
	"context"
	"fmt"
	"time"

	"lanscan/internal/listen"
	"lanscan/internal/model"
)

// maxListenSightings bounds the distinct observations one listen records.
const maxListenSightings = 10000

// listenCapture and listenSupported are replaced by tests.
var (
	listenCapture   = func(iface string) (capture, error) { return listen.Open(iface) }
	listenSupported = listen.Supported
)

type capture interface {
	Run(context.Context, time.Time, func(listen.Frame) error) error
	Close() error
}

// listenFor records evidence from broadcast and multicast traffic for
// c.Listen. It sends nothing; an unavailable capture is an error, not a
// fallback.
func (s *stream) listenFor(ctx context.Context, c config) error {
	capt, err := listenCapture(c.Interface)
	if err != nil {
		return fmt.Errorf("--listen: %w", err)
	}
	defer capt.Close()
	details := map[string]any{"duration_ns": int64(c.Listen), "backend": "af_packet", "transmits": false}
	if lc, ok := capt.(*listen.Capture); ok {
		details["all_multicast"] = lc.AllMulti
	}
	if c.Interface != "" {
		details["interface"] = c.Interface
	}
	if err := s.emit(model.Event{Type: "capability", Source: "listen", Outcome: "available", ObservedAt: model.Now(), Details: details}); err != nil {
		return err
	}
	seen := map[string]bool{}
	frames := map[string]int{}
	dropped := 0
	runErr := capt.Run(ctx, time.Now().Add(c.Listen), func(f listen.Frame) error {
		for _, sight := range listen.Parse(f.Proto, f.Data, c.NoIPv6) {
			frames[sight.Protocol]++
			key := sight.Protocol + "|" + sight.Role + "|" + sight.Address.String() + "|" + sight.Prefix.String() + "|" + f.Interface
			if seen[key] {
				continue
			}
			if len(seen) >= maxListenSightings {
				dropped++
				continue
			}
			seen[key] = true
			if err := s.emit(sightingEvent(sight, f.Interface)); err != nil {
				return err
			}
		}
		return nil
	})
	outcome := "complete"
	status := map[string]any{"sightings": len(seen), "sightings_by_protocol": frames}
	if dropped > 0 {
		status["dropped_sightings"] = dropped
	}
	if runErr != nil {
		outcome = "failed"
		status["error"] = runErr.Error()
	}
	if err := s.emit(model.Event{Type: "collector_status", Source: "listen", Outcome: outcome, ObservedAt: model.Now(), Details: status}); err != nil {
		return err
	}
	if runErr != nil && ctx.Err() == nil {
		return fmt.Errorf("--listen: %w", runErr)
	}
	return nil
}

func sightingEvent(sight listen.Sighting, iface string) model.Event {
	e := model.Event{Type: "observation", Source: "listen", Protocol: sight.Protocol, ActivityBasis: "passive_capture", InterfaceID: iface, ObservedAt: model.Now(), Details: map[string]any{}}
	for k, v := range sight.Details {
		e.Details[k] = v
	}
	if sight.Role != "" {
		e.Details["role"] = sight.Role
	}
	if sight.Address.IsValid() {
		e.Address = sight.Address.String()
		if sight.Address.Is6() && sight.Address.IsLinkLocalUnicast() {
			e.Zone = iface
		}
	}
	if sight.Prefix.IsValid() {
		p := sight.Prefix
		e.Prefix = &p
		e.PrefixBasis = sight.PrefixBasis
	}
	return e
}
