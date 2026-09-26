package app

import (
	"context"
	"sync"
	"time"

	"lanscan/internal/journal"
	"lanscan/internal/model"
)

// Runtime is leased durably ahead of work. A clean finish commits measured runtime;
// after a crash, the outstanding lease is conservatively charged. Downtime never
// accrues. Renewal and operation reservation share the writer lock.
func (s *stream) ensureRuntimeLocked(lookahead time.Duration) error {
	if s.segmentStart.IsZero() {
		return nil
	}
	elapsed := s.baseElapsed + time.Since(s.segmentStart)
	if elapsed >= s.runtimeLimit {
		return context.DeadlineExceeded
	}
	required := elapsed + lookahead
	if required < elapsed+time.Second {
		required = elapsed + time.Second
	}
	if required > s.runtimeLimit {
		required = s.runtimeLimit
	}
	if s.runtimeLease >= required {
		return nil
	}
	reserve := required + 2*time.Second
	if reserve > s.runtimeLimit {
		reserve = s.runtimeLimit
	}
	if _, err := s.writeLocked(model.Event{Type: "runtime_reserved", ObservedAt: model.Now(), Details: map[string]any{"total_reserved_ns": int64(reserve), "total_elapsed_ns": int64(elapsed)}}); err != nil {
		return err
	}
	if s.journal != nil {
		if err := s.journal.Sync(); err != nil {
			s.err = err
			return err
		}
	}
	s.runtimeLease = reserve
	if s.baseElapsed+time.Since(s.segmentStart) >= s.runtimeLimit {
		return context.DeadlineExceeded
	}
	return nil
}

func (s *stream) heartbeat(ctx context.Context) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	// Establish the first lease synchronously before collectors or probes begin.
	s.mu.Lock()
	err := s.ensureRuntimeLocked(0)
	s.mu.Unlock()
	if err != nil {
		s.cancel()
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.mu.Lock()
				err := s.ensureRuntimeLocked(0)
				s.mu.Unlock()
				if err != nil {
					s.cancel()
					return
				}
			}
		}
	}()
	return func() { once.Do(func() { close(stop); <-done }) }
}

func (s *stream) checkpoint(c config) error {
	if s.journal == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, err := hashValue(c)
	if err != nil {
		return err
	}
	return s.journal.Checkpoint(journal.Checkpoint{RunID: s.run, Seq: s.seq, ConfigHash: hash, Operations: s.spent, ElapsedNS: int64(s.baseElapsed + time.Since(s.segmentStart)), RoutingEpoch: s.epoch})
}
