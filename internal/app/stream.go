package app

import (
	"context"
	"fmt"
	"sync"
	"time"

	"lanscan/internal/discover"
	"lanscan/internal/journal"
	"lanscan/internal/model"
)

type stream struct {
	mu                  sync.Mutex
	run, realm, vantage string
	seq                 uint64
	epoch               uint64
	spent               int
	segmentStart        time.Time
	baseElapsed         time.Duration
	runtimeLimit        time.Duration
	operationTimeout    time.Duration
	runtimeLease        time.Duration
	cancel              context.CancelFunc
	journal             *journal.Writer
	renderer            interface{ Write(model.Event) error }
	reducer             *discover.Reducer
	statuses            map[string]string
	routes              []model.Event
	err                 error
}

func (s *stream) writeLocked(e model.Event) (model.Event, error) {
	if s.err != nil {
		return e, s.err
	}
	s.seq++
	e.SchemaVersion = model.SchemaVersion
	e.Seq = s.seq
	e.RunID = s.run
	e.EventID = fmt.Sprintf("%s:%d", s.run, s.seq)
	e.RecordedAt = time.Now().UTC()
	if e.RealmID == "" {
		e.RealmID = s.realm
	}
	e.VantageID = s.vantage
	e.RoutingEpoch = s.epoch
	if err := e.Validate(); err != nil {
		s.err = err
		return e, err
	}
	if s.journal != nil {
		if err := s.journal.Append(e); err != nil {
			s.err = err
			return e, err
		}
	}
	if err := s.renderer.Write(e); err != nil {
		s.err = err
		return e, err
	}
	return e, nil
}

// reserve durably records an operation before it may send. The journal sync
// runs after the stream lock is released so result events from concurrent
// workers are not stalled behind disk latency.
func (s *stream) reserve(e model.Event) error {
	s.mu.Lock()
	// DNS exchanges may take twice the operation timeout.
	if err := s.ensureRuntimeLocked(2*s.operationTimeout + time.Second); err != nil {
		s.mu.Unlock()
		return err
	}
	if _, err := s.writeLocked(e); err != nil {
		s.mu.Unlock()
		return err
	}
	s.spent++
	j := s.journal
	s.mu.Unlock()
	if j != nil {
		return j.Sync()
	}
	return nil
}

func (s *stream) emit(e model.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, err := s.writeLocked(e)
	if err != nil {
		return err
	}
	if e.Type == "collector_status" || e.Type == "capability" {
		s.statuses[e.Source] = e.Outcome
	}
	if e.Source == "routes" && e.Prefix != nil {
		s.routes = append(s.routes, e)
	}
	if f := s.reducer.Observe(e); f != nil {
		saved, err := s.writeLocked(*f)
		if err != nil {
			return err
		}
		s.reducer.Commit(saved)
	}
	for _, association := range s.reducer.ResponsePrefixes(e) {
		if f := s.reducer.Observe(association); f != nil {
			saved, err := s.writeLocked(*f)
			if err != nil {
				return err
			}
			s.reducer.Commit(saved)
		}
	}
	return nil
}
