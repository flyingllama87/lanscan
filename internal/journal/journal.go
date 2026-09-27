// Package journal provides append-only JSONL with periodic durable sync and strict replay.
package journal

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"lanscan/internal/model"
)

type Options struct {
	EveryEvent bool
	DiskBudget int64
}

type Writer struct {
	mu      sync.Mutex
	file    *os.File
	guard   *os.File
	path    string
	options Options
	size    int64
	pending int
	failure error
	// written and durable count records; syncing marks an fsync running
	// without the lock so concurrent Sync callers can share it.
	written   uint64
	durable   uint64
	syncing   bool
	synced    *sync.Cond
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func Create(path string, opts Options) (*Writer, error) {
	guard, err := acquire(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		guard.Close()
		return nil, err
	}
	return start(f, guard, path, opts, 0), nil
}

// start wraps an open journal positioned at size and begins periodic syncing.
func start(f, guard *os.File, path string, opts Options, size int64) *Writer {
	w := &Writer{file: f, guard: guard, path: path, options: opts, size: size, stop: make(chan struct{}), done: make(chan struct{})}
	w.synced = sync.NewCond(&w.mu)
	go w.syncLoop()
	return w
}

func (w *Writer) syncLoop() {
	defer close(w.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-tick.C:
			w.mu.Lock()
			if w.pending > 0 && w.failure == nil {
				w.syncLocked()
			}
			w.mu.Unlock()
		}
	}
}

func (w *Writer) syncLocked() error {
	if w.failure != nil {
		return w.failure
	}
	target := w.written
	if err := w.file.Sync(); err != nil {
		w.failure = err
		return err
	}
	w.markDurableLocked(target)
	return nil
}

func (w *Writer) markDurableLocked(n uint64) {
	if n > w.durable {
		w.durable = n
	}
	w.pending = int(w.written - w.durable)
}

func (w *Writer) Append(e model.Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(b) > model.MaxRecordBytes {
		return errors.New("event exceeds record limit")
	}
	b = append(b, '\n')
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failure != nil {
		return w.failure
	}
	if w.options.DiskBudget > 0 && w.size+int64(len(b)) > w.options.DiskBudget {
		w.failure = errors.New("journal disk budget exhausted")
		return w.failure
	}
	n, err := w.file.Write(b)
	w.size += int64(n)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.failure = err
		return err
	}
	w.written++
	w.pending++
	if w.options.EveryEvent || w.pending >= 100 {
		return w.syncLocked()
	}
	return nil
}

// Sync returns once every record appended before the call is durable. The
// fsync runs without the writer lock, and concurrent callers share one fsync
// (group commit), so appends and other writers are not stalled by disk latency.
func (w *Writer) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	target := w.written
	for {
		if w.failure != nil {
			return w.failure
		}
		if w.durable >= target {
			return nil
		}
		if !w.syncing {
			break
		}
		w.synced.Wait()
	}
	w.syncing = true
	n := w.written
	w.mu.Unlock()
	err := w.file.Sync()
	w.mu.Lock()
	w.syncing = false
	if err != nil && w.failure == nil {
		w.failure = err
	} else if err == nil {
		w.markDurableLocked(n)
	}
	w.synced.Broadcast()
	return w.failure
}

func (w *Writer) Err() error { w.mu.Lock(); defer w.mu.Unlock(); return w.failure }
func (w *Writer) Close() error {
	w.closeOnce.Do(func() {
		close(w.stop)
		<-w.done
		w.mu.Lock()
		defer w.mu.Unlock()
		for w.syncing {
			w.synced.Wait()
		}
		w.syncLocked()
		err := w.file.Close()
		if e := w.guard.Close(); err == nil {
			err = e
		}
		if w.failure == nil {
			w.failure = err
		}
	})
	return w.Err()
}

type ReplayResult struct {
	Records       uint64
	CompleteBytes int64
	TornTail      []byte
	Runs          map[string]bool
}

// Replay accepts a torn final line only. Complete malformed records, sequence gaps,
// and unknown schemas are errors; callers must not treat corruption as a clean EOF.
func Replay(r io.Reader, emit func(model.Event) error) (ReplayResult, error) {
	result := ReplayResult{Runs: make(map[string]bool)}
	br := bufio.NewReaderSize(r, 64*1024)
	seqs := make(map[string]uint64)
	for {
		var line []byte
		for {
			part, err := br.ReadSlice('\n')
			line = append(line, part...)
			if len(line) > model.MaxRecordBytes+1 {
				return result, errors.New("record exceeds limit")
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			if errors.Is(err, io.EOF) {
				if len(line) > 0 {
					result.TornTail = bytes.Clone(line)
				}
				return result, nil
			}
			if err != nil {
				return result, err
			}
			break
		}
		var e model.Event
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.UseNumber()
		if err := decoder.Decode(&e); err != nil {
			return result, fmt.Errorf("record %d: %w", result.Records+1, err)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return result, fmt.Errorf("record %d: trailing JSON or invalid data", result.Records+1)
		}
		if err := e.Validate(); err != nil {
			return result, fmt.Errorf("record %d: %w", result.Records+1, err)
		}
		if e.Seq != seqs[e.RunID]+1 {
			return result, fmt.Errorf("run %s: nonconsecutive sequence %d", e.RunID, e.Seq)
		}
		if e.Seq > 1 && e.Type == "run_started" {
			return result, errors.New("duplicate run_started")
		}
		seqs[e.RunID] = e.Seq
		if _, ok := result.Runs[e.RunID]; !ok && e.Type != "run_started" {
			return result, errors.New("run missing run_started")
		}
		result.Runs[e.RunID] = e.Type == "run_finished"
		if emit != nil {
			if err := emit(e); err != nil {
				return result, err
			}
		}
		result.Records++
		result.CompleteBytes += int64(len(line))
	}
}

// SetOptions is used only after validated resume, before new events are appended.
func (w *Writer) SetOptions(opts Options) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if opts.DiskBudget > 0 && w.size >= opts.DiskBudget {
		return errors.New("journal disk budget exhausted")
	}
	w.options = opts
	return nil
}
