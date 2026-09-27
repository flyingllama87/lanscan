package journal

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"lanscan/internal/model"
)

func event(seq uint64, kind string) model.Event {
	return model.Event{SchemaVersion: 1, RunID: "test", EventID: fmtID(seq), Seq: seq, Type: kind, RealmID: "realm", VantageID: "vantage", RecordedAt: time.Now().UTC(), RoutingEpoch: 1}
}
func fmtID(seq uint64) string { return "test:" + strconv.FormatUint(seq, 10) }

func TestStreamingAndReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.jsonl")
	w, err := Create(path, Options{EveryEvent: true})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err = w.Append(event(1, "run_started")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Replay(bytes.NewReader(b), nil)
	if err != nil || result.Records != 1 || result.Runs["test"] {
		t.Fatalf("%+v %v", result, err)
	}
	if err = w.Append(event(2, "run_finished")); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	result, err = Replay(bytes.NewReader(append(b, []byte(`{"torn":`)...)), nil)
	if err != nil || result.Records != 2 || !result.Runs["test"] || string(result.TornTail) != `{"torn":` {
		t.Fatalf("%+v %v", result, err)
	}
	if _, err = Create(path, Options{}); err == nil {
		t.Fatal("overwrote an existing journal")
	}
}

func TestReplayRejectsCorruptionAndSequenceGaps(t *testing.T) {
	first, _ := json.Marshal(event(1, "run_started"))
	gap, _ := json.Marshal(event(3, "observation"))
	for _, tail := range []string{"oops\n", string(gap) + "\n", strings.Repeat("x", model.MaxRecordBytes+2)} {
		_, err := Replay(strings.NewReader(string(first)+"\n"+tail), nil)
		if err == nil {
			t.Fatal("accepted corrupt journal")
		}
	}
}

func TestDiskBudgetFailureIsSticky(t *testing.T) {
	w, err := Create(filepath.Join(t.TempDir(), "journal"), Options{DiskBudget: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Append(event(1, "run_started")); err == nil {
		t.Fatal("ignored disk budget")
	}
	if err = w.Close(); err == nil {
		t.Fatal("lost write failure")
	}
}

func FuzzReplay(f *testing.F) {
	e, _ := json.Marshal(event(1, "run_started"))
	f.Add(append(e, '\n'))
	f.Add([]byte("{}\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 2*model.MaxRecordBytes {
			return
		}
		_, _ = Replay(bytes.NewReader(b), nil)
	})
}

// BenchmarkReservation measures the durable append made before every network
// operation. It bounds the achievable dispatch rate. Set LANSCAN_BENCH_DIR to
// measure a particular filesystem (the default temp directory may be tmpfs).
func BenchmarkReservation(b *testing.B) {
	dir := os.Getenv("LANSCAN_BENCH_DIR")
	if dir == "" {
		dir = b.TempDir()
	}
	path := filepath.Join(dir, "bench-"+strconv.FormatInt(time.Now().UnixNano(), 36)+".jsonl")
	defer os.Remove(path + ".lock")
	defer os.Remove(path)
	w, err := Create(path, Options{})
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close()
	var seq uint64
	for b.Loop() {
		seq++
		e := event(seq, "operation_reserved")
		e.Address, e.Protocol = "10.20.30.40", "icmp"
		e.Details = map[string]any{"operation_id": "0123456789abcdef0123456789abcdef"}
		if err := w.Append(e); err != nil {
			b.Fatal(err)
		}
		if err := w.Sync(); err != nil {
			b.Fatal(err)
		}
	}
}

func TestConcurrentSyncGroupCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.jsonl")
	w, err := Create(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seq uint64
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 25 {
				mu.Lock()
				seq++
				kind := "observation"
				if seq == 1 {
					kind = "run_started"
				}
				err := w.Append(event(seq, kind))
				mu.Unlock()
				if err != nil {
					t.Error(err)
					return
				}
				if err := w.Sync(); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
	w.mu.Lock()
	written, durable, pending := w.written, w.durable, w.pending
	w.mu.Unlock()
	if written != 200 || durable != written || pending != 0 {
		t.Fatalf("written %d durable %d pending %d", written, durable, pending)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Replay(bytes.NewReader(b), nil); err != nil || result.Records != 200 {
		t.Fatalf("%+v %v", result, err)
	}
}
