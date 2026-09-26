package journal

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
