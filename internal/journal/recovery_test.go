package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"lanscan/internal/model"
)

func TestResumeLocksBacksUpTailAndAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.jsonl")
	w, err := Create(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Append(event(1, "run_started")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenResume(path, Options{}, nil, nil); err == nil {
		t.Fatal("second writer acquired live lock")
	}
	// Read-only export remains possible while the writer holds its sidecar lock.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Replay(bytes.NewReader(data), nil); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	tail := []byte(`{"half-written":`)
	if _, err = f.Write(tail); err != nil {
		t.Fatal(err)
	}
	f.Close()
	resumed, result, err := OpenResume(path, Options{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Records != 1 || !bytes.Equal(result.TornTail, tail) {
		t.Fatalf("%+v", result)
	}
	backups, err := filepath.Glob(path + ".torn-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("%v %v", backups, err)
	}
	backup, err := os.ReadFile(backups[0])
	if err != nil || !bytes.Equal(backup, tail) {
		t.Fatalf("backup %q %v", backup, err)
	}
	if err = resumed.Append(event(2, "run_finished")); err != nil {
		t.Fatal(err)
	}
	if err = resumed.Close(); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	result, err = Replay(bytes.NewReader(data), nil)
	if err != nil || result.Records != 2 || !result.Runs["test"] {
		t.Fatalf("%+v %v", result, err)
	}
}

func TestRejectedResumeDoesNotRepairTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.jsonl")
	w, err := Create(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Append(event(1, "run_started")); err != nil {
		t.Fatal(err)
	}
	w.Close()
	original, _ := os.ReadFile(path)
	original = append(original, []byte("torn")...)
	if err = os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("bad config")
	_, _, err = OpenResume(path, Options{}, nil, func(ReplayResult) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(original, after) {
		t.Fatal("repaired unvalidated journal")
	}
}

func TestCheckpointReferencesSyncedSequence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.jsonl")
	w, err := Create(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err = w.Append(event(1, "run_started")); err != nil {
		t.Fatal(err)
	}
	if err = w.Checkpoint(Checkpoint{RunID: "test", Seq: 1, Operations: 5, ConfigHash: "abc"}); err != nil {
		t.Fatal(err)
	}
	var c Checkpoint
	data, err := os.ReadFile(path + ".checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	stat, _ := os.Stat(path)
	if c.Seq != 1 || c.CompleteBytes != stat.Size() || c.SchemaVersion != 1 {
		t.Fatalf("%+v", c)
	}
	if err = w.Append(event(2, "run_finished")); err != nil {
		t.Fatal(err)
	}
	if err = w.Checkpoint(Checkpoint{RunID: "test", Seq: 2}); err != nil {
		t.Fatal(err)
	}
}

func TestReplayPreservesLargeIntegerDetailsAndRejectsTrailingJSON(t *testing.T) {
	e := event(1, "run_started")
	e.Details = map[string]any{"counter": uint64(9007199254740993)}
	b, _ := json.Marshal(e)
	var actual model.Event
	if _, err := Replay(bytes.NewReader(append(b, '\n')), func(e model.Event) error { actual = e; return nil }); err != nil {
		t.Fatal(err)
	}
	number, ok := actual.Details["counter"].(json.Number)
	if !ok || number.String() != "9007199254740993" {
		t.Fatalf("%T %v", actual.Details["counter"], actual.Details["counter"])
	}
	b = append(b, []byte(" {}\n")...)
	if _, err := Replay(bytes.NewReader(b), nil); err == nil {
		t.Fatal("accepted trailing JSON in a record")
	}
}
