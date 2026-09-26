package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lanscan/internal/discover"
	"lanscan/internal/importer"
	"lanscan/internal/journal"
	"lanscan/internal/model"
	"lanscan/internal/output"
)

// A partial run with a durable unfinished reservation; no actual network traffic.
func partialRun(t *testing.T, active bool) (string, config) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "run.jsonl")
	c := defaults()
	c.Realm = "corp"
	c.Vantage = "test"
	c.Journal = path
	c.Active = active
	c.Include = []string{"192.0.2.0/24"}
	c.MaxOperations = 1
	j, err := journal.Create(path, journal.Options{})
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := output.New(&bytes.Buffer{}, "jsonl", false)
	if err != nil {
		t.Fatal(err)
	}
	s := &stream{run: "test", realm: c.Realm, vantage: c.Vantage, epoch: 1, journal: j, renderer: renderer, reducer: discover.NewReducer(c.Limit), statuses: map[string]string{}}
	ch, _ := hashValue(c)
	ih, _ := inputsHash(nil, nil)
	events := []model.Event{
		{Type: "run_started", Details: map[string]any{"config": c, "config_hash": ch, "input_hash": ih}},
		{Type: "inputs_finished", Details: map[string]any{"input_hash": ih}},
		{Type: "runtime_reserved", Details: map[string]any{"total_reserved_ns": int64(3 * time.Second)}},
		{Type: "operation_reserved", Address: "192.0.2.9", Protocol: "icmp", Details: map[string]any{"operation_id": "unfinished"}},
		{Type: "observation", Source: "neighbors", Address: "192.0.2.9", ActivityBasis: "cache"},
	}
	for _, e := range events {
		if err = s.emit(e); err != nil {
			t.Fatal(err)
		}
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	return path, c
}
func replayRun(t *testing.T, path string) []model.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []model.Event
	_, err = journal.Replay(f, func(e model.Event) error { out = append(out, e); return nil })
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestResumeChargesPendingOperationAndStartsNewEpoch(t *testing.T) {
	path, _ := partialRun(t, true)
	var out, stderr bytes.Buffer
	code := Run(context.Background(), []string{"resume", "--journal", path, "--format", "jsonl"}, &out, &stderr)
	if code != 3 {
		t.Fatalf("code=%d %s", code, stderr.String())
	}
	events := replayRun(t, path)
	var finish model.Event
	recovered := false
	newReservation := false
	for _, e := range events {
		if e.Type == "run_finished" {
			finish = e
		}
		if e.Type == "operation_recovered" {
			recovered = true
			if e.Outcome != "unknown" {
				t.Fatal("unfinished operation promoted to success")
			}
		}
		if e.RoutingEpoch == 2 && e.Type == "operation_reserved" {
			newReservation = true
		}
	}
	if newReservation || !recovered || finish.RoutingEpoch != 2 || finish.Outcome != "operation_budget_exhausted" {
		t.Fatalf("recovered=%v new=%v finish=%+v", recovered, newReservation, finish)
	}
	spent, err := integer(finish.Details["operations"])
	if err != nil || spent != 1 {
		t.Fatalf("spent %d %v", spent, err)
	}
	elapsed, err := integer(finish.Details["total_elapsed_ns"])
	if err != nil || elapsed < int64(3*time.Second) {
		t.Fatalf("elapsed %d %v", elapsed, err)
	}
	// The complete journal remains valid and a second resume cannot reset either budget.
	out.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"resume", "--journal", path}, &out, &stderr)
	if code != 3 {
		t.Fatalf("second resume code=%d %s", code, stderr.String())
	}
	events = replayRun(t, path)
	last := events[len(events)-1]
	if last.Type != "run_finished" || last.RoutingEpoch != 3 {
		t.Fatalf("%+v", last)
	}
}

func TestResumeRejectsChangedConfigBeforeMutation(t *testing.T) {
	path, _ := partialRun(t, false)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(b, []byte(`"max_operations":1`), []byte(`"max_operations":99`), 1)
	if bytes.Equal(changed, b) {
		t.Fatal("fixture missing config")
	}
	changed = append(changed, []byte("torn-tail")...)
	if err = os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"resume", "--journal", path}, &out, &stderr); code != 1 {
		t.Fatalf("%d %s", code, stderr.String())
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, changed) {
		t.Fatal("modified invalid journal")
	}
	if !strings.Contains(stderr.String(), "hash") {
		t.Fatal(stderr.String())
	}
}

func TestResumeBudgetExtensionIsRecordedAndScopeImmutable(t *testing.T) {
	path, c := partialRun(t, false)
	var out, stderr bytes.Buffer
	code := Run(context.Background(), []string{"resume", "--journal", path, "--extend-operations", "2", "--extend-duration", "1m"}, &out, &stderr)
	if code != 0 {
		t.Fatalf("%d %s", code, stderr.String())
	}
	var revision model.Event
	for _, e := range replayRun(t, path) {
		if e.Type == "config_revised" {
			revision = e
		}
	}
	var updated config
	if err := decodeValue(revision.Details["config"], &updated); err != nil {
		t.Fatal(err)
	}
	if updated.MaxOperations != 3 || updated.Duration != c.Duration+time.Minute || updated.Include[0] != c.Include[0] {
		t.Fatalf("%+v", updated)
	}
	state := newRecovery()
	for _, e := range replayRun(t, path) {
		if err := state.replay(e); err != nil {
			t.Fatal(err)
		}
	}
	out.Reset()
	stderr.Reset()
	if code = Run(context.Background(), []string{"resume", "--journal", path}, &out, &stderr); code != 1 {
		t.Fatalf("finished run resumed: %d", code)
	}
}

func TestResumeUsesCompletedInputSnapshotWithoutSourceFile(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "hosts.txt")
	path := filepath.Join(dir, "run.jsonl")
	if err := os.WriteFile(seedPath, []byte("192.0.2.23\nseed.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"discover", "--journal", path, "--seeds", seedPath, "--format", "jsonl"}, &out, &stderr); code != 0 {
		t.Fatalf("%d %s", code, stderr.String())
	}
	// Remove only the final complete record to model a crash before completion.
	events := replayRun(t, path)
	var truncated bytes.Buffer
	for _, e := range events[:len(events)-1] {
		if err := json.NewEncoder(&truncated).Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, truncated.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(seedPath); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	stderr.Reset()
	if code := Run(context.Background(), []string{"resume", "--journal", path, "--format", "jsonl"}, &out, &stderr); code != 0 {
		t.Fatalf("%d %s", code, stderr.String())
	}
	found := false
	for _, e := range replayRun(t, path) {
		if e.RoutingEpoch == 2 && e.Type == "observation" && e.Address == "192.0.2.23" {
			found = true
		}
	}
	if !found {
		t.Fatal("lost seed snapshot")
	}
}

func TestInputSnapshotHashRoundTrip(t *testing.T) {
	seeds := []importer.Seed{{Name: "host.example", Source: "input:1"}}
	expected, _ := inputsHash(seeds, nil)
	b, _ := json.Marshal(seeds)
	var decoded []importer.Seed
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	actual, _ := inputsHash(decoded, nil)
	if actual != expected {
		t.Fatal("unstable snapshot hash")
	}
}
