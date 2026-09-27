package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"lanscan/internal/journal"
	"lanscan/internal/model"
)

func TestPassiveDiscoveryJournalAndExport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "run.jsonl")
	var out, stderr bytes.Buffer
	code := Run(context.Background(), []string{"discover", "--journal", path, "--format", "jsonl", "--realm", "test"}, &out, &stderr)
	if code != 0 {
		t.Fatalf("code %d: %s", code, stderr.String())
	}
	result, err := journal.Replay(bytes.NewReader(out.Bytes()), func(e model.Event) error {
		if e.Type == "finding_upsert" && e.Prefix != nil && e.PrefixBasis == "unknown" {
			t.Error("unknown mask given prefix")
		}
		return nil
	})
	if err != nil || result.Records < 2 {
		t.Fatalf("%+v %v", result, err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, out.Bytes()) {
		t.Fatal("journal and JSONL stream differ")
	}
	out.Reset()
	stderr.Reset()
	if code = Run(context.Background(), []string{"export", "--journal", path, "--format", "csv-findings", "--view", "latest"}, &out, &stderr); code != 0 {
		t.Fatalf("%d: %s", code, stderr.String())
	}
	if !bytes.HasPrefix(out.Bytes(), []byte("schema_version,run_id,")) {
		t.Fatal("missing CSV header")
	}
}

func TestInvalidInputFailsBeforeOutputCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	var out, stderr bytes.Buffer
	code := Run(context.Background(), []string{"discover", "--journal", path, "--include", "not-a-prefix"}, &out, &stderr)
	if code != 2 {
		t.Fatalf("code %d", code)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("created journal before validation")
	}
}

func TestRequiredUnavailableCollectorIsPartial(t *testing.T) {
	var out, stderr bytes.Buffer
	code := Run(context.Background(), []string{"discover", "--require-capability", "missing"}, &out, &stderr)
	if code != 3 {
		t.Fatalf("%d: %s", code, stderr.String())
	}
}

func TestMergeSupportsDocumentedTrailingFlagsAndDeduplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.jsonl")
	var out, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"discover", "--journal", path, "--format", "jsonl"}, &out, &stderr); code != 0 {
		t.Fatalf("%d %s", code, stderr.String())
	}
	original := append([]byte(nil), out.Bytes()...)
	out.Reset()
	stderr.Reset()
	if code := Run(context.Background(), []string{"merge", path, path, "--format", "jsonl"}, &out, &stderr); code != 0 {
		t.Fatalf("%d %s", code, stderr.String())
	}
	var before, after []model.Event
	_, err := journal.Replay(bytes.NewReader(original), func(e model.Event) error { before = append(before, e); return nil })
	if err != nil {
		t.Fatal(err)
	}
	_, err = journal.Replay(bytes.NewReader(out.Bytes()), func(e model.Event) error { after = append(after, e); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("duplicate merge changed event stream")
	}

}
