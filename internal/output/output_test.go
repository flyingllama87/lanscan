package output

import (
	"bytes"
	"encoding/csv"
	"errors"
	"io"
	"strings"
	"testing"

	"lanscan/internal/model"
)

func TestCSVStreamingAndFormulaNeutralization(t *testing.T) {
	var b bytes.Buffer
	r, err := New(&b, "csv", false)
	if err != nil {
		t.Fatal(err)
	}
	e := model.Event{Type: "finding_upsert", EntityID: "=DANGER()", EvidenceIDs: []string{"r:1", "r:2"}}
	if err = r.Write(e); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(b.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1][3] != "'=DANGER()" || rows[1][17] != `["r:1","r:2"]` {
		t.Fatalf("%v", rows)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestOutputFailurePropagates(t *testing.T) {
	for _, format := range []string{"jsonl", "csv", "text"} {
		r, err := New(brokenWriter{}, format, false)
		if err == nil {
			err = r.Write(model.Event{Type: "finding_upsert"})
		}
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("%s: %v", format, err)
		}
	}
}
