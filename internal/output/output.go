// Package output renders events: text and csv summarize the run when it
// finishes (a report, and a table of subnets and hosts); jsonl streams every
// event and csv-findings streams finding revisions, for tools.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"lanscan/internal/model"
)

type Renderer struct {
	format  string
	writer  io.Writer
	csv     *csv.Writer
	raw     bool
	summary *summary
	// deferred prints the text summary only at Close, for offline commands
	// that replay several runs.
	deferred bool
}

// Deferred makes the text summary wait for Close.
func (r *Renderer) Deferred() *Renderer { r.deferred = true; return r }

// Summarizing reports whether the renderer builds a summary from every event.
func (r *Renderer) Summarizing() bool { return r.summary != nil }

// Formats lists the accepted output formats.
var Formats = []string{"text", "csv", "jsonl", "csv-findings"}

func New(w io.Writer, format string, raw bool) (*Renderer, error) {
	r := &Renderer{format: format, writer: w, raw: raw}
	switch format {
	case "jsonl":
	case "text", "csv":
		r.summary = newSummary(w)
	case "csv-findings":
		r.csv = csv.NewWriter(w)
		err := r.csv.Write(strings.Split("schema_version,run_id,seq,entity_id,revision,realm_id,vantage_id,routing_epoch,observed_at,prefix,address,prefix_basis,activity_basis,reachability,protocol,port,outcome,evidence_ids", ","))
		if err != nil {
			return nil, err
		}
		r.csv.Flush()
		if err = r.csv.Error(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown output format %q", format)
	}
	return r, nil
}

func safe(s string) string {
	if len(s) > 0 && strings.ContainsRune("=+-@\t\r\n", rune(s[0])) {
		return "'" + s
	}
	return s
}

func (r *Renderer) Write(e model.Event) error {
	switch r.format {
	case "jsonl":
		return json.NewEncoder(r.writer).Encode(e)
	case "csv-findings":
		if e.Type != "finding_upsert" {
			return nil
		}
		prefix, at, port := "", "", ""
		if e.Prefix != nil {
			prefix = e.Prefix.String()
		}
		if e.ObservedAt != nil {
			at = e.ObservedAt.Format("2006-01-02T15:04:05.999999999Z07:00")
		}
		if e.Port != 0 {
			port = strconv.Itoa(e.Port)
		}
		ids, _ := json.Marshal(e.EvidenceIDs)
		fields := []string{strconv.Itoa(e.SchemaVersion), e.RunID, strconv.FormatUint(e.Seq, 10), e.EntityID, strconv.FormatUint(e.Revision, 10), e.RealmID, e.VantageID, strconv.FormatUint(e.RoutingEpoch, 10), at, prefix, e.Address, e.PrefixBasis, e.ActivityBasis, e.Reachability, e.Protocol, port, e.Outcome, string(ids)}
		if !r.raw {
			for i := range fields {
				fields[i] = safe(fields[i])
			}
		}
		if err := r.csv.Write(fields); err != nil {
			return err
		}
		r.csv.Flush()
		return r.csv.Error()
	case "text", "csv":
		r.summary.observe(e)
		if e.Type == "run_finished" && !r.deferred {
			return r.flush()
		}
	}
	return nil
}

// Close prints the text summary if run_finished never arrived, as when
// exporting an interrupted journal.
func (r *Renderer) Close() error {
	if r.summary != nil {
		return r.flush()
	}
	return nil
}

func (r *Renderer) flush() error {
	if r.format == "csv" {
		return r.summary.printCSV(r.raw)
	}
	return r.summary.print()
}
