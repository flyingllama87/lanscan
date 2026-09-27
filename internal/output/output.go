// Package output renders events without buffering findings until completion.
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
	format string
	writer io.Writer
	csv    *csv.Writer
	raw    bool
}

func New(w io.Writer, format string, raw bool) (*Renderer, error) {
	r := &Renderer{format: format, writer: w, raw: raw}
	switch format {
	case "jsonl", "text":
	case "csv":
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
	case "csv":
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
	case "text":
		if e.Type == "finding_upsert" {
			subject := e.Address
			if e.Prefix != nil {
				subject = e.Prefix.String()
			}
			if subject == "" {
				subject = e.Name
			}
			_, err := fmt.Fprintf(r.writer, "%s  basis=%s activity=%s reachability=%s source=%s\n", strconv.QuoteToASCII(subject), e.PrefixBasis, e.ActivityBasis, e.Reachability, strconv.QuoteToASCII(e.Source))
			return err
		}
		switch e.Type {
		case "routing_epoch":
			_, err := fmt.Fprintf(r.writer, "routing_epoch %d reason=%v detection=%v\n", e.RoutingEpoch, e.Details["reason"], e.Details["detection"])
			return err
		case "resolver_change":
			_, err := fmt.Fprintf(r.writer, "resolver_change detection=%v\n", e.Details["detection"])
			return err
		case "trace_finished":
			_, err := fmt.Fprintf(r.writer, "trace %s stop=%s hops=%v\n", strconv.QuoteToASCII(e.Address), e.Outcome, e.Details["hops_sent"])
			return err
		case "capability":
			_, err := fmt.Fprintf(r.writer, "capability %s %s\n", strconv.QuoteToASCII(e.Source), e.Outcome)
			return err
		case "run_finished", "plan":
			if coverage, ok := e.Details["coverage"].(map[string]any); ok {
				if _, err := fmt.Fprintf(r.writer, "coverage known_prefixes=%v responding_prefixes=%v candidate_prefixes_tested=%v untested=%v observed_addresses=%v (relative to known evidence, not the organisation)\n", coverage["known_prefixes"], coverage["prefixes_with_responding_target"], coverage["candidate_prefixes_tested"], coverage["candidate_prefixes_untested"], coverage["observed_addresses"]); err != nil {
					return err
				}
			}
			data, err := json.Marshal(e.Details)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(r.writer, "%s %s\n", e.Type, data)
			return err
		}
	}
	return nil
}
