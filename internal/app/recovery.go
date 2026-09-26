package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"sort"
	"time"

	"lanscan/internal/discover"
	"lanscan/internal/importer"
	"lanscan/internal/journal"
	"lanscan/internal/model"
	"lanscan/internal/output"
)

func hashValue(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func decodeValue(v any, dst any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	d.DisallowUnknownFields()
	return d.Decode(dst)
}
func integer(v any) (int64, error) {
	switch n := v.(type) {
	case json.Number:
		return n.Int64()
	case int:
		return int64(n), nil
	case int64:
		return n, nil
	case uint64:
		if n <= math.MaxInt64 {
			return int64(n), nil
		}
	}
	return 0, fmt.Errorf("expected integer, got %T", v)
}
func inputsHash(seeds []importer.Seed, inventory []model.Event) (string, error) {
	return hashValue(struct {
		Seeds     []importer.Seed `json:"seeds"`
		Inventory []model.Event   `json:"inventory"`
	}{seeds, inventory})
}

type recoveryState struct {
	config              config
	configHash          string
	inputHash           string
	run, realm, vantage string
	seq, epoch          uint64
	spent               int
	elapsed             time.Duration
	lease               time.Duration
	finished            bool
	outcome             string
	inputsComplete      bool
	seeds               []importer.Seed
	inventory           []model.Event
	pending             map[string]model.Event
	historical          map[string]model.Event
}

func newRecovery() *recoveryState {
	return &recoveryState{pending: make(map[string]model.Event), historical: make(map[string]model.Event)}
}

func (r *recoveryState) replay(e model.Event) error {
	if r.run != "" && r.run != e.RunID {
		return errors.New("cannot resume a merged journal")
	}
	r.run = e.RunID
	r.seq = e.Seq
	if e.RoutingEpoch < r.epoch {
		return errors.New("routing epoch regressed")
	}
	r.epoch = e.RoutingEpoch
	switch e.Type {
	case "run_started", "config_revised":
		var c config
		if err := decodeValue(e.Details["config"], &c); err != nil {
			return fmt.Errorf("invalid saved config: %w", err)
		}
		if err := validateConfig(c); err != nil {
			return err
		}
		h, err := hashValue(c)
		if err != nil {
			return err
		}
		supplied, ok := e.Details["config_hash"].(string)
		if !ok || supplied != h {
			return errors.New("saved configuration hash is missing or does not match")
		}
		if e.Type == "config_revised" {
			if e.Details["previous_config_hash"] != r.configHash {
				return errors.New("configuration revision chain does not match")
			}
			// Scope and identity cannot be changed through an edited journal revision.
			before, after := r.config, c
			before.MaxOperations = after.MaxOperations
			before.Duration = after.Duration
			before.DiskBudget = after.DiskBudget
			if same, _ := hashValue(before); same != h {
				return errors.New("configuration revision changed immutable run settings")
			}
			if c.MaxOperations < r.config.MaxOperations || c.Duration < r.config.Duration || c.DiskBudget < r.config.DiskBudget {
				return errors.New("configuration revision shrinks a budget")
			}
		}
		r.config = c
		r.configHash = h
		if e.Type == "run_started" {
			r.realm = e.RealmID
			r.vantage = e.VantageID
			r.inputHash, _ = e.Details["input_hash"].(string)
			if r.inputHash == "" {
				return errors.New("run lacks an input snapshot hash")
			}
		}
	case "input_seed":
		index, err := integer(e.Details["index"])
		if err != nil || index < 0 || index >= int64(r.config.Limit) {
			return errors.New("invalid input seed index")
		}
		var seed importer.Seed
		if err := decodeValue(e.Details["seed"], &seed); err != nil {
			return err
		}
		if index > int64(len(r.seeds)) {
			return errors.New("seed snapshot has a gap")
		}
		if int(index) == len(r.seeds) {
			r.seeds = append(r.seeds, seed)
		} else {
			a, _ := hashValue(r.seeds[index])
			b, _ := hashValue(seed)
			if a != b {
				return errors.New("seed snapshot changed")
			}
		}
	case "input_inventory":
		index, err := integer(e.Details["index"])
		if err != nil || index < 0 || index >= int64(r.config.Limit) {
			return errors.New("invalid inventory index")
		}
		var item model.Event
		if err := decodeValue(e.Details["inventory"], &item); err != nil {
			return err
		}
		if index > int64(len(r.inventory)) {
			return errors.New("inventory snapshot has a gap")
		}
		if int(index) == len(r.inventory) {
			r.inventory = append(r.inventory, item)
		} else {
			a, _ := hashValue(r.inventory[index])
			b, _ := hashValue(item)
			if a != b {
				return errors.New("inventory snapshot changed")
			}
		}
	case "inputs_finished":
		h, err := inputsHash(r.seeds, r.inventory)
		if err != nil {
			return err
		}
		if h != r.inputHash || e.Details["input_hash"] != h {
			return errors.New("input snapshot hash does not match")
		}
		r.inputsComplete = true
	case "run_resumed":
		ns, err := integer(e.Details["total_elapsed_ns"])
		if err != nil || ns < int64(r.consumed()) {
			return errors.New("resume reset cumulative runtime")
		}
		r.elapsed = time.Duration(ns)
		r.lease = r.elapsed
		r.finished = false
	case "runtime_reserved":
		ns, err := integer(e.Details["total_reserved_ns"])
		if err != nil || ns < 0 || ns > int64(r.config.Duration) {
			return errors.New("invalid runtime reservation")
		}
		if time.Duration(ns) < r.elapsed {
			return errors.New("runtime reservation precedes committed runtime")
		}
		r.lease = time.Duration(ns)
	case "operation_reserved":
		if r.spent >= r.config.MaxOperations {
			return errors.New("journal operations exceed configured budget")
		}
		r.spent++
		id, _ := e.Details["operation_id"].(string)
		if id == "" {
			id = e.EventID
		}
		if _, exists := r.pending[id]; exists {
			return errors.New("duplicate pending operation identity")
		}
		r.pending[id] = e
	case "operation_recovered":
		id, _ := e.Details["operation_id"].(string)
		delete(r.pending, id)
	case "observation":
		if id, ok := e.Details["operation_id"].(string); ok {
			delete(r.pending, id)
		}
		if e.Address != "" && (e.Source == "probe" || e.Source == "neighbors" || e.Source == "history") {
			key := e.RealmID + "\x00" + e.Address + "\x00" + e.InterfaceID
			if _, ok := r.historical[key]; ok || len(r.historical) < r.config.Limit {
				r.historical[key] = e
			}
		}
	case "run_finished":
		ns, err := integer(e.Details["total_elapsed_ns"])
		if err != nil || ns < 0 || time.Duration(ns) < r.elapsed {
			return errors.New("missing or regressed cumulative runtime")
		}
		r.elapsed = time.Duration(ns)
		r.lease = r.elapsed
		r.finished = true
		r.outcome = e.Outcome
	}
	return nil
}

func (r *recoveryState) consumed() time.Duration {
	if !r.finished && r.lease > r.elapsed {
		return r.lease
	}
	return r.elapsed
}

func runResume(parent context.Context, args []string, stdout, stderr io.Writer) (code int, retErr error) {
	fs := flag.NewFlagSet("resume", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("journal", "", "journal to validate and resume")
	format := fs.String("format", "", "output format for this segment (default: original format)")
	outputPath := fs.String("output", "", "new exclusive output file (default: stdout)")
	addOperations := fs.Int("extend-operations", 0, "explicitly add to the cumulative operation budget")
	addDuration := fs.Duration("extend-duration", 0, "explicitly add to the cumulative active-runtime budget")
	diskBudget := fs.Int64("disk-budget", 0, "explicitly increase maximum journal bytes")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if fs.NArg() != 0 || *path == "" || *addOperations < 0 || *addDuration < 0 || *diskBudget < 0 {
		return 2, errors.New("--journal required; extensions must be nonnegative")
	}
	if *format != "" && *format != "jsonl" && *format != "csv" && *format != "text" {
		return 2, errors.New("unknown output format")
	}
	state := newRecovery()
	var updated config
	// No repair or append occurs until all immutable settings and snapshots pass.
	j, result, err := journal.OpenResume(*path, journal.Options{}, state.replay, func(result journal.ReplayResult) error {
		if state.config.NoJournal {
			return errors.New("stream-only runs cannot be resumed")
		}
		if state.finished && state.outcome == "completed" {
			return errors.New("run already completed; start a new discover run")
		}
		if state.epoch == math.MaxUint64 {
			return errors.New("routing epoch exhausted")
		}
		updated = state.config
		if *addOperations > math.MaxInt-updated.MaxOperations || *addDuration > time.Duration(math.MaxInt64)-updated.Duration {
			return errors.New("budget extension overflows")
		}
		updated.MaxOperations += *addOperations
		updated.Duration += *addDuration
		if *diskBudget != 0 {
			if *diskBudget < updated.DiskBudget {
				return errors.New("disk budget may only increase")
			}
			updated.DiskBudget = *diskBudget
		}
		if result.CompleteBytes >= updated.DiskBudget {
			return errors.New("journal disk budget exhausted; increase --disk-budget")
		}
		if !state.inputsComplete {
			var seeds []importer.Seed
			var inventory []model.Event
			var err error
			if updated.Seeds != "" {
				seeds, err = importer.Seeds(updated.Seeds, updated.Limit)
				if err != nil {
					return fmt.Errorf("incomplete input snapshot; original seeds required: %w", err)
				}
			}
			if updated.Inventory != "" {
				inventory, err = importer.Inventory(updated.Inventory, updated.Limit)
				if err != nil {
					return fmt.Errorf("incomplete input snapshot; original inventory required: %w", err)
				}
			}
			h, err := inputsHash(seeds, inventory)
			if err != nil {
				return err
			}
			if h != state.inputHash {
				return errors.New("original inputs changed before snapshot completion")
			}
			state.seeds = seeds
			state.inventory = inventory
		}
		return nil
	})
	if err != nil {
		return 1, err
	}
	defer func() {
		if err := j.Close(); err != nil && retErr == nil {
			code = 1
			retErr = err
		}
	}()
	if err = j.SetOptions(journal.Options{EveryEvent: updated.Sync == "every-event", DiskBudget: updated.DiskBudget}); err != nil {
		return 1, err
	}
	chosen := *format
	if chosen == "" {
		chosen = updated.Format
	}
	out, closeOut, err := openOutput(*outputPath, stdout)
	if err != nil {
		return 1, err
	}
	defer func() {
		if err := closeOut(); err != nil && retErr == nil {
			code = 1
			retErr = err
		}
	}()
	renderer, err := output.New(out, chosen, false)
	if err != nil {
		return 2, err
	}
	s := &stream{run: state.run, realm: state.realm, vantage: state.vantage, seq: state.seq, epoch: state.epoch + 1, journal: j, renderer: renderer, reducer: discover.NewReducer(updated.Limit), statuses: make(map[string]string), spent: state.spent}
	fmt.Fprintln(stderr, "Resuming journal:", *path)
	if len(result.TornTail) > 0 {
		fmt.Fprintf(stderr, "Preserved and removed %d torn tail bytes.\n", len(result.TornTail))
	}
	nextHash, _ := hashValue(updated)
	if nextHash != state.configHash {
		if err = s.emit(model.Event{Type: "config_revised", ObservedAt: model.Now(), Details: map[string]any{"config": updated, "config_hash": nextHash, "previous_config_hash": state.configHash}}); err != nil {
			return 1, err
		}
	}
	if err = s.emit(model.Event{Type: "run_resumed", ObservedAt: model.Now(), Details: map[string]any{"previous_seq": state.seq, "operations_spent": state.spent, "total_elapsed_ns": int64(state.consumed()), "runtime_accounting": "conservative outstanding lease charged on unclean exit"}}); err != nil {
		return 1, err
	}
	if err = s.emit(model.Event{Type: "routing_epoch", ObservedAt: model.Now(), Details: map[string]any{"reason": "resume_refresh", "prior_epoch": state.epoch}}); err != nil {
		return 1, err
	}
	ids := make([]string, 0, len(state.pending))
	for id := range state.pending {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err = s.emit(model.Event{Type: "operation_recovered", Outcome: "unknown", Details: map[string]any{"operation_id": id, "reservation_event": state.pending[id].EventID, "budget_charged": true}}); err != nil {
			return 1, err
		}
	}
	keys := make([]string, 0, len(state.historical))
	for key := range state.historical {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		old := state.historical[key]
		// Historical observations may seed revalidation, never assert fresh reachability.
		e := model.Event{Type: "observation", RealmID: old.RealmID, Address: old.Address, Zone: old.Zone, Name: old.Name, Source: "history", InterfaceID: old.InterfaceID, ActivityBasis: "historical", Reachability: "unknown", ObservedAt: old.ObservedAt, EvidenceIDs: []string{old.EventID}}
		if err = s.emit(e); err != nil {
			return 1, err
		}
	}
	return execute(parent, updated, s, state.seeds, state.inventory, state.consumed(), !state.inputsComplete)
}
