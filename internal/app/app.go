// Package app connects the CLI to local discovery, journals, and renderers.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"lanscan/internal/discover"
	"lanscan/internal/importer"
	"lanscan/internal/journal"
	"lanscan/internal/model"
	"lanscan/internal/output"
	"lanscan/internal/platform"
	"lanscan/internal/probe"
	"lanscan/internal/schedule"
)

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

// Version can be set at build time via -ldflags.
var Version = "development"

// Run returns an exit code without terminating the caller, allowing integration tests.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	var code int
	var err error
	switch args[0] {
	case "discover":
		code, err = runDiscover(ctx, args[1:], stdout, stderr)
	case "export":
		code, err = runExport(args[1:], stdout, stderr)
	case "merge":
		code, err = runMerge(args[1:], stdout, stderr)
	case "resume":
		code, err = runResume(ctx, args[1:], stdout, stderr)
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	case "version", "--version":
		fmt.Fprintf(stdout, "lanscan %s (schema 1)\n", Version)
		return 0
	default:
		usage(stderr)
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "lanscan:", err)
	}
	return code
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: lanscan discover [options] | resume --journal FILE | export [options] | merge [options] journals...\n\nDiscovery defaults to local-only collection. Use discover --help for options.")
}

// Config configures a discovery run. Start with DefaultConfig.
type Config struct {
	Rate          float64       `json:"rate"`
	Concurrency   int           `json:"concurrency"`
	MaxOperations int           `json:"max_operations"`
	Timeout       time.Duration `json:"timeout"`
	Port          int           `json:"tcp_port"`
	Source        string        `json:"source"`
	Active        bool          `json:"active"`
	Plan          bool          `json:"plan"`
	Include       []string      `json:"include"`
	Exclude       []string      `json:"exclude"`
	ScopeFrom     string        `json:"scope_from"`
	Seeds         string        `json:"seeds"`
	Inventory     string        `json:"inventory"`
	Interface     string        `json:"interface"`
	Realm         string        `json:"realm"`
	Vantage       string        `json:"vantage"`
	Format        string        `json:"format"`
	Output        string        `json:"output"`
	Journal       string        `json:"journal"`
	NoJournal     bool          `json:"no_journal"`
	Sync          string        `json:"sync"`
	Limit         int           `json:"candidate_limit"`
	DiskBudget    int64         `json:"disk_budget"`
	Duration      time.Duration `json:"duration"`
	Require       []string      `json:"require_capability"`
	// Fields added after schema 1 omit zero values so earlier configuration
	// hashes remain verifiable on resume.
	DNSSuffix       []string      `json:"dns_suffix,omitempty"`
	Resolver        string        `json:"resolver,omitempty"`
	DNSBudget       int           `json:"dns_budget,omitempty"`
	Trace           int           `json:"trace,omitempty"`
	TraceHops       int           `json:"trace_hops,omitempty"`
	TraceBudget     int           `json:"trace_budget,omitempty"`
	SamplePerPrefix int           `json:"sample_per_prefix,omitempty"`
	Refresh         time.Duration `json:"refresh_interval,omitempty"`
}

type config = Config

// DefaultConfig returns the CLI defaults.
func DefaultConfig() Config { return defaults() }

func defaults() config {
	return config{Rate: 20, Concurrency: 32, MaxOperations: 1000, Timeout: time.Second, Port: 443, Format: "text", Sync: "periodic", Limit: 100000, DiskBudget: 256 << 20, Duration: 2 * time.Minute, DNSBudget: 100, TraceHops: 16, TraceBudget: 48, Refresh: 5 * time.Second}
}

func parseConfig(args []string, stderr io.Writer) (config, error) {
	c := defaults()
	// Load JSON configuration before flags so explicit CLI values always win.
	for i, a := range args {
		path := ""
		if strings.HasPrefix(a, "--config=") {
			path = strings.TrimPrefix(a, "--config=")
		}
		if a == "--config" && i+1 < len(args) {
			path = args[i+1]
		}
		if path != "" {
			f, err := os.Open(path)
			if err != nil {
				return c, err
			}
			d := json.NewDecoder(io.LimitReader(f, 1<<20))
			d.DisallowUnknownFields()
			err = d.Decode(&c)
			if err == nil {
				var extra any
				if e := d.Decode(&extra); e != io.EOF {
					err = errors.New("config contains trailing data")
				}
			}
			f.Close()
			if err != nil {
				return c, err
			}
		}
	}
	// Repeated list flags replace the config list, then append in CLI order.
	for _, entry := range []struct {
		name  string
		value *[]string
	}{{"include", &c.Include}, {"exclude", &c.Exclude}, {"require-capability", &c.Require}, {"dns-suffix", &c.DNSSuffix}} {
		for _, arg := range args {
			if arg == "--"+entry.name || strings.HasPrefix(arg, "--"+entry.name+"=") {
				*entry.value = nil
				break
			}
		}
	}
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configPath string
	fs.Float64Var(&c.Rate, "rate", c.Rate, "maximum operation starts per second")
	fs.IntVar(&c.Concurrency, "concurrency", c.Concurrency, "maximum concurrent validation jobs")
	fs.IntVar(&c.MaxOperations, "max-operations", c.MaxOperations, "maximum operation reservations, including failed starts")
	fs.DurationVar(&c.Timeout, "timeout", c.Timeout, "deadline per echo or TCP attempt")
	fs.IntVar(&c.Port, "tcp-port", c.Port, "single fallback TCP service port; silence is inconclusive")
	fs.StringVar(&c.Source, "source", c.Source, "source IP address for validation")
	fs.StringVar(&configPath, "config", "", "JSON configuration file (duration in nanoseconds)")
	fs.BoolVar(&c.Active, "active", c.Active, "enable explicitly scoped network validation")
	fs.BoolVar(&c.Plan, "plan", c.Plan, "collect locally and show the bounded candidate plan; no probes")
	fs.Var((*stringsFlag)(&c.Include), "include", "allowed CIDR; repeatable")
	fs.Var((*stringsFlag)(&c.Exclude), "exclude", "excluded CIDR; repeatable, always wins")
	fs.StringVar(&c.ScopeFrom, "scope-from", c.ScopeFrom, "routes: use explicit private unicast routes as scope")
	fs.StringVar(&c.Seeds, "seeds", c.Seeds, "file with one IP or hostname per line")
	fs.StringVar(&c.Inventory, "inventory", c.Inventory, "prefix inventory CSV")
	fs.StringVar(&c.Interface, "interface", c.Interface, "restrict planned egress interface")
	fs.StringVar(&c.Realm, "realm", c.Realm, "network realm (default: unique to this run)")
	fs.StringVar(&c.Vantage, "vantage", c.Vantage, "observation point (default: host name)")
	fs.StringVar(&c.Format, "format", c.Format, "text, jsonl, or csv")
	fs.StringVar(&c.Output, "output", c.Output, "exclusive output file (default: stdout)")
	fs.StringVar(&c.Journal, "journal", c.Journal, "exclusive JSONL journal path")
	fs.BoolVar(&c.NoJournal, "no-journal", c.NoJournal, "stream only, without a recoverable journal")
	fs.StringVar(&c.Sync, "sync", c.Sync, "periodic or every-event journal sync")
	fs.IntVar(&c.Limit, "candidate-limit", c.Limit, "maximum retained findings and candidates")
	fs.Int64Var(&c.DiskBudget, "disk-budget", c.DiskBudget, "maximum journal bytes")
	fs.DurationVar(&c.Duration, "duration", c.Duration, "maximum run duration")
	fs.Var((*stringsFlag)(&c.Require), "require-capability", "collector or capability that must be available; repeatable")
	fs.Var((*stringsFlag)(&c.DNSSuffix), "dns-suffix", "approved organisational DNS suffix; repeatable")
	fs.StringVar(&c.Resolver, "resolver", c.Resolver, "explicit DNS server IP (default: system resolver policy)")
	fs.IntVar(&c.DNSBudget, "dns-budget", c.DNSBudget, "maximum DNS exchanges in active mode; 0 disables DNS")
	fs.IntVar(&c.Trace, "trace", c.Trace, "trace up to N selected destinations; 0 disables")
	fs.IntVar(&c.TraceHops, "trace-hops", c.TraceHops, "maximum hop limit per trace")
	fs.IntVar(&c.TraceBudget, "trace-budget", c.TraceBudget, "maximum trace hop operations")
	fs.IntVar(&c.SamplePerPrefix, "sample-per-prefix", c.SamplePerPrefix, "synthetic IPv4 samples in known prefixes without host evidence (0-3)")
	fs.DurationVar(&c.Refresh, "refresh-interval", c.Refresh, "topology poll interval during active runs")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, errors.New("unexpected positional arguments")
	}
	return c, validateConfig(c)
}

func validateConfig(c config) error {
	if c.Limit < 1 || c.Limit > 1000000 || c.Duration <= 0 || c.DiskBudget < 1 {
		return errors.New("positive duration/disk budget and candidate limit 1..1000000 required")
	}
	if c.Format != "text" && c.Format != "jsonl" && c.Format != "csv" {
		return errors.New("format must be text, jsonl, or csv")
	}
	if c.Sync != "periodic" && c.Sync != "every-event" {
		return errors.New("sync must be periodic or every-event")
	}
	if c.NoJournal && c.Journal != "" {
		return errors.New("--no-journal and --journal are mutually exclusive")
	}
	if c.ScopeFrom != "" && c.ScopeFrom != "routes" {
		return errors.New("scope-from must be routes")
	}
	if c.Active && len(c.Include) == 0 && c.ScopeFrom == "" {
		return errors.New("active discovery requires --include or --scope-from routes")
	}
	if math.IsNaN(c.Rate) || math.IsInf(c.Rate, 0) || c.Rate <= 0 || c.Rate > 10000 || c.Concurrency < 1 || c.Concurrency > 1024 || c.MaxOperations < 1 || c.Timeout <= 0 || c.Port < 1 || c.Port > 65535 {
		return errors.New("invalid probe budgets, concurrency, timeout or TCP port")
	}
	if c.Source != "" {
		if _, err := netip.ParseAddr(c.Source); err != nil {
			return fmt.Errorf("invalid source: %w", err)
		}
	}
	if c.Resolver != "" {
		if a, err := netip.ParseAddr(c.Resolver); err != nil || a.IsUnspecified() || a.IsMulticast() {
			return errors.New("resolver must be a unicast IP address")
		}
	}
	for _, s := range c.DNSSuffix {
		if !importer.ValidName(s) {
			return fmt.Errorf("invalid DNS suffix %q", s)
		}
	}
	if c.DNSBudget < 0 || c.Trace < 0 || c.Trace > 64 || c.TraceBudget < 0 || c.SamplePerPrefix < 0 || c.SamplePerPrefix > 3 {
		return errors.New("DNS/trace budgets must be nonnegative; trace 0..64; sample-per-prefix 0..3")
	}
	if c.Trace > 0 && (c.TraceHops < 1 || c.TraceHops > 64) {
		return errors.New("trace-hops must be 1..64")
	}
	if c.Refresh < 0 || (c.Refresh > 0 && c.Refresh < 500*time.Millisecond) {
		return errors.New("refresh-interval must be 0 (disabled) or at least 500ms")
	}
	return nil
}

type stream struct {
	mu                  sync.Mutex
	run, realm, vantage string
	seq                 uint64
	epoch               uint64
	spent               int
	segmentStart        time.Time
	baseElapsed         time.Duration
	runtimeLimit        time.Duration
	operationTimeout    time.Duration
	runtimeLease        time.Duration
	cancel              context.CancelFunc
	journal             *journal.Writer
	renderer            interface{ Write(model.Event) error }
	reducer             *discover.Reducer
	statuses            map[string]string
	routes              []model.Event
	err                 error
}

func (s *stream) writeLocked(e model.Event) (model.Event, error) {
	if s.err != nil {
		return e, s.err
	}
	s.seq++
	e.SchemaVersion = model.SchemaVersion
	e.Seq = s.seq
	e.RunID = s.run
	e.EventID = fmt.Sprintf("%s:%d", s.run, s.seq)
	e.RecordedAt = time.Now().UTC()
	if e.RealmID == "" {
		e.RealmID = s.realm
	}
	e.VantageID = s.vantage
	e.RoutingEpoch = s.epoch
	if err := e.Validate(); err != nil {
		s.err = err
		return e, err
	}
	if s.journal != nil {
		if err := s.journal.Append(e); err != nil {
			s.err = err
			return e, err
		}
	}
	if err := s.renderer.Write(e); err != nil {
		s.err = err
		return e, err
	}
	return e, nil
}

func (s *stream) reserve(e model.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// DNS exchanges may take twice the operation timeout.
	if err := s.ensureRuntimeLocked(2*s.operationTimeout + time.Second); err != nil {
		return err
	}
	if _, err := s.writeLocked(e); err != nil {
		return err
	}
	s.spent++
	if s.journal != nil {
		return s.journal.Sync()
	}
	return nil
}

func (s *stream) emit(e model.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, err := s.writeLocked(e)
	if err != nil {
		return err
	}
	if e.Type == "collector_status" || e.Type == "capability" {
		s.statuses[e.Source] = e.Outcome
	}
	if e.Source == "routes" && e.Prefix != nil {
		s.routes = append(s.routes, e)
	}
	if f := s.reducer.Observe(e); f != nil {
		saved, err := s.writeLocked(*f)
		if err != nil {
			return err
		}
		s.reducer.Commit(saved)
	}
	for _, association := range s.reducer.ResponsePrefixes(e) {
		if f := s.reducer.Observe(association); f != nil {
			saved, err := s.writeLocked(*f)
			if err != nil {
				return err
			}
			s.reducer.Commit(saved)
		}
	}
	return nil
}

func openOutput(path string, fallback io.Writer) (io.Writer, func() error, error) {
	if path == "" {
		return fallback, func() error { return nil }, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}

func runDiscover(parent context.Context, args []string, stdout, stderr io.Writer) (code int, retErr error) {
	c, err := parseConfig(args, stderr)
	if err != nil {
		return 2, err
	}
	return discoverConfig(parent, c, stdout, stderr, nil)
}

// Discover runs the shared discovery pipeline with a typed event sink.
func Discover(ctx context.Context, c Config, emit func(model.Event) error) (int, error) {
	if emit == nil {
		return 2, errors.New("event handler required")
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	if c.Output != "" {
		return 2, errors.New("Output is CLI-only; use the event handler to write results")
	}
	return discoverConfig(ctx, c, io.Discard, io.Discard, eventSink(emit))
}

type eventSink func(model.Event) error

func (f eventSink) Write(e model.Event) error { return f(e) }

func discoverConfig(parent context.Context, c config, stdout, stderr io.Writer, sink eventSink) (code int, retErr error) {
	if err := validateConfig(c); err != nil {
		return 2, err
	}
	var err error
	_, err = discover.ParsePrefixes(c.Include)
	if err != nil {
		return 2, err
	}
	_, err = discover.ParsePrefixes(c.Exclude)
	if err != nil {
		return 2, err
	}
	var seeds []importer.Seed
	var inventory []model.Event
	if c.Seeds != "" {
		seeds, err = importer.Seeds(c.Seeds, c.Limit)
		if err != nil {
			return 2, err
		}
	}
	if c.Inventory != "" {
		inventory, err = importer.Inventory(c.Inventory, c.Limit)
		if err != nil {
			return 2, err
		}
	}
	id, err := model.NewRunID()
	if err != nil {
		return 1, err
	}
	if c.Realm == "" {
		c.Realm = "run-" + id
	}
	if c.Vantage == "" {
		c.Vantage, _ = os.Hostname()
		if c.Vantage == "" {
			c.Vantage = id
		}
	}
	if !c.NoJournal && c.Journal == "" {
		c.Journal = "lanscan-" + id + ".jsonl"
	}
	out, closeOut, err := openOutput(c.Output, stdout)
	if err != nil {
		return 1, err
	}
	defer func() {
		if err := closeOut(); err != nil && retErr == nil {
			code = 1
			retErr = err
		}
	}()
	renderer, err := output.New(out, c.Format, false)
	if err != nil {
		return 1, err
	}
	var j *journal.Writer
	if !c.NoJournal {
		j, err = journal.Create(c.Journal, journal.Options{EveryEvent: c.Sync == "every-event", DiskBudget: c.DiskBudget})
		if err != nil {
			return 1, err
		}
		defer func() {
			if err := j.Close(); err != nil && retErr == nil {
				code = 1
				retErr = err
			}
		}()
		fmt.Fprintln(stderr, "Journal:", c.Journal)
	}
	s := &stream{run: id, realm: c.Realm, vantage: c.Vantage, epoch: 1, journal: j, renderer: renderer, reducer: discover.NewReducer(c.Limit), statuses: make(map[string]string)}
	if sink != nil {
		s.renderer = sink
	}
	configHash, err := hashValue(c)
	if err != nil {
		return 1, err
	}
	inputHash, err := inputsHash(seeds, inventory)
	if err != nil {
		return 1, err
	}
	if err = s.emit(model.Event{Type: "run_started", ObservedAt: model.Now(), Details: map[string]any{"config": c, "config_hash": configHash, "input_hash": inputHash, "version": Version, "traffic_accounting": "application operations; no packet guarantee"}}); err != nil {
		return 1, err
	}
	return execute(parent, c, s, seeds, inventory, 0, true)
}

func execute(parent context.Context, c config, s *stream, seeds []importer.Seed, inventory []model.Event, used time.Duration, snapshot bool) (code int, retErr error) {
	includes, err := discover.ParsePrefixes(c.Include)
	if err != nil {
		return 2, err
	}
	excludes, err := discover.ParsePrefixes(c.Exclude)
	if err != nil {
		return 2, err
	}
	remaining := c.Duration - used
	if remaining < 0 {
		remaining = 0
	}
	ctx, cancel := context.WithTimeout(parent, remaining)
	defer cancel()
	s.segmentStart = time.Now()
	s.baseElapsed = used
	s.runtimeLimit = c.Duration
	s.operationTimeout = c.Timeout
	s.cancel = cancel
	started := s.segmentStart
	stopHeartbeat := s.heartbeat(ctx)
	defer stopHeartbeat()
	if snapshot {
		for i, seed := range seeds {
			if err = s.emit(model.Event{Type: "input_seed", Details: map[string]any{"index": i, "seed": seed}}); err != nil {
				return 1, err
			}
		}
		for i, item := range inventory {
			if err = s.emit(model.Event{Type: "input_inventory", Details: map[string]any{"index": i, "inventory": item}}); err != nil {
				return 1, err
			}
		}
		h, _ := inputsHash(seeds, inventory)
		if err = s.emit(model.Event{Type: "inputs_finished", Details: map[string]any{"input_hash": h}}); err != nil {
			return 1, err
		}
	}

	for _, seed := range seeds {
		e := model.Event{Type: "observation", Source: seed.Source, Name: seed.Name}
		if seed.Address.IsValid() {
			e.Address = seed.Address.String()
		}
		if err = s.emit(e); err != nil {
			return 1, err
		}
	}
	for _, e := range inventory {
		if err = s.emit(e); err != nil {
			return 1, err
		}
	}
	collectors := []func(context.Context, platform.Emit) error{platform.Interfaces, platform.Network, platform.Hosts, platform.Resolvers, platform.DNSCache}
	if err := collect(ctx, s, collectors); err != nil {
		return 1, err
	}
	active := c.Active && !c.Plan
	scope := &liveScope{base: discover.Scope{Include: includes, Exclude: excludes, Interface: c.Interface, SamplePerPrefix: c.SamplePerPrefix}, fromRoutes: c.ScopeFrom == "routes"}
	scope.refresh(s)
	var runner *schedule.Runner
	dnsCtx := schedule.DNSContext{Resolver: net.DefaultResolver, Policy: "system", Suffixes: c.DNSSuffix}
	if c.Resolver != "" {
		dnsCtx = explicitResolver(c.Resolver, c.DNSSuffix)
	}
	names := forwardNames(seeds, c.DNSSuffix)
	stopWatch := func() {}
	if active && ctx.Err() == nil {
		noEcho, err := s.capabilities(c)
		if err != nil {
			return 1, err
		}
		source := netip.Addr{}
		if c.Source != "" {
			source, _ = netip.ParseAddr(c.Source)
		}
		s.mu.Lock()
		left := c.MaxOperations - s.spent
		s.mu.Unlock()
		if left < 0 {
			left = 0
		}
		runner = &schedule.Runner{Config: schedule.Config{Rate: c.Rate, Concurrency: c.Concurrency, MaxOperations: left, Timeout: c.Timeout, Port: c.Port, Source: source, Interface: c.Interface, EnrichmentLimit: left / 2, DNSBudget: min(c.DNSBudget, left/2), TraceBudget: min(c.TraceBudget, left/2), NoEcho4: noEcho[0], NoEcho6: noEcho[1]}, Emit: s.emit, Reserve: s.reserve, Allow: scope.allow}
		stopWatch = s.watchTopology(ctx, c.Refresh, scope)
		if left > 0 && c.DNSBudget > 0 && len(names) > 0 {
			if _, err := runner.Forward(ctx, dnsCtx, names); err != nil {
				stopWatch()
				return 1, err
			}
		}
	}
	defer stopWatch()
	s.mu.Lock()
	candidates, skips := s.reducer.Plan(scope.current(), c.Realm)
	s.mu.Unlock()
	synthetic := 0
	for _, cand := range candidates {
		if cand.Synthetic {
			synthetic++
		}
	}
	if c.Plan {
		planned := scope.current()
		if err := s.emit(model.Event{Type: "plan", ObservedAt: model.Now(), Details: map[string]any{"candidates": len(candidates), "synthetic_samples": synthetic, "skipped": skips, "include": planned.Include, "exclude": planned.Exclude, "unresolved_names": countNames(seeds), "dns_names_eligible": len(names), "dns_budget": c.DNSBudget, "trace_destinations": c.Trace, "trace_budget": c.TraceBudget, "max_operations": c.MaxOperations, "network_operations": 0, "prediction": "candidate counts exclude later DNS answers; operations are not packets"}}); err != nil {
			return 1, err
		}
	}
	validation := schedule.Summary{Untried: len(candidates), StopReason: "completed"}
	if runner != nil && ctx.Err() == nil && runner.Spent() < runner.Config.MaxOperations {
		validation, err = runner.Run(ctx, candidates)
		if err != nil {
			return 1, err
		}
		if c.DNSBudget > 0 && ctx.Err() == nil {
			var responders []netip.Addr
			for _, r := range runner.Results() {
				if r.Response {
					responders = append(responders, r.Target)
				}
			}
			if err := runner.Reverse(ctx, dnsCtx, responders); err != nil {
				return 1, err
			}
		}
		if c.Trace > 0 && ctx.Err() == nil {
			hops := c.TraceHops
			if err := runner.Trace(ctx, schedule.SelectTraceTargets(runner.Results(), c.Trace), hops); err != nil {
				return 1, err
			}
		}
	}
	stopWatch()
	stopHeartbeat()
	s.mu.Lock()
	streamErr := s.err
	totalSpent := s.spent
	s.mu.Unlock()
	if streamErr != nil {
		return 1, streamErr
	}
	if active && validation.Untried > 0 && totalSpent >= c.MaxOperations {
		validation.StopReason = "operation_budget_exhausted"
	}
	reason := "completed"
	code = 0
	if validation.StopReason != "completed" {
		code = 3
		reason = validation.StopReason
	}
	if s.reducer.Dropped > 0 {
		code = 3
		reason = "capacity_exceeded"
	}
	for _, name := range c.Require {
		if st := s.statuses[name]; st != "complete" && st != "available" {
			code = 3
			reason = "required_capability_unavailable"
		}
	}
	if ctx.Err() != nil {
		code = 3
		reason = "duration_exhausted"
	}
	if parent.Err() != nil {
		code = 130
		reason = "interrupted"
	}
	// Read runner state before the stream lock: operation() holds the runner's
	// dispatch lock while reserving through the stream.
	var results []schedule.Result
	methods := map[string]int{}
	if runner != nil {
		results, methods = runner.Results(), runner.ByMethod()
	}
	s.mu.Lock()
	coverage := s.coverage(results, methods, candidates)
	epoch := s.epoch
	s.mu.Unlock()
	if err := s.emit(model.Event{Type: "run_finished", ObservedAt: model.Now(), Outcome: reason, Details: map[string]any{"stop_reason": reason, "elapsed_ms": time.Since(started).Milliseconds(), "total_elapsed_ns": int64(used + time.Since(started)), "findings": len(s.reducer.Findings), "known_prefixes": len(s.reducer.Prefixes), "candidate_addresses": len(candidates), "synthetic_samples": synthetic, "untested_candidates": validation.Untried, "capacity_dropped": s.reducer.Dropped, "operations": totalSpent, "segment_operations": validation.Operations, "validation": validation, "collectors": s.statuses, "skipped": skips, "coverage": coverage, "routing_epochs": epoch, "journal": !c.NoJournal, "sync": c.Sync, "format": c.Format, "accounting_limitations": accountingLimitations}}); err != nil {
		return 1, err
	}
	if err := s.checkpoint(c); err != nil {
		return 1, err
	}
	return code, nil
}

var accountingLimitations = []string{
	"operations count application starts, not wire packets",
	"TCP retransmissions, ARP/NDP resolution and VPN encapsulation are not counted",
	"system resolver lookups may issue retries or recursion that are not visible",
	"coverage counts are relative to known prefixes and candidates, not the organisation",
}

// collect runs collectors concurrently; each reports its own terminal status.
func collect(ctx context.Context, s *stream, collectors []func(context.Context, platform.Emit) error) error {
	results := make(chan error, len(collectors))
	for _, fn := range collectors {
		go func() { results <- fn(ctx, s.emit) }()
	}
	var first error
	for range collectors {
		if err := <-results; err != nil && first == nil {
			first = err
		}
	}
	return first
}

// capabilities records the capability matrix and reports, per family, whether
// echo is unavailable.
func (s *stream) capabilities(c config) ([2]bool, error) {
	var noEcho [2]bool
	for i, v6 := range []bool{false, true} {
		name := "icmp4"
		if v6 {
			name = "icmp6"
		}
		outcome := "available"
		details := map[string]any{}
		if err := probe.EchoCapability(v6); err != nil {
			outcome = "unavailable"
			details["error"] = err.Error()
			details["fallback"] = "tcp_connect"
			noEcho[i] = true
		}
		if err := s.emit(model.Event{Type: "capability", Source: name, Outcome: outcome, ObservedAt: model.Now(), Details: details}); err != nil {
			return noEcho, err
		}
	}
	dns := map[string]any{"policy": "system", "upstream": "unknown", "budget": c.DNSBudget}
	if c.Resolver != "" {
		dns = map[string]any{"policy": "explicit", "resolver": c.Resolver, "budget": c.DNSBudget, "note": "explicit resolver can bypass platform split-DNS policy"}
	}
	outcome := "available"
	if c.DNSBudget == 0 {
		outcome = "disabled"
	}
	if err := s.emit(model.Event{Type: "capability", Source: "dns", Outcome: outcome, ObservedAt: model.Now(), Details: dns}); err != nil {
		return noEcho, err
	}
	if c.Trace > 0 {
		trace := map[string]any{"backend": "hop-limited ICMP echo", "hops": c.TraceHops, "budget": c.TraceBudget, "paris": false}
		outcome = "available"
		if err := probe.EchoCapability(false); err != nil {
			outcome = "unavailable"
			trace["error"] = err.Error()
		}
		if err := s.emit(model.Event{Type: "capability", Source: "trace", Outcome: outcome, ObservedAt: model.Now(), Details: trace}); err != nil {
			return noEcho, err
		}
	}
	return noEcho, nil
}

func forwardNames(seeds []importer.Seed, suffixes []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, seed := range seeds {
		if seed.Name == "" || seen[seed.Name] {
			continue
		}
		// Supplied names need an approved suffix whenever suffixes are configured.
		if len(suffixes) > 0 && !schedule.InSuffix(seed.Name, suffixes) {
			continue
		}
		seen[seed.Name] = true
		out = append(out, seed.Name)
	}
	return out
}

func explicitResolver(server string, suffixes []string) schedule.DNSContext {
	addr := net.JoinHostPort(server, "53")
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}}
	return schedule.DNSContext{Resolver: r, Policy: "explicit", Server: server, Suffixes: suffixes}
}

func countNames(seeds []importer.Seed) int {
	n := 0
	for _, s := range seeds {
		if s.Name != "" {
			n++
		}
	}
	return n
}

func runExport(args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("journal", "", "input JSONL journal")
	format := fs.String("format", "jsonl", "jsonl, csv, or text")
	view := fs.String("view", "events", "events or latest findings")
	outputPath := fs.String("output", "", "exclusive output file")
	raw := fs.Bool("raw-csv", false, "preserve formula-leading text without spreadsheet neutralization")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *path == "" || fs.NArg() > 0 || (*view != "events" && *view != "latest") {
		return 2, errors.New("--journal required; --view must be events or latest")
	}
	f, err := os.Open(*path)
	if err != nil {
		return 1, err
	}
	defer f.Close()
	out, closeOut, err := openOutput(*outputPath, stdout)
	if err != nil {
		return 1, err
	}
	r, err := output.New(out, *format, *raw)
	if err != nil {
		closeOut()
		return 2, err
	}
	latest := make(map[string]model.Event)
	result, err := journal.Replay(f, func(e model.Event) error {
		if *view == "latest" {
			if e.Type == "finding_upsert" {
				latest[model.FindingKey(e)] = e
			}
			return nil
		}
		return r.Write(e)
	})
	if err == nil && *view == "latest" {
		keys := make([]string, 0, len(latest))
		for k := range latest {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if err = r.Write(latest[k]); err != nil {
				break
			}
		}
	}
	closeErr := closeOut()
	if err != nil {
		return 1, err
	}
	if closeErr != nil {
		return 1, closeErr
	}
	partial := len(result.TornTail) > 0
	for _, complete := range result.Runs {
		if !complete {
			partial = true
		}
	}
	if partial {
		fmt.Fprintln(stderr, "Warning: incomplete run or torn final record; complete records were exported.")
		return 3, nil
	}
	return 0, nil
}

func runMerge(args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("merge", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "jsonl", "jsonl, csv, or text")
	outputPath := fs.String("output", "", "exclusive output file")
	// Accept the documented command form with options after input paths.
	var options, inputs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			inputs = append(inputs, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") {
			options = append(options, arg)
			if (arg == "--format" || arg == "--output" || arg == "-format" || arg == "-output") && i+1 < len(args) {
				i++
				options = append(options, args[i])
			}
		} else {
			inputs = append(inputs, arg)
		}
	}
	if err := fs.Parse(append(append(options, "--"), inputs...)); err != nil {
		return 2, err
	}
	paths := fs.Args()
	if len(paths) < 2 {
		return 2, errors.New("merge requires at least two journals; flags precede paths")
	}
	out, closeOut, err := openOutput(*outputPath, stdout)
	if err != nil {
		return 1, err
	}
	r, err := output.New(out, *format, false)
	if err != nil {
		closeOut()
		return 2, err
	}
	seen := make(map[string]string)
	partial := false
	for _, path := range paths {
		f, e := os.Open(path)
		if e != nil {
			err = e
			break
		}
		result, e := journal.Replay(f, func(e model.Event) error {
			b, _ := json.Marshal(e)
			if old, ok := seen[e.EventID]; ok {
				if old != string(b) {
					return fmt.Errorf("conflicting event %s", e.EventID)
				}
				return nil
			}
			seen[e.EventID] = string(b)
			return r.Write(e)
		})
		f.Close()
		if e != nil {
			err = e
			break
		}
		if len(result.TornTail) > 0 {
			partial = true
		}
		for _, complete := range result.Runs {
			if !complete {
				partial = true
			}
		}
	}
	closeErr := closeOut()
	if err != nil {
		return 1, err
	}
	if closeErr != nil {
		return 1, closeErr
	}
	if partial {
		fmt.Fprintln(stderr, "Warning: at least one input run is incomplete.")
		return 3, nil
	}
	return 0, nil
}
