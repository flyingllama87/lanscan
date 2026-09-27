package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"lanscan/internal/discover"
	"lanscan/internal/importer"
	"lanscan/internal/journal"
	"lanscan/internal/model"
	"lanscan/internal/output"
	"lanscan/internal/platform"
	"lanscan/internal/probe"
	"lanscan/internal/schedule"
	"lanscan/internal/version"
)

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
		return 2, errors.New("config.Output is CLI-only; use the event handler to write results")
	}
	return discoverConfig(ctx, c, io.Discard, io.Discard, eventSink(emit))
}

type eventSink func(model.Event) error

func (f eventSink) Write(e model.Event) error { return f(e) }

func discoverConfig(parent context.Context, c config, stdout, stderr io.Writer, sink eventSink) (code int, retErr error) {
	c = c.resolved()
	if err := validateConfig(c); err != nil {
		return 2, err
	}
	// Fail before creating any file when capture is impossible.
	if c.Listen > 0 {
		capt, err := listenCapture(c.Interface)
		if err != nil {
			return 1, fmt.Errorf("--listen: %w", err)
		}
		capt.Close()
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
	if err = s.emit(model.Event{Type: "run_started", ObservedAt: model.Now(), Details: map[string]any{"config": c, "config_hash": configHash, "input_hash": inputHash, "version": version.String(), "traffic_accounting": "application operations; no packet guarantee"}}); err != nil {
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
		if err := s.emitInputSnapshot(seeds, inventory); err != nil {
			return 1, err
		}
	}
	if err := s.emitInputs(seeds, inventory); err != nil {
		return 1, err
	}
	if err := collect(ctx, s, localCollectors); err != nil {
		return 1, err
	}
	if c.Listen > 0 {
		if err := s.listenFor(ctx, c); err != nil {
			return 1, err
		}
	}
	active := c.active()
	if len(includes) == 0 && c.ScopeFrom == "" {
		includes = discover.PrivateSpace
	}
	scope := &liveScope{base: discover.Scope{Include: includes, Exclude: excludes, Interface: c.Interface, SamplePerPrefix: c.SamplePerPrefix, Neighbours: c.Neighbours, NoIPv6: c.NoIPv6}, fromRoutes: c.ScopeFrom == "routes"}
	scope.refresh(s)
	dnsCtx := schedule.DNSContext{Resolver: probes.resolver, Policy: probes.resolverPolicy, Annotate: probes.dnsPolicy, Suffixes: c.DNSSuffix}
	if c.Resolver != "" {
		dnsCtx = explicitResolver(c.Resolver, c.DNSSuffix)
	}
	names := forwardNames(seeds, c.DNSSuffix)
	var runner *schedule.Runner
	stopWatch := func() {}
	if active && ctx.Err() == nil {
		runner, stopWatch, err = s.startValidation(ctx, c, scope, dnsCtx, names)
		if err != nil {
			return 1, err
		}
	}
	defer stopWatch()
	s.mu.Lock()
	candidates, skips := s.reducer.Plan(scope.current(), c.Realm)
	s.mu.Unlock()
	if c.Plan {
		if err := s.emitPlan(c, scope.current(), candidates, skips, seeds, names); err != nil {
			return 1, err
		}
	}
	validation := schedule.Summary{Untried: len(candidates), StopReason: "completed"}
	if runner != nil && ctx.Err() == nil && runner.Spent() < runner.Config.MaxOperations {
		if validation, err = validateAndEnrich(ctx, c, runner, dnsCtx, candidates); err != nil {
			return 1, err
		}
	}
	stopWatch()
	stopHeartbeat()
	return s.finish(parent, ctx, c, runner, finishInput{started: started, used: used, active: active, validation: validation, candidates: candidates, skips: skips})
}

// probes are the network primitives of active runs. Tests replace them to
// drive the whole pipeline without sending traffic.
var probes = struct {
	capability     func(ipv6 bool) error
	lookup         func(target, source netip.Addr, iface string) (platform.Route, error)
	echo           func(context.Context, netip.Addr, platform.Route, int) probe.Result
	echoFlow       func(context.Context, netip.Addr, platform.Route, int, probe.Flow) probe.Result
	tcp            func(context.Context, netip.Addr, platform.Route, int) probe.Result
	resolver       schedule.Resolver
	resolverPolicy string
	dnsPolicy      func(queryName string) map[string]any
}{capability: probe.EchoCapability, lookup: platform.LookupRoute, echo: probe.Echo, tcp: probe.TCP, echoFlow: probe.EchoFlow, dnsPolicy: platform.DNSPolicyDetails}

func init() {
	probes.resolver, probes.resolverPolicy = platform.SystemResolver()
}

var localCollectors = []func(context.Context, platform.Emit) error{platform.Interfaces, platform.Network, platform.Hosts, platform.Resolvers, platform.DNSCache}

// emitInputSnapshot records imported inputs so resume can verify them.
func (s *stream) emitInputSnapshot(seeds []importer.Seed, inventory []model.Event) error {
	for i, seed := range seeds {
		if err := s.emit(model.Event{Type: "input_seed", Details: map[string]any{"index": i, "seed": seed}}); err != nil {
			return err
		}
	}
	for i, item := range inventory {
		if err := s.emit(model.Event{Type: "input_inventory", Details: map[string]any{"index": i, "inventory": item}}); err != nil {
			return err
		}
	}
	h, _ := inputsHash(seeds, inventory)
	return s.emit(model.Event{Type: "inputs_finished", Details: map[string]any{"input_hash": h}})
}

// emitInputs turns seeds and inventory rows into observations for this segment.
func (s *stream) emitInputs(seeds []importer.Seed, inventory []model.Event) error {
	for _, seed := range seeds {
		e := model.Event{Type: "observation", Source: seed.Source, Name: seed.Name}
		if seed.Address.IsValid() {
			e.Address = seed.Address.String()
		}
		if err := s.emit(e); err != nil {
			return err
		}
	}
	for _, e := range inventory {
		if err := s.emit(e); err != nil {
			return err
		}
	}
	return nil
}

// startValidation records capabilities, builds the budgeted runner, starts the
// topology watch and resolves supplied names. The returned stop function is
// always non-nil.
func (s *stream) startValidation(ctx context.Context, c config, scope *liveScope, dnsCtx schedule.DNSContext, names []string) (*schedule.Runner, func(), error) {
	noop := func() {}
	noEcho, err := s.capabilities(c)
	if err != nil {
		return nil, noop, err
	}
	source := netip.Addr{}
	if c.Source != "" {
		source, _ = netip.ParseAddr(c.Source)
	}
	s.mu.Lock()
	left := max(c.MaxOperations-s.spent, 0)
	s.mu.Unlock()
	runner := &schedule.Runner{Config: schedule.Config{Rate: c.Rate, Concurrency: c.Concurrency, MaxOperations: left, Timeout: c.Timeout, Port: c.Port, Source: source, Interface: c.Interface, EnrichmentLimit: left / 2, DNSBudget: min(c.DNSBudget, left/2), TraceBudget: min(c.TraceBudget, left/2), NoEcho4: noEcho[0], NoEcho6: noEcho[1], NoIPv6: c.NoIPv6, Retry: c.Retry}, Lookup: probes.lookup, Echo: probes.echo, EchoFlow: probes.echoFlow, TCP: probes.tcp, Emit: s.emit, Reserve: s.reserve, Allow: scope.allow}
	stopWatch := s.watchTopology(ctx, c.Refresh, scope)
	if left > 0 && c.DNSBudget > 0 && len(names) > 0 {
		if _, err := runner.Forward(ctx, dnsCtx, names); err != nil {
			stopWatch()
			return nil, noop, err
		}
	}
	return runner, stopWatch, nil
}

func (s *stream) emitPlan(c config, planned discover.Scope, candidates []discover.Candidate, skips map[string]int, seeds []importer.Seed, names []string) error {
	return s.emit(model.Event{Type: "plan", ObservedAt: model.Now(), Details: map[string]any{"candidates": len(candidates), "synthetic_samples": countSynthetic(candidates), "skipped": skips, "include": planned.Include, "exclude": planned.Exclude, "unresolved_names": countNames(seeds), "dns_names_eligible": len(names), "intensity": c.Intensity, "neighbour_guesses": countNeighbours(candidates), "dns_budget": c.DNSBudget, "trace_destinations": c.Trace, "trace_budget": c.TraceBudget, "max_operations": c.MaxOperations, "network_operations": 0, "prediction": "candidate counts exclude later DNS answers; operations are not packets"}})
}

// validateAndEnrich probes candidates, then spends remaining enrichment budget
// on reverse DNS for responders and targeted traces.
func validateAndEnrich(ctx context.Context, c config, runner *schedule.Runner, dnsCtx schedule.DNSContext, candidates []discover.Candidate) (schedule.Summary, error) {
	validation, err := runner.Run(ctx, candidates)
	if err != nil {
		return validation, err
	}
	if c.DNSBudget > 0 && ctx.Err() == nil {
		var responders []netip.Addr
		for _, r := range runner.Results() {
			if r.Response {
				responders = append(responders, r.Target)
			}
		}
		if err := runner.Reverse(ctx, dnsCtx, responders); err != nil {
			return validation, err
		}
	}
	if c.Trace > 0 && ctx.Err() == nil {
		if err := runner.Trace(ctx, schedule.SelectTraceTargets(runner.Results(), c.Trace), c.TraceHops); err != nil {
			return validation, err
		}
	}
	return validation, nil
}

type finishInput struct {
	started    time.Time
	used       time.Duration
	active     bool
	validation schedule.Summary
	candidates []discover.Candidate
	skips      map[string]int
}

// stopOutcome is the precedence-ordered reason a run ended; later conditions
// override earlier ones.
type stopOutcome struct {
	validation          string
	dropped             int
	required            []string
	statuses            map[string]string
	deadline, interrupt bool
}

func (o stopOutcome) resolve() (code int, reason string) {
	code, reason = 0, "completed"
	if o.validation != "completed" {
		code, reason = 3, o.validation
	}
	if o.dropped > 0 {
		code, reason = 3, "capacity_exceeded"
	}
	for _, name := range o.required {
		if st := o.statuses[name]; st != "complete" && st != "available" {
			code, reason = 3, "required_capability_unavailable"
		}
	}
	if o.deadline {
		code, reason = 3, "duration_exhausted"
	}
	if o.interrupt {
		code, reason = 130, "interrupted"
	}
	return code, reason
}

// finish emits run_finished with coverage and writes the resume checkpoint.
func (s *stream) finish(parent, ctx context.Context, c config, runner *schedule.Runner, in finishInput) (int, error) {
	s.mu.Lock()
	streamErr := s.err
	totalSpent := s.spent
	s.mu.Unlock()
	if streamErr != nil {
		return 1, streamErr
	}
	validation := in.validation
	if in.active && validation.Untried > 0 && totalSpent >= c.MaxOperations {
		validation.StopReason = "operation_budget_exhausted"
	}
	code, reason := stopOutcome{validation: validation.StopReason, dropped: s.reducer.Dropped, required: c.Require, statuses: s.statuses, deadline: ctx.Err() != nil, interrupt: parent.Err() != nil}.resolve()
	// Read runner state before the stream lock: operation() holds the runner's
	// dispatch lock while reserving through the stream.
	var results []schedule.Result
	methods := map[string]int{}
	if runner != nil {
		results, methods = runner.Results(), runner.ByMethod()
	}
	s.mu.Lock()
	coverage := s.coverage(results, methods, in.candidates)
	epoch := s.epoch
	s.mu.Unlock()
	if err := s.emit(model.Event{Type: "run_finished", ObservedAt: model.Now(), Outcome: reason, Details: map[string]any{"stop_reason": reason, "elapsed_ms": time.Since(in.started).Milliseconds(), "total_elapsed_ns": int64(in.used + time.Since(in.started)), "findings": len(s.reducer.Findings), "known_prefixes": len(s.reducer.Prefixes), "candidate_addresses": len(in.candidates), "synthetic_samples": countSynthetic(in.candidates), "neighbour_guesses": countNeighbours(in.candidates), "intensity": c.Intensity, "untested_candidates": validation.Untried, "capacity_dropped": s.reducer.Dropped, "operations": totalSpent, "segment_operations": validation.Operations, "validation": validation, "collectors": s.statuses, "skipped": in.skips, "coverage": coverage, "routing_epochs": epoch, "journal": !c.NoJournal, "sync": c.Sync, "format": c.Format, "accounting_limitations": accountingLimitations}}); err != nil {
		return 1, err
	}
	if err := s.checkpoint(c); err != nil {
		return 1, err
	}
	return code, nil
}

func countNeighbours(candidates []discover.Candidate) int {
	n := 0
	for _, c := range candidates {
		if c.NeighbourOf != nil {
			n++
		}
	}
	return n
}

func countSynthetic(candidates []discover.Candidate) int {
	n := 0
	for _, c := range candidates {
		if c.Synthetic {
			n++
		}
	}
	return n
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
		if v6 && c.NoIPv6 {
			noEcho[i] = true
			if err := s.emit(model.Event{Type: "capability", Source: name, Outcome: "disabled", ObservedAt: model.Now()}); err != nil {
				return noEcho, err
			}
			continue
		}
		if err := probes.capability(v6); err != nil {
			outcome = "unavailable"
			details["error"] = err.Error()
			details["fallback"] = "tcp_connect"
			noEcho[i] = true
		}
		if err := s.emit(model.Event{Type: "capability", Source: name, Outcome: outcome, ObservedAt: model.Now(), Details: details}); err != nil {
			return noEcho, err
		}
	}
	dns := map[string]any{"policy": probes.resolverPolicy, "upstream": "unknown", "budget": c.DNSBudget}
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
		trace := map[string]any{"backend": "hop-limited ICMP echo", "hops": c.TraceHops, "budget": c.TraceBudget, "paris": probe.FlowStableTrace}
		outcome = "available"
		if err := probes.capability(false); err != nil {
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
