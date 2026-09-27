// Package schedule owns application-operation limits and cancellation.
package schedule

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"

	"lanscan/internal/discover"
	"lanscan/internal/model"
	"lanscan/internal/platform"
	"lanscan/internal/probe"
)

var (
	ErrBudget           = errors.New("operation budget exhausted")
	ErrEnrichmentBudget = errors.New("enrichment budget exhausted")
)

const (
	minAdaptiveTimeout = 250 * time.Millisecond
	maxAdaptiveTimeout = 3 * time.Second
)

type Config struct {
	Rate          float64
	Concurrency   int
	MaxOperations int
	Timeout       time.Duration
	Port          int
	Source        netip.Addr
	Interface     string
	// PathRate limits starts per egress interface/next hop; zero means 5/second.
	PathRate float64
	// EnrichmentLimit caps DNS and trace operations so they cannot starve
	// validation. Zero disables enrichment.
	EnrichmentLimit int
	DNSBudget       int
	// DNSRate limits DNS exchange starts; zero means 2/second.
	DNSRate float64
	// TraceBudget caps hop-limited trace operations.
	TraceBudget int
	// NoEcho4/NoEcho6 record that the echo capability probe failed, so no
	// operation budget is reserved for attempts that cannot send.
	NoEcho4, NoEcho6 bool
	// NoIPv6 skips IPv6 targets and AAAA lookups.
	NoIPv6 bool
	// Retry grants each silent target at most one more attempt, after every
	// first attempt. Zero disables retries.
	Retry int
}

type Summary struct {
	Operations int            `json:"operations"`
	Tested     int            `json:"tested"`
	Responded  int            `json:"responded"`
	Untried    int            `json:"untried"`
	Synthetic  int            `json:"synthetic_tested"`
	Retried    int            `json:"retried"`
	Skipped    map[string]int `json:"skipped"`
	StopReason string         `json:"stop_reason"`
}

// Result is the last validation outcome for a target; it selects trace targets.
type Result struct {
	Target   netip.Addr
	Route    platform.Route
	Outcome  string
	Response bool
	Group    string
}

type Runner struct {
	Config Config
	Lookup func(netip.Addr, netip.Addr, string) (platform.Route, error)
	Echo   func(context.Context, netip.Addr, platform.Route, int) probe.Result
	// EchoFlow sends trace probes on one stable flow. When nil it defaults to
	// probe.EchoFlow, or to Echo (without flow stability) if Echo was supplied.
	EchoFlow func(context.Context, netip.Addr, platform.Route, int, probe.Flow) probe.Result
	TCP      func(context.Context, netip.Addr, platform.Route, int) probe.Result
	// Allow rechecks scope immediately before a job starts, e.g. after a routing
	// epoch change removed route-derived scope. Nil allows every planned target.
	Allow func(discover.Candidate) (bool, string)
	Emit  func(model.Event) error
	// Reserve must sync the operation reservation before a packet can be sent.
	Reserve      func(model.Event) error
	once         sync.Once
	mu           sync.Mutex
	dispatch     sync.Mutex
	nextGlobal   time.Time
	nextDNS      time.Time
	paths        map[string]time.Time
	rtt          map[string]time.Duration
	failures     map[string]int
	spent        int
	enrichSpent  int
	dnsSpent     int
	traceSpent   int
	byMethod     map[string]int
	prefixCounts map[string]int
	positive     map[string]bool
	results      map[netip.Addr]Result
	summary      Summary
	retries      []discover.Candidate
}

func (r *Runner) init() {
	r.once.Do(func() {
		if r.Lookup == nil {
			r.Lookup = platform.LookupRoute
		}
		if r.EchoFlow == nil {
			if echo := r.Echo; echo != nil {
				r.EchoFlow = func(ctx context.Context, t netip.Addr, route platform.Route, hops int, _ probe.Flow) probe.Result {
					return echo(ctx, t, route, hops)
				}
			} else {
				r.EchoFlow = probe.EchoFlow
			}
		}
		if r.Echo == nil {
			r.Echo = probe.Echo
		}
		if r.TCP == nil {
			r.TCP = probe.TCP
		}
		r.paths = make(map[string]time.Time)
		r.rtt = make(map[string]time.Duration)
		r.failures = make(map[string]int)
		r.byMethod = make(map[string]int)
		r.prefixCounts = make(map[string]int)
		r.positive = make(map[string]bool)
		r.results = make(map[netip.Addr]Result)
	})
}

// Spent reports all operation reservations made through this runner.
func (r *Runner) Spent() int { r.dispatch.Lock(); defer r.dispatch.Unlock(); return r.spent }

// ByMethod reports reservations by method, including DNS and trace hops.
func (r *Runner) ByMethod() map[string]int {
	r.dispatch.Lock()
	defer r.dispatch.Unlock()
	out := make(map[string]int, len(r.byMethod))
	for k, v := range r.byMethod {
		out[k] = v
	}
	return out
}

func (r *Runner) pathInterval(path string) time.Duration {
	rate := r.Config.PathRate
	if rate <= 0 {
		rate = 5
	}
	interval := time.Duration(float64(time.Second) / rate)
	r.mu.Lock()
	failures := r.failures[path]
	r.mu.Unlock()
	// Repeated loss or path errors back off the path, up to eight times slower.
	for shift := failures / 3; shift > 0 && interval < 8*time.Duration(float64(time.Second)/rate); shift-- {
		interval *= 2
	}
	return interval
}

// Serialize dispatch pacing so a delay at one limiter cannot accumulate credits
// at another and release an excessive burst. This is conservatively burst-free.
func (r *Runner) operation(ctx context.Context, class, path string, e model.Event) error {
	r.dispatch.Lock()
	defer r.dispatch.Unlock()
	if r.spent >= r.Config.MaxOperations {
		return ErrBudget
	}
	if class != "probe" && r.enrichSpent >= r.Config.EnrichmentLimit {
		return ErrEnrichmentBudget
	}
	if class == "dns" && r.dnsSpent >= r.Config.DNSBudget {
		return ErrEnrichmentBudget
	}
	if class == "trace" && r.traceSpent >= r.Config.TraceBudget {
		return ErrEnrichmentBudget
	}
	// DNS exchanges use their own rate rather than an egress path bucket.
	next := r.nextGlobal
	if class != "dns" && r.paths[path].After(next) {
		next = r.paths[path]
	}
	if class == "dns" && r.nextDNS.After(next) {
		next = r.nextDNS
	}
	if delay := time.Until(next); delay > 0 {
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	e.Type = "operation_reserved"
	e.ObservedAt = model.Now()
	if err := r.Reserve(e); err != nil {
		return err
	}
	now := time.Now()
	r.nextGlobal = now.Add(time.Duration(float64(time.Second) / r.Config.Rate))
	if class != "dns" {
		r.paths[path] = now.Add(r.pathInterval(path))
	}
	if class == "dns" {
		rate := r.Config.DNSRate
		if rate <= 0 {
			rate = 2
		}
		r.nextDNS = now.Add(time.Duration(float64(time.Second) / rate))
		r.dnsSpent++
	}
	if class == "trace" {
		r.traceSpent++
	}
	if class != "probe" {
		r.enrichSpent++
	}
	r.spent++
	r.byMethod[e.Protocol]++
	return nil
}

// timeout adapts to observed path RTT but never exceeds the configured deadline.
func (r *Runner) timeout(path string) time.Duration {
	r.mu.Lock()
	srtt := r.rtt[path]
	r.mu.Unlock()
	t := r.Config.Timeout
	if srtt <= 0 {
		return t
	}
	adaptive := 4 * srtt
	if adaptive < minAdaptiveTimeout {
		adaptive = minAdaptiveTimeout
	}
	if adaptive > maxAdaptiveTimeout {
		adaptive = maxAdaptiveTimeout
	}
	if adaptive < t {
		return adaptive
	}
	return t
}

func (r *Runner) observe(path string, result probe.Result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if result.Response || result.Outcome == "time_exceeded" {
		r.failures[path] = 0
		if result.RTT > 0 {
			if old := r.rtt[path]; old > 0 {
				r.rtt[path] = (7*old + result.RTT) / 8
			} else {
				r.rtt[path] = result.RTT
			}
		}
		return
	}
	if result.Outcome == "timeout" || result.Outcome == "path_unreachable" || result.Outcome == "administratively_prohibited" {
		r.failures[path]++
	}
}

func candidateGroup(c discover.Candidate) string {
	if c.Prefix != nil {
		return c.Prefix.String()
	}
	return "host:" + c.Address.String()
}

// breadthFirst interleaves known prefixes before considering extra hosts.
// Synthetic samples follow every evidence-backed candidate.
func breadthFirst(candidates []discover.Candidate) []discover.Candidate {
	var evidence, synthetic []discover.Candidate
	for _, c := range candidates {
		if c.Synthetic {
			synthetic = append(synthetic, c)
		} else {
			evidence = append(evidence, c)
		}
	}
	return append(interleave(evidence), interleave(synthetic)...)
}

func interleave(candidates []discover.Candidate) []discover.Candidate {
	groups := make(map[string][]discover.Candidate)
	var keys []string
	for _, c := range candidates {
		k := candidateGroup(c)
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], c)
	}
	sort.Strings(keys)
	keys = acrossInterfaces(keys, groups)
	out := make([]discover.Candidate, 0, len(candidates))
	for round := 0; round < 3; round++ {
		for _, key := range keys {
			if round < len(groups[key]) {
				out = append(out, groups[key][round])
			}
		}
	}
	return out
}

// acrossInterfaces reorders group keys round-robin by the evidence interface
// of each group, so one interface with many prefixes cannot fill the front of
// the queue. Groups without interface evidence share one turn.
func acrossInterfaces(keys []string, groups map[string][]discover.Candidate) []string {
	byInterface := make(map[string][]string)
	var interfaces []string
	for _, k := range keys {
		i := groups[k][0].InterfaceID
		if _, ok := byInterface[i]; !ok {
			interfaces = append(interfaces, i)
		}
		byInterface[i] = append(byInterface[i], k)
	}
	if len(interfaces) < 2 {
		return keys
	}
	sort.Strings(interfaces)
	out := make([]string, 0, len(keys))
	for turn := 0; len(out) < len(keys); turn++ {
		for _, i := range interfaces {
			if turn < len(byInterface[i]) {
				out = append(out, byInterface[i][turn])
			}
		}
	}
	return out
}

func (r *Runner) validConfig() error {
	c := r.Config
	if c.Rate <= 0 || c.Concurrency <= 0 || c.MaxOperations <= 0 || c.Timeout <= 0 || c.Port < 1 || c.Port > 65535 {
		return errors.New("invalid scheduler configuration")
	}
	if r.Emit == nil || r.Reserve == nil {
		return errors.New("event sinks required")
	}
	return nil
}

func (r *Runner) Run(parent context.Context, candidates []discover.Candidate) (Summary, error) {
	if err := r.validConfig(); err != nil {
		return Summary{}, err
	}
	r.init()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	before := r.Spent()
	r.summary = Summary{Skipped: make(map[string]int), StopReason: "completed"}
	r.retries = nil
	firstErr := r.runJobs(ctx, cancel, breadthFirst(candidates), false)
	// Retries follow every first attempt, so they never delay planned work.
	if firstErr == nil && ctx.Err() == nil && r.Config.Retry > 0 {
		r.mu.Lock()
		retries := r.retries
		r.retries = nil
		r.mu.Unlock()
		firstErr = r.runJobs(ctx, cancel, retries, true)
	}
	r.summary.Operations = r.Spent() - before
	r.summary.Untried = len(candidates) - r.summary.Tested
	if errors.Is(firstErr, ErrBudget) {
		r.summary.StopReason = "operation_budget_exhausted"
		firstErr = nil
	} else if parent.Err() != nil && (firstErr == nil || errors.Is(firstErr, context.Canceled) || errors.Is(firstErr, context.DeadlineExceeded)) {
		r.summary.StopReason = "duration_or_interrupt"
		firstErr = nil
	}
	return r.summary, firstErr
}

// runJobs runs candidates on the worker pool in order and returns the first
// error, after which remaining work is canceled.
func (r *Runner) runJobs(ctx context.Context, cancel context.CancelFunc, ordered []discover.Candidate, retry bool) error {
	jobs := make(chan job)
	var wg sync.WaitGroup
	var firstErr error
	for i := 0; i < r.Config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					close(j.done)
					return
				}
				if err := r.validate(ctx, j); err != nil {
					r.mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					r.mu.Unlock()
					cancel()
					return
				}
			}
		}()
	}
	// Each job's first attempt waits for its predecessor's, so planned
	// priority survives variable route-lookup latency across workers.
	prev := make(chan struct{})
	close(prev)
loop:
	for _, candidate := range ordered {
		j := job{candidate: candidate, turn: prev, done: make(chan struct{}), retry: retry}
		select {
		case jobs <- j:
			prev = j.done
		case <-ctx.Done():
			break loop
		}
	}
	close(jobs)
	wg.Wait()
	return firstErr
}

func (r *Runner) skip(reason string) { r.mu.Lock(); r.summary.Skipped[reason]++; r.mu.Unlock() }

type job struct {
	candidate discover.Candidate
	turn      <-chan struct{}
	done      chan struct{}
	retry     bool
}

func (r *Runner) validate(ctx context.Context, j job) error {
	var once sync.Once
	release := func() { once.Do(func() { close(j.done) }) }
	defer release()
	select {
	case <-j.turn:
	case <-ctx.Done():
		return nil
	}
	candidate := j.candidate
	group := candidateGroup(candidate)
	r.mu.Lock()
	switch {
	case j.retry && r.positive[group]:
		r.summary.Skipped["retry_prefix_satisfied"]++
		r.mu.Unlock()
		return nil
	case !j.retry && (r.positive[group] || r.prefixCounts[group] >= 3):
		r.summary.Skipped["prefix_satisfied_or_sample_limit"]++
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()
	if r.Allow != nil {
		if ok, reason := r.Allow(candidate); !ok {
			r.skip(reason)
			return nil
		}
	}
	target := candidate.Address
	echoOK := !(target.Is4() && r.Config.NoEcho4) && !(target.Is6() && r.Config.NoEcho6)
	methods := []string{"icmp", "tcp"}
	if j.retry {
		// One more attempt: echo when available, since it holds no connection state.
		methods = methods[:1]
		if !echoOK {
			methods = []string{"tcp"}
		}
	} else {
		r.mu.Lock()
		r.prefixCounts[group]++
		r.mu.Unlock()
	}
	tested := j.retry
	attempted, silent := false, true
	for _, method := range methods {
		if method == "icmp" && !echoOK {
			r.skip("icmp_unavailable")
			continue
		}
		route, err := r.Lookup(target, r.Config.Source, r.Config.Interface)
		if err != nil {
			r.skip("route_lookup_failed")
			return r.Emit(model.Event{Type: "observation", Address: target.String(), Source: "route_lookup", Outcome: "local_route_failure", ObservedAt: model.Now(), Details: map[string]any{"error": err.Error()}})
		}
		if route.Source.WithZone("") == target.WithZone("") {
			r.skip("local_address")
			return nil
		}
		operationID, err := model.NewRunID()
		if err != nil {
			return err
		}
		path := route.Interface + "/" + route.Gateway.String()
		e := model.Event{Details: map[string]any{"operation_id": operationID}, Address: target.String(), Source: "probe", SourceAddress: route.Source.String(), InterfaceID: route.Interface, Protocol: method, EvidenceIDs: candidate.EvidenceIDs}
		if candidate.Synthetic {
			e.Details["synthetic_sample"] = true
		}
		if candidate.NeighbourOf != nil {
			e.Details["neighbour_of"] = candidate.NeighbourOf.String()
		}
		if j.retry {
			e.Details["retry"] = true
		}
		if method == "tcp" {
			e.Port = r.Config.Port
		}
		err = r.operation(ctx, "probe", path, e)
		release()
		if err != nil {
			return err
		}
		fresh, err := r.Lookup(target, r.Config.Source, r.Config.Interface)
		if err != nil || fresh != route {
			r.skip("route_changed_before_dispatch")
			return r.Emit(model.Event{Type: "observation", Source: "route_lookup", Address: target.String(), Outcome: "route_changed", ObservedAt: model.Now(), Details: map[string]any{"operation_id": operationID}})
		}
		if !tested {
			r.mu.Lock()
			r.summary.Tested++
			if candidate.Synthetic {
				r.summary.Synthetic++
			}
			r.mu.Unlock()
			tested = true
		}
		timeout := r.timeout(path)
		opCtx, cancel := context.WithTimeout(ctx, timeout)
		var result probe.Result
		if method == "icmp" {
			result = r.Echo(opCtx, target, route, 0)
		} else {
			result = r.TCP(opCtx, target, route, r.Config.Port)
		}
		cancel()
		r.observe(path, result)
		e.Type = "observation"
		e.ObservedAt = model.Now()
		e.Outcome = result.Outcome
		e.Reachability = "unknown"
		e.Details = map[string]any{"operation_id": operationID, "backend": result.Backend, "error": result.Error, "rtt_ns": result.RTT.Nanoseconds(), "timeout_ns": timeout.Nanoseconds(), "responder": result.Responder, "icmp_type": result.ICMPType, "icmp_code": result.ICMPCode, "responder_identity": "address_or_middlebox"}
		if result.Status != 0 {
			e.Details["native_status"] = result.Status
		}
		if result.Correlation != "" {
			e.Details["correlation"] = result.Correlation
		}
		if candidate.Synthetic {
			e.Details["synthetic_sample"] = true
		}
		if candidate.NeighbourOf != nil {
			e.Details["neighbour_of"] = candidate.NeighbourOf.String()
		}
		if j.retry {
			e.Details["retry"] = true
		}
		attempted = true
		if j.retry {
			r.mu.Lock()
			r.summary.Retried++
			r.mu.Unlock()
		}
		if result.Outcome != "timeout" {
			silent = false
		}
		if result.Response {
			e.Reachability = "endpoint_response"
			e.ActivityBasis = "active_response"
		}
		if err := r.Emit(e); err != nil {
			return err
		}
		r.mu.Lock()
		r.results[target] = Result{Target: target, Route: route, Outcome: result.Outcome, Response: result.Response, Group: group}
		r.mu.Unlock()
		if result.Response {
			r.mu.Lock()
			r.summary.Responded++
			r.positive[group] = true
			r.mu.Unlock()
			return nil
		}
	}
	// Only silence is retried; an ICMP error or refusal is already an answer.
	if !j.retry && attempted && silent && r.Config.Retry > 0 {
		r.mu.Lock()
		r.retries = append(r.retries, candidate)
		r.mu.Unlock()
	}
	return nil
}

// Results returns the latest validation outcome per target in address order.
func (r *Runner) Results() []Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Result, 0, len(r.results))
	for _, v := range r.results {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target.Less(out[j].Target) })
	return out
}
