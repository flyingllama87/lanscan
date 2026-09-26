package schedule

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"lanscan/internal/importer"
	"lanscan/internal/model"
	"lanscan/internal/platform"
)

const (
	maxAnswersPerName = 8
	maxNamesPerAddr   = 4
	dnsInFlight       = 4
)

// Resolver is satisfied by *net.Resolver. Implementations must not fall back
// to public resolvers, multicast DNS, LLMNR or NetBIOS.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// DNSContext records which resolver policy produced naming evidence.
type DNSContext struct {
	Resolver Resolver
	// Policy is "system" (platform policy, upstream unknown) or "explicit".
	Policy   string
	Server   string
	Suffixes []string
}

// InSuffix reports whether name falls within an approved organisational suffix.
func InSuffix(name string, suffixes []string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, s := range suffixes {
		s = strings.ToLower(strings.Trim(s, "."))
		if s != "" && (name == s || strings.HasSuffix(name, "."+s)) {
			return true
		}
	}
	return false
}

func dnsOutcome(err error) string {
	var de *net.DNSError
	switch {
	case err == nil:
		return "answered"
	case errors.As(err, &de) && de.IsNotFound:
		return "nxdomain_or_nodata"
	case errors.As(err, &de) && de.IsTimeout, errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	return "error"
}

func (d DNSContext) details(operationID, query string) map[string]any {
	m := map[string]any{"operation_id": operationID, "query": query, "resolver_policy": d.Policy, "accounting": "one native lookup; resolver retries and recursion are opaque"}
	if d.Server != "" {
		m["resolver"] = d.Server
	} else {
		m["resolver"] = "unknown_upstream"
	}
	return m
}

func (r *Runner) boundedDNS(ctx context.Context, n int, work func(context.Context, int) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var first error
	for w := 0; w < dnsInFlight; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if err := work(ctx, i); err != nil {
					mu.Lock()
					if first == nil {
						first = err
					}
					mu.Unlock()
					cancel()
					return
				}
			}
		}()
	}
feed:
	for i := 0; i < n; i++ {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	return first
}

func stopError(err error) bool {
	return errors.Is(err, ErrBudget) || errors.Is(err, ErrEnrichmentBudget) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// Forward resolves supplied names once per address family. Answers are
// candidates only; scope and exclusions are applied afterwards by the planner.
func (r *Runner) Forward(ctx context.Context, dns DNSContext, names []string) (int, error) {
	if err := r.validConfig(); err != nil {
		return 0, err
	}
	r.init()
	var mu sync.Mutex
	answers := 0
	err := r.boundedDNS(ctx, len(names), func(ctx context.Context, i int) error {
		name := names[i]
		for _, family := range []string{"ip4", "ip6"} {
			if err := r.lookupForward(ctx, dns, name, family, "", func() bool {
				mu.Lock()
				defer mu.Unlock()
				if answers >= maxAnswersPerName*len(names) {
					return false
				}
				answers++
				return true
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if stopError(err) {
		err = nil
	}
	return answers, err
}

func (r *Runner) lookupForward(ctx context.Context, dns DNSContext, name, family, derivedFrom string, admit func() bool) error {
	operationID, err := model.NewRunID()
	if err != nil {
		return err
	}
	query := "A"
	if family == "ip6" {
		query = "AAAA"
	}
	if err := r.operation(ctx, "dns", "dns", model.Event{Protocol: "dns", Name: name, Details: map[string]any{"operation_id": operationID, "query": query}}); err != nil {
		return err
	}
	opCtx, cancel := context.WithTimeout(ctx, r.Config.Timeout*2)
	// A trailing dot prevents search-list expansion outside approved names.
	addrs, lookupErr := dns.Resolver.LookupNetIP(opCtx, family, strings.TrimSuffix(name, ".")+".")
	cancel()
	details := dns.details(operationID, query)
	if derivedFrom != "" {
		details["derived_from_ptr"] = derivedFrom
	}
	outcome := dnsOutcome(lookupErr)
	if lookupErr != nil {
		details["error"] = lookupErr.Error()
		return r.Emit(model.Event{Type: "observation", Source: "dns_forward", Name: name, Outcome: outcome, ObservedAt: model.Now(), Details: details})
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
	emitted := 0
	for _, a := range addrs {
		if emitted >= maxAnswersPerName || !admit() {
			details["truncated"] = true
			break
		}
		a = a.Unmap()
		if !a.IsValid() || a.IsUnspecified() {
			continue
		}
		d := make(map[string]any, len(details))
		for k, v := range details {
			d[k] = v
		}
		if err := r.Emit(model.Event{Type: "observation", Source: "dns_forward", Name: name, Address: a.String(), ActivityBasis: "dns", Reachability: "unknown", Outcome: outcome, ObservedAt: model.Now(), Details: d}); err != nil {
			return err
		}
		emitted++
	}
	if emitted == 0 {
		return r.Emit(model.Event{Type: "observation", Source: "dns_forward", Name: name, Outcome: "no_usable_answer", ObservedAt: model.Now(), Details: details})
	}
	return nil
}

// Reverse queries PTR names for known targets. Naming evidence never implies
// liveness. Names within approved suffixes are forward-confirmed once.
func (r *Runner) Reverse(ctx context.Context, dns DNSContext, targets []netip.Addr) error {
	if err := r.validConfig(); err != nil {
		return err
	}
	r.init()
	var mu sync.Mutex
	confirmed := make(map[string]bool)
	err := r.boundedDNS(ctx, len(targets), func(ctx context.Context, i int) error {
		target := targets[i]
		operationID, err := model.NewRunID()
		if err != nil {
			return err
		}
		if err := r.operation(ctx, "dns", "dns", model.Event{Protocol: "dns", Address: target.String(), Details: map[string]any{"operation_id": operationID, "query": "PTR"}}); err != nil {
			return err
		}
		opCtx, cancel := context.WithTimeout(ctx, r.Config.Timeout*2)
		names, lookupErr := dns.Resolver.LookupAddr(opCtx, target.WithZone("").String())
		cancel()
		details := dns.details(operationID, "PTR")
		if lookupErr != nil {
			details["error"] = lookupErr.Error()
			return r.Emit(model.Event{Type: "observation", Source: "dns_reverse", Address: target.String(), Outcome: dnsOutcome(lookupErr), ObservedAt: model.Now(), Details: details})
		}
		var valid []string
		for _, n := range names {
			n = strings.ToLower(strings.TrimSuffix(n, "."))
			if importer.ValidName(n) && len(valid) < maxNamesPerAddr {
				valid = append(valid, n)
			}
		}
		if len(valid) == 0 {
			return r.Emit(model.Event{Type: "observation", Source: "dns_reverse", Address: target.String(), Outcome: "no_usable_answer", ObservedAt: model.Now(), Details: details})
		}
		for _, n := range valid {
			if err := r.Emit(model.Event{Type: "observation", Source: "dns_reverse", Address: target.String(), Name: n, ActivityBasis: "dns", Reachability: "unknown", Outcome: "answered", ObservedAt: model.Now(), Details: details}); err != nil {
				return err
			}
		}
		for _, n := range valid {
			if !InSuffix(n, dns.Suffixes) {
				continue
			}
			mu.Lock()
			seen := confirmed[n]
			confirmed[n] = true
			mu.Unlock()
			if seen {
				continue
			}
			family := "ip4"
			if target.Is6() {
				family = "ip6"
			}
			if err := r.lookupForward(ctx, dns, n, family, target.String(), func() bool { return true }); err != nil {
				return err
			}
		}
		return nil
	})
	if stopError(err) {
		return nil
	}
	return err
}

// TraceTarget is an evidence-backed destination with its selected route.
type TraceTarget struct {
	Target netip.Addr
	Route  platform.Route
	Reason string
}

// SelectTraceTargets prefers routed responders on distinct egress paths, then
// unexplained path failures. It never selects discovered hops or on-link targets.
func SelectTraceTargets(results []Result, limit int) []TraceTarget {
	var out []TraceTarget
	paths := make(map[string]bool)
	chosen := make(map[netip.Addr]bool)
	for _, pass := range []string{"distinct_path_response", "path_failure"} {
		for _, res := range results {
			if len(out) >= limit {
				return out
			}
			// On-link destinations have no transit hops to reveal.
			if chosen[res.Target] || !res.Route.Gateway.IsValid() || res.Route.Gateway.IsUnspecified() {
				continue
			}
			path := res.Route.Interface + "/" + res.Route.Gateway.String()
			switch pass {
			case "distinct_path_response":
				if !res.Response || paths[path] {
					continue
				}
				paths[path] = true
			case "path_failure":
				if res.Response || (res.Outcome != "path_unreachable" && res.Outcome != "administratively_prohibited" && res.Outcome != "timeout") {
					continue
				}
			}
			chosen[res.Target] = true
			out = append(out, TraceTarget{Target: res.Target, Route: res.Route, Reason: pass})
		}
	}
	return out
}

// Trace sends one hop-limited echo per hop. It stops at the destination, a
// correlated terminal failure, the hop limit, or three consecutive silent hops.
// Responding hops are recorded but never expand scope or reveal masks.
func (r *Runner) Trace(ctx context.Context, targets []TraceTarget, maxHops int) error {
	if err := r.validConfig(); err != nil {
		return err
	}
	r.init()
	for _, t := range targets {
		stop, hops, err := r.traceOne(ctx, t, maxHops)
		if err != nil && !stopError(err) {
			return err
		}
		finished := model.Event{Type: "trace_finished", Address: t.Target.String(), InterfaceID: t.Route.Interface, SourceAddress: t.Route.Source.String(), Outcome: stop, ObservedAt: model.Now(), Details: map[string]any{"hops_sent": hops, "selection": t.Reason, "path_model": "hop-limited ICMP echo; ECMP, tunnels and asymmetric paths may hide or reorder hops"}}
		if emitErr := r.Emit(finished); emitErr != nil {
			return emitErr
		}
		if err != nil {
			return nil
		}
	}
	return nil
}

func (r *Runner) traceOne(ctx context.Context, t TraceTarget, maxHops int) (string, int, error) {
	silent := 0
	path := t.Route.Interface + "/" + t.Route.Gateway.String()
	for hop := 1; hop <= maxHops; hop++ {
		operationID, err := model.NewRunID()
		if err != nil {
			return "local_error", hop - 1, err
		}
		e := model.Event{Protocol: "trace", Address: t.Target.String(), SourceAddress: t.Route.Source.String(), InterfaceID: t.Route.Interface, Details: map[string]any{"operation_id": operationID, "hop_limit": hop}}
		if err := r.operation(ctx, "trace", path, e); err != nil {
			if errors.Is(err, ErrBudget) || errors.Is(err, ErrEnrichmentBudget) {
				return "budget_exhausted", hop - 1, err
			}
			return "interrupted", hop - 1, err
		}
		fresh, err := r.Lookup(t.Target, r.Config.Source, r.Config.Interface)
		if err != nil || fresh != t.Route {
			if emitErr := r.Emit(model.Event{Type: "observation", Source: "route_lookup", Address: t.Target.String(), Outcome: "route_changed", ObservedAt: model.Now(), Details: map[string]any{"operation_id": operationID}}); emitErr != nil {
				return "local_error", hop, emitErr
			}
			return "route_changed", hop, nil
		}
		opCtx, cancel := context.WithTimeout(ctx, r.timeout(path))
		res := r.Echo(opCtx, t.Target, t.Route, hop)
		cancel()
		ev := model.Event{Type: "observation", Source: "trace", SourceAddress: t.Route.Source.String(), InterfaceID: t.Route.Interface, Outcome: res.Outcome, Reachability: "unknown", ObservedAt: model.Now(), Details: map[string]any{"operation_id": operationID, "trace_target": t.Target.String(), "hop_limit": hop, "backend": res.Backend, "rtt_ns": res.RTT.Nanoseconds(), "icmp_type": res.ICMPType, "icmp_code": res.ICMPCode, "error": res.Error}}
		if res.Correlation != "" {
			ev.Details["correlation"] = res.Correlation
		}
		if res.Status != 0 {
			ev.Details["native_status"] = res.Status
		}
		if res.Responder != "" {
			if a, err := netip.ParseAddr(res.Responder); err == nil {
				ev.Address = a.String()
				ev.ActivityBasis = "transit_response"
			}
		}
		if res.Response {
			ev.Address = t.Target.String()
			ev.Reachability = "endpoint_response"
			ev.ActivityBasis = "active_response"
		}
		if err := r.Emit(ev); err != nil {
			return "local_error", hop, err
		}
		switch {
		case res.Response:
			return "destination_reached", hop, nil
		case res.Outcome == "path_unreachable" || res.Outcome == "administratively_prohibited":
			return "terminal_failure", hop, nil
		case res.Outcome == "unavailable" || res.Outcome == "local_error" || res.Outcome == "send_error":
			return "backend_unavailable", hop, nil
		case res.Outcome == "time_exceeded":
			silent = 0
		default:
			silent++
			if silent >= 3 {
				return "silent_hops", hop, nil
			}
		}
	}
	return "hop_limit", maxHops, nil
}
