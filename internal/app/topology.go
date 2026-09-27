package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"lanscan/internal/discover"
	"lanscan/internal/model"
	"lanscan/internal/platform"
	"lanscan/internal/schedule"
)

// liveScope is the active scope for the current routing epoch. Route-derived
// scope is recomputed from the latest epoch's routes only, so a vanished VPN
// route stops granting scope to queued work.
type liveScope struct {
	mu         sync.Mutex
	base       discover.Scope
	fromRoutes bool
	scope      discover.Scope
}

// refresh must be called with no stream lock held.
func (l *liveScope) refresh(s *stream) {
	s.mu.Lock()
	var routes []netip.Prefix
	if l.fromRoutes {
		for _, e := range s.routes {
			if e.RoutingEpoch != s.epoch {
				continue
			}
			kind, _ := e.Details["route_type"].(string)
			if discover.RouteScope(*e.Prefix, kind) {
				routes = append(routes, *e.Prefix)
			}
		}
	}
	s.mu.Unlock()
	l.mu.Lock()
	defer l.mu.Unlock()
	next := l.base
	next.Include = append(append([]netip.Prefix(nil), l.base.Include...), routes...)
	l.scope = next
}

func (l *liveScope) current() discover.Scope {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.scope
}

func (l *liveScope) allow(c discover.Candidate) (bool, string) {
	ok, reason := l.current().Allows(c.Address)
	if !ok {
		return false, "scope_changed_" + reason
	}
	return true, ""
}

// topologyFingerprint hashes interface and route state, excluding volatile
// neighbor caches and timestamps. It emits nothing to the journal.
func topologyFingerprint(ctx context.Context) (string, error) {
	var mu sync.Mutex
	var lines []string
	capture := func(e model.Event) error {
		if e.Type != "observation" || (e.Source != "interfaces" && e.Source != "routes" && e.Source != "rules") {
			return nil
		}
		prefix := ""
		if e.Prefix != nil {
			prefix = e.Prefix.String()
		}
		d := map[string]any{}
		for _, k := range []string{"gateway", "route_type", "table", "metric", "rule", "flags"} {
			if v, ok := e.Details[k]; ok {
				d[k] = v
			}
		}
		mu.Lock()
		lines = append(lines, fmt.Sprint(e.Source, "|", prefix, "|", e.Address, "|", e.InterfaceID, "|", d))
		mu.Unlock()
		return nil
	}
	for _, fn := range []func(context.Context, platform.Emit) error{platform.Interfaces, platform.Network} {
		if err := fn(ctx, capture); err != nil {
			return "", err
		}
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// resolverFingerprint hashes resolver configuration so a changed upstream,
// suffix or per-link routing domain is recorded. It sends no queries.
func resolverFingerprint(ctx context.Context) (string, error) {
	var mu sync.Mutex
	var lines []string
	err := platform.Resolvers(ctx, func(e model.Event) error {
		if e.Type != "observation" {
			return nil
		}
		d, _ := json.Marshal(e.Details)
		mu.Lock()
		lines = append(lines, e.Address+"|"+e.InterfaceID+"|"+string(d))
		mu.Unlock()
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "\x00")))
	return hex.EncodeToString(h[:]), nil
}

// notifySettle coalesces the burst of messages one change produces, such as
// a VPN adding a link, addresses and routes.
const notifySettle = 200 * time.Millisecond

// watchTopology follows interface/route changes during active work. Platform
// notifications (rtnetlink, IP Helper) trigger an immediate check; polling
// every interval remains as the fallback. A change starts a new routing epoch,
// re-collects local evidence under it, and refreshes scope; the scheduler's
// per-dispatch route recheck and scope gate then skip stale work. Resolver
// configuration changes are recorded without a new epoch. Historical
// observations are retained.
func (s *stream) watchTopology(ctx context.Context, interval time.Duration, scope *liveScope) func() {
	if interval <= 0 {
		return func() {}
	}
	base, err := topologyFingerprint(ctx)
	if err != nil {
		return func() {}
	}
	resolvers, _ := resolverFingerprint(ctx)
	watchCtx, cancelWatch := context.WithCancel(ctx)
	notify, notifyErr := platform.WatchTopology(watchCtx)
	details := map[string]any{"poll_interval_ns": int64(interval), "detection": "notification_and_polling"}
	if notifyErr != nil {
		notify = nil
		details["detection"] = "polling"
		details["error"] = notifyErr.Error()
	}
	if err := s.emit(model.Event{Type: "capability", Source: "topology_watch", Outcome: "available", ObservedAt: model.Now(), Details: details}); err != nil {
		cancelWatch()
		return func() {}
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		defer cancelWatch()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			detection := "polling"
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
			case _, ok := <-notify:
				if !ok {
					notify = nil // socket failed; polling continues
					continue
				}
				detection = "notification"
				settle := time.NewTimer(notifySettle)
			coalesce:
				for {
					select {
					case <-stop:
						settle.Stop()
						return
					case <-ctx.Done():
						settle.Stop()
						return
					case _, ok := <-notify:
						if !ok {
							notify = nil
						}
					case <-settle.C:
						break coalesce
					}
				}
			}
			if next, err := resolverFingerprint(ctx); err == nil && next != resolvers {
				resolvers = next
				if err := s.emit(model.Event{Type: "resolver_change", ObservedAt: model.Now(), Details: map[string]any{"detection": detection}}); err != nil {
					return
				}
				if err := collect(ctx, s, []func(context.Context, platform.Emit) error{platform.Resolvers}); err != nil {
					return
				}
			}
			next, err := topologyFingerprint(ctx)
			if err != nil || next == base {
				continue
			}
			base = next
			s.mu.Lock()
			prior := s.epoch
			s.epoch++
			s.mu.Unlock()
			if err := s.emit(model.Event{Type: "routing_epoch", ObservedAt: model.Now(), Details: map[string]any{"reason": "topology_change", "prior_epoch": prior, "detection": detection, "race": "route changes between detection and dispatch remain possible; each dispatch rechecks the route"}}); err != nil {
				return
			}
			if err := collect(ctx, s, []func(context.Context, platform.Emit) error{platform.Interfaces, platform.Network}); err != nil {
				return
			}
			scope.refresh(s)
		}
	}()
	return func() { once.Do(func() { close(stop); <-done }) }
}

// coverage reports counts against explicit denominators only. Caller holds s.mu.
func (s *stream) coverage(results []schedule.Result, methods map[string]int, candidates []discover.Candidate) map[string]any {
	byBasis := make(map[string]map[string]bool)
	for _, f := range s.reducer.Prefixes {
		if byBasis[f.PrefixBasis] == nil {
			byBasis[f.PrefixBasis] = make(map[string]bool)
		}
		byBasis[f.PrefixBasis][f.Prefix.String()] = true
	}
	known := make(map[string]bool)
	basisCounts := make(map[string]int)
	for basis, set := range byBasis {
		basisCounts[basis] = len(set)
		for p := range set {
			known[p] = true
		}
	}
	responsive := make(map[string]bool)
	hosts := make(map[string]bool)
	activity := make(map[string]int)
	for _, f := range s.reducer.Findings {
		if f.Prefix != nil && f.Reachability == "endpoint_response" {
			responsive[f.Prefix.String()] = true
		}
		if f.Prefix == nil && f.Address != "" {
			hosts[f.Address] = true
			activity[f.ActivityBasis]++
		}
	}
	candidatePrefixes := make(map[string]bool)
	for _, c := range candidates {
		if c.Prefix != nil {
			candidatePrefixes[c.Prefix.String()] = true
		}
	}
	tested := make(map[string]bool)
	outcomes := map[string]int{}
	for _, r := range results {
		outcomes[r.Outcome]++
		if r.Group != "" && !strings.HasPrefix(r.Group, "host:") {
			tested[r.Group] = true
		}
	}
	untested := 0
	for p := range candidatePrefixes {
		if !tested[p] {
			untested++
		}
	}
	return map[string]any{
		"known_prefixes":                    len(known),
		"prefixes_by_basis":                 basisCounts,
		"prefixes_with_responding_target":   len(responsive),
		"prefixes_with_candidates":          len(candidatePrefixes),
		"candidate_prefixes_tested":         len(tested),
		"candidate_prefixes_untested":       untested,
		"known_prefixes_without_candidates": len(known) - len(candidatePrefixes),
		"observed_addresses":                len(hosts),
		"address_findings_by_activity":      activity,
		"operations_by_method":              methods,
		"latest_outcomes":                   outcomes,
		"denominator_note":                  "tested counts are relative to known prefixes and planned candidates; silence is unknown, not unused",
	}
}
