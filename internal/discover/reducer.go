package discover

import (
	"fmt"
	"net/netip"
	"sort"

	"lanscan/internal/model"
)

type Candidate struct {
	Address     netip.Addr    `json:"address"`
	EvidenceIDs []string      `json:"evidence_ids"`
	InterfaceID string        `json:"interface_id,omitempty"`
	Prefix      *netip.Prefix `json:"prefix"`
	// Synthetic samples are explicitly enabled guesses inside a known prefix.
	Synthetic bool `json:"synthetic,omitempty"`
}

type Reducer struct {
	Limit      int
	Findings   map[string]model.Event
	Candidates map[string]Candidate
	Prefixes   map[string]model.Event
	Dropped    int
	// unicast records prefixes backed by at least one unicast route, so that
	// sampling never targets blackhole, reject, local or broadcast routes.
	unicast map[string]bool
	index   prefixIndex
}

func NewReducer(limit int) *Reducer {
	return &Reducer{Limit: limit, Findings: make(map[string]model.Event), Candidates: make(map[string]Candidate), Prefixes: make(map[string]model.Event), unicast: make(map[string]bool)}
}

// Observe returns a derived finding without inventing boundaries. The caller
// persists it before Commit so failed writes never publish unjournaled state.
func (r *Reducer) Observe(e model.Event) *model.Event {
	if e.Type != "observation" || (e.Prefix == nil && e.Address == "" && e.Name == "") {
		return nil
	}
	if e.Prefix != nil && e.Source == "routes" {
		if kind, _ := e.Details["route_type"].(string); kind == "unicast" {
			r.unicast[e.RealmID+"\x00"+e.Prefix.String()] = true
		}
	}
	f := e
	f.Type = "finding_upsert"
	f.EvidenceIDs = append([]string{e.EventID}, e.EvidenceIDs...)
	f.Details = nil
	f.Seq = 0
	f.EventID = ""
	f.Reachability = "unknown"
	if f.Prefix != nil {
		f.EntityID = fmt.Sprintf("%s:prefix:%s:%s", e.RealmID, e.Prefix, e.PrefixBasis)
	} else if f.Address != "" {
		f.EntityID = e.RealmID + ":address:" + e.Address
		f.PrefixBasis = "unknown"
	} else {
		f.EntityID = e.RealmID + ":name:" + e.Name
		f.PrefixBasis = "unknown"
	}
	if e.Reachability != "" {
		f.Reachability = e.Reachability
	}
	if f.ActivityBasis == "" {
		f.ActivityBasis = "unknown"
	}
	key := model.FindingKey(f)
	if old, ok := r.Findings[key]; ok {
		f.Revision = old.Revision + 1
	} else {
		if len(r.Findings) >= r.Limit {
			r.Dropped++
			return nil
		}
		f.Revision = 1
	}
	return &f
}

func (r *Reducer) Commit(f model.Event) {
	r.Findings[model.FindingKey(f)] = f
	if f.Prefix != nil && f.Source != "probe" {
		key := model.FindingKey(f)
		r.Prefixes[key] = f
		r.index.add(*f.Prefix, key)
	}
	if f.Address != "" {
		a, err := netip.ParseAddr(f.Address)
		if err != nil {
			return
		}
		if f.Zone != "" {
			a = a.WithZone(f.Zone)
		}
		key := f.RealmID + "\x00" + a.String() + "\x00" + f.InterfaceID
		if _, exists := r.Candidates[key]; !exists && len(r.Candidates) >= r.Limit {
			r.Dropped++
			return
		}
		r.Candidates[key] = Candidate{Address: a, EvidenceIDs: f.EvidenceIDs, InterfaceID: f.InterfaceID}
	}
}

func (r *Reducer) Plan(s Scope, realm string) ([]Candidate, map[string]int) {
	var out []Candidate
	skipped := make(map[string]int)
	keys := make([]string, 0, len(r.Candidates))
	for k := range r.Candidates {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	seen := make(map[string]bool)
	for _, key := range keys {
		c := r.Candidates[key]
		// Candidate keys begin with the exact realm plus a NUL delimiter.
		if len(key) < len(realm)+1 || key[:len(realm)+1] != realm+"\x00" {
			skipped["different_realm"]++
			continue
		}
		if ok, reason := s.Allows(c.Address); !ok {
			skipped[reason]++
			continue
		}
		if s.Interface != "" && c.InterfaceID != "" && c.InterfaceID != s.Interface {
			skipped["different_interface"]++
			continue
		}
		broadcast := false
		for _, f := range r.containing(realm, c.Address) {
			if c.Prefix == nil {
				p := *f.Prefix
				c.Prefix = &p
			}
			if f.PrefixBasis == "interface" && IsBroadcast(c.Address, *f.Prefix) {
				broadcast = true
			}
		}
		if broadcast {
			skipped["broadcast"]++
			continue
		}
		if seen[c.Address.String()] {
			continue
		}
		seen[c.Address.String()] = true
		out = append(out, c)
	}
	if s.SamplePerPrefix > 0 {
		out = append(out, r.samples(s, realm, out, seen, skipped)...)
	}
	return out, skipped
}

// samples adds explicitly enabled deterministic IPv4 guesses inside known
// prefixes that have no evidence-backed candidate. IPv6 is never enumerated.
func (r *Reducer) samples(s Scope, realm string, evidence []Candidate, seen map[string]bool, skipped map[string]int) []Candidate {
	// A prefix containing any evidence-backed candidate has host evidence.
	covered := make(map[string]bool)
	for _, c := range evidence {
		for _, f := range r.containing(realm, c.Address) {
			covered[f.Prefix.String()] = true
		}
	}
	keys := make([]string, 0, len(r.Prefixes))
	for k := range r.Prefixes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Candidate
	done := make(map[string]bool)
	for _, key := range keys {
		f := r.Prefixes[key]
		p := *f.Prefix
		if f.RealmID != realm || !p.Addr().Is4() || p.Bits() < 8 || covered[p.String()] || done[p.String()] {
			continue
		}
		if f.PrefixBasis == "route" && !r.unicast[realm+"\x00"+p.String()] {
			continue
		}
		if s.Interface != "" && f.InterfaceID != "" && f.InterfaceID != s.Interface {
			continue
		}
		done[p.String()] = true
		for _, a := range SampleAddresses(p, s.SamplePerPrefix) {
			if ok, reason := s.Allows(a); !ok {
				skipped["sample_"+reason]++
				continue
			}
			if seen[a.String()] {
				continue
			}
			seen[a.String()] = true
			prefix := p
			out = append(out, Candidate{Address: a, EvidenceIDs: f.EvidenceIDs, InterfaceID: f.InterfaceID, Prefix: &prefix, Synthetic: true})
		}
	}
	return out
}

// SampleAddresses returns up to n deterministic IPv4 addresses inside p: the
// first and last usable host, then the midpoint. /31 and /32 keep their
// point-to-point and host semantics rather than excluding network/broadcast.
func SampleAddresses(p netip.Prefix, n int) []netip.Addr {
	if !p.IsValid() || !p.Addr().Is4() || n <= 0 {
		return nil
	}
	p = p.Masked()
	b := p.Addr().As4()
	base := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	size := uint64(1) << (32 - p.Bits())
	var offsets []uint64
	switch p.Bits() {
	case 32:
		offsets = []uint64{0}
	case 31:
		offsets = []uint64{0, 1}
	default:
		offsets = []uint64{1, size - 2, size / 2}
	}
	var out []netip.Addr
	seen := make(map[uint64]bool)
	for _, o := range offsets {
		if len(out) >= n || seen[o] {
			continue
		}
		seen[o] = true
		v := base + uint32(o)
		out = append(out, netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}))
	}
	return out
}

// ResponsePrefixes associates an actual response only with evidenced containing
// prefixes. It retains the original boundary evidence and never subdivides it.
func (r *Reducer) ResponsePrefixes(e model.Event) []model.Event {
	if e.Type != "observation" || e.Reachability != "endpoint_response" || e.Prefix != nil {
		return nil
	}
	a, err := netip.ParseAddr(e.Address)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []model.Event
	for _, known := range r.containing(e.RealmID, a) {
		if known.InterfaceID != "" && e.InterfaceID != "" && known.InterfaceID != e.InterfaceID {
			continue
		}
		key := known.Prefix.String() + ":" + known.PrefixBasis
		if seen[key] {
			continue
		}
		seen[key] = true
		derived := e
		derived.Prefix = known.Prefix
		derived.PrefixBasis = known.PrefixBasis
		derived.EvidenceIDs = known.EvidenceIDs
		out = append(out, derived)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Prefix.String()+out[i].PrefixBasis < out[j].Prefix.String()+out[j].PrefixBasis
	})
	return out
}
