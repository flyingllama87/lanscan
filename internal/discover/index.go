package discover

import (
	"net/netip"
	"sort"

	"lanscan/internal/model"
)

// prefixIndex finds containing prefixes by probing each present prefix length,
// so lookups cost O(distinct lengths) rather than O(known prefixes).
type prefixIndex struct {
	byBits map[int]map[netip.Prefix]map[string]bool
	bits   []int
}

func (x *prefixIndex) add(p netip.Prefix, key string) {
	if x.byBits == nil {
		x.byBits = make(map[int]map[netip.Prefix]map[string]bool)
	}
	m := x.byBits[p.Bits()]
	if m == nil {
		m = make(map[netip.Prefix]map[string]bool)
		x.byBits[p.Bits()] = m
		x.bits = append(x.bits, p.Bits())
		sort.Sort(sort.Reverse(sort.IntSlice(x.bits)))
	}
	if m[p] == nil {
		m[p] = make(map[string]bool)
	}
	m[p][key] = true
}

// containing returns finding keys whose prefix contains a, most specific first.
func (x *prefixIndex) containing(a netip.Addr) []string {
	a = a.WithZone("")
	var out []string
	for _, bits := range x.bits {
		if bits > a.BitLen() {
			continue
		}
		p, err := a.Prefix(bits)
		if err != nil {
			continue
		}
		keys := x.byBits[bits][p]
		if len(keys) == 0 {
			continue
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		out = append(out, sorted...)
	}
	return out
}

func (r *Reducer) containing(realm string, a netip.Addr) []model.Event {
	var out []model.Event
	for _, key := range r.index.containing(a) {
		f := r.Prefixes[key]
		if f.RealmID == realm {
			out = append(out, f)
		}
	}
	return out
}
