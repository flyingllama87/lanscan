package discover

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"lanscan/internal/model"
)

func TestSampleAddressesRespectPrefixSemantics(t *testing.T) {
	for _, test := range []struct {
		prefix string
		n      int
		want   []string
	}{
		{"10.1.1.0/24", 3, []string{"10.1.1.1", "10.1.1.254", "10.1.1.128"}},
		{"10.1.1.0/24", 1, []string{"10.1.1.1"}},
		{"10.1.1.0/30", 3, []string{"10.1.1.1", "10.1.1.2"}},
		{"10.1.1.4/31", 3, []string{"10.1.1.4", "10.1.1.5"}},
		{"10.1.1.9/32", 3, []string{"10.1.1.9"}},
		{"2001:db8::/64", 3, nil},
	} {
		var got []string
		for _, a := range SampleAddresses(netip.MustParsePrefix(test.prefix), test.n) {
			got = append(got, a.String())
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("%s/%d: got %v want %v", test.prefix, test.n, got, test.want)
		}
	}
}

func observe(t *testing.T, r *Reducer, seq int, e model.Event) {
	t.Helper()
	e.Type = "observation"
	e.RealmID = "corp"
	e.VantageID = "a"
	e.EventID = fmt.Sprintf("r:%d", seq)
	f := r.Observe(e)
	if f == nil {
		t.Fatal("no finding")
	}
	r.Commit(*f)
}

func TestSamplingOnlyWhereNoHostEvidenceAndUnicast(t *testing.T) {
	r := NewReducer(100)
	agg := netip.MustParsePrefix("10.0.0.0/8")
	lan := netip.MustParsePrefix("10.1.0.0/24")
	empty := netip.MustParsePrefix("10.2.0.0/24")
	hole := netip.MustParsePrefix("10.3.0.0/24")
	v6 := netip.MustParsePrefix("fd00::/64")
	observe(t, r, 1, model.Event{Source: "routes", Prefix: &agg, PrefixBasis: "route", Details: map[string]any{"route_type": "unicast"}})
	observe(t, r, 2, model.Event{Source: "routes", Prefix: &lan, PrefixBasis: "route", Details: map[string]any{"route_type": "unicast"}})
	observe(t, r, 3, model.Event{Source: "inventory", Prefix: &empty, PrefixBasis: "inventory"})
	observe(t, r, 4, model.Event{Source: "routes", Prefix: &hole, PrefixBasis: "route", Details: map[string]any{"route_type": "blackhole"}})
	observe(t, r, 5, model.Event{Source: "routes", Prefix: &v6, PrefixBasis: "route", Details: map[string]any{"route_type": "unicast"}})
	observe(t, r, 6, model.Event{Source: "neighbors", Address: "10.1.0.7"})
	scope := Scope{Include: []netip.Prefix{agg, v6}, SamplePerPrefix: 1}
	plan, _ := r.Plan(scope, "corp")
	var synthetic []string
	for _, c := range plan {
		if c.Synthetic {
			synthetic = append(synthetic, c.Prefix.String()+" "+c.Address.String())
		}
	}
	// The /8 and /24 contain host evidence, the blackhole is not unicast and
	// IPv6 is never enumerated: only the empty inventory subnet is sampled.
	if !reflect.DeepEqual(synthetic, []string{"10.2.0.0/24 10.2.0.1"}) {
		t.Fatalf("unexpected samples %v", synthetic)
	}
	scope.SamplePerPrefix = 0
	plan, _ = r.Plan(scope, "corp")
	for _, c := range plan {
		if c.Synthetic {
			t.Fatal("sampling enabled by default")
		}
	}
}

func TestPlanUsesMostSpecificPrefix(t *testing.T) {
	r := NewReducer(100)
	agg := netip.MustParsePrefix("10.0.0.0/8")
	lan := netip.MustParsePrefix("10.1.0.0/27")
	observe(t, r, 1, model.Event{Source: "routes", Prefix: &agg, PrefixBasis: "route"})
	observe(t, r, 2, model.Event{Source: "interfaces", Prefix: &lan, PrefixBasis: "interface"})
	observe(t, r, 3, model.Event{Source: "neighbors", Address: "10.1.0.9"})
	observe(t, r, 4, model.Event{Source: "neighbors", Address: "10.1.0.31"})
	plan, skipped := r.Plan(Scope{Include: []netip.Prefix{agg}}, "corp")
	if len(plan) != 1 || *plan[0].Prefix != lan || skipped["broadcast"] != 1 {
		t.Fatalf("%+v %v", plan, skipped)
	}
}

func TestDefaultRoutesDoNotGroupCandidates(t *testing.T) {
	r := NewReducer(100)
	unicast := map[string]any{"route_type": "unicast"}
	for i, p := range []string{"0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "::/0", "10.1.0.0/16"} {
		prefix := netip.MustParsePrefix(p)
		observe(t, r, i+1, model.Event{Source: "routes", Prefix: &prefix, PrefixBasis: "route", Details: unicast})
	}
	for i, a := range []string{"198.51.100.10", "198.51.100.11", "10.1.2.3", "2001:db8::1"} {
		observe(t, r, i+10, model.Event{Source: "seed", Address: a})
	}
	scope := Scope{Include: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}
	candidates, _ := r.Plan(scope, "corp")
	got := map[string]string{}
	for _, c := range candidates {
		got[c.Address.String()] = ""
		if c.Prefix != nil {
			got[c.Address.String()] = c.Prefix.String()
		}
	}
	want := map[string]string{"198.51.100.10": "", "198.51.100.11": "", "10.1.2.3": "10.1.0.0/16", "2001:db8::1": ""}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
