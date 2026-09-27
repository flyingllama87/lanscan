package discover

import (
	"net/netip"
	"testing"

	"lanscan/internal/model"
)

func TestScopeExclusionsAndSpecialAddresses(t *testing.T) {
	s := Scope{Include: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}, Exclude: []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16")}}
	for _, test := range []struct {
		ip   string
		want bool
	}{{"10.1.2.3", true}, {"10.2.3.4", false}, {"127.0.0.1", false}, {"224.0.0.1", false}, {"::", false}, {"::1", false}, {"ff02::1", false}, {"fe80::1", false}, {"fe80::1%eth0", false}, {"2001:db8::1", true}, {"::ffff:10.2.3.4", false}} {
		got, _ := s.Allows(netip.MustParseAddr(test.ip))
		if got != test.want {
			t.Errorf("%s: %v", test.ip, got)
		}
	}
	s.Interface = "eth0"
	if ok, _ := s.Allows(netip.MustParseAddr("fe80::1%eth0")); !ok {
		t.Fatal("explicit zoned target rejected")
	}
	if ok, _ := s.Allows(netip.MustParseAddr("fe80::1%eth1")); ok {
		t.Fatal("wrong interface accepted")
	}
}

func TestRouteScopeDoesNotGrantAggregatesOutsidePrivateSpace(t *testing.T) {
	for _, test := range []struct {
		prefix string
		want   bool
	}{{"0.0.0.0/0", false}, {"0.0.0.0/1", false}, {"128.0.0.0/1", false}, {"10.0.0.0/7", false}, {"10.0.0.0/8", true}, {"172.16.0.0/12", true}, {"192.168.0.0/16", true}, {"fc00::/7", true}, {"fc00::/6", false}, {"100.64.0.0/10", false}} {
		p := netip.MustParsePrefix(test.prefix)
		if got := RouteScope(p, "unicast"); got != test.want {
			t.Errorf("%s = %v", p, got)
		}
		if RouteScope(p, "blackhole") {
			t.Errorf("blackhole grants scope: %s", p)
		}
	}
}

func TestPrivateSpaceScope(t *testing.T) {
	s := Scope{Include: PrivateSpace}
	for _, test := range []struct {
		addr string
		want bool
	}{{"10.1.2.3", true}, {"172.31.0.1", true}, {"172.32.0.1", false}, {"192.168.9.9", true}, {"fd00::1", true}, {"100.64.0.1", false}, {"8.8.8.8", false}, {"2001:db8::1", false}} {
		if got, _ := s.Allows(netip.MustParseAddr(test.addr)); got != test.want {
			t.Errorf("%s = %v", test.addr, got)
		}
	}
	s.NoIPv6 = true
	if ok, reason := s.Allows(netip.MustParseAddr("fd00::1")); ok || reason != "ipv6_disabled" {
		t.Fatal(ok, reason)
	}
}

func TestBroadcastSmallPrefixes(t *testing.T) {
	a := netip.MustParseAddr("10.1.1.31")
	if !IsBroadcast(a, netip.MustParsePrefix("10.1.1.0/27")) {
		t.Fatal("missed /27 broadcast")
	}
	if IsBroadcast(a, netip.MustParsePrefix("10.1.1.30/31")) {
		t.Fatal("/31 endpoint is not broadcast")
	}
	if IsBroadcast(a, netip.MustParsePrefix("10.1.1.31/32")) {
		t.Fatal("host prefix is not broadcast")
	}
}

func TestHostObservationNeverInventsPrefix(t *testing.T) {
	r := NewReducer(10)
	e := model.Event{Type: "observation", Address: "10.24.7.19", RealmID: "corp", VantageID: "office", EventID: "r:1", Source: "neighbors", ActivityBasis: "cache"}
	f := r.Observe(e)
	if f == nil || f.Prefix != nil || f.PrefixBasis != "unknown" || f.Reachability != "unknown" {
		t.Fatalf("invented evidence: %+v", f)
	}
	r.Commit(*f)
	p := netip.MustParsePrefix("10.0.0.0/8")
	route := r.Observe(model.Event{Type: "observation", Prefix: &p, PrefixBasis: "route", RealmID: "corp", VantageID: "office", EventID: "r:2"})
	r.Commit(*route)
	plan, _ := r.Plan(Scope{Include: []netip.Prefix{p}}, "corp")
	if len(plan) != 1 || *plan[0].Prefix != p {
		t.Fatalf("unexpected plan %+v", plan)
	}
	if f.Prefix != nil {
		t.Fatal("plan mutated original host evidence")
	}
	other, _ := r.Plan(Scope{Include: []netip.Prefix{p}}, "other")
	if len(other) != 0 {
		t.Fatal("cross-realm candidate")
	}
}

func TestResponseAssociatesOnlyEvidenceBackedPrefixes(t *testing.T) {
	r := NewReducer(100)
	p := netip.MustParsePrefix("10.0.0.0/8")
	f := r.Observe(model.Event{Type: "observation", EventID: "r:1", RealmID: "corp", VantageID: "a", Prefix: &p, PrefixBasis: "route", Source: "routes"})
	r.Commit(*f)
	e := model.Event{Type: "observation", EventID: "r:2", RealmID: "corp", VantageID: "a", Address: "10.24.7.19", Source: "probe", Protocol: "tcp", Reachability: "endpoint_response", ActivityBasis: "active_response"}
	associated := r.ResponsePrefixes(e)
	if len(associated) != 1 || *associated[0].Prefix != p {
		t.Fatalf("%+v", associated)
	}
	result := r.Observe(associated[0])
	if len(result.EvidenceIDs) != 2 || result.EvidenceIDs[0] != "r:2" || result.EvidenceIDs[1] != "r:1" {
		t.Fatalf("lost provenance: %+v", result)
	}
	e.Reachability = "unknown"
	if len(r.ResponsePrefixes(e)) != 0 {
		t.Fatal("timeout promoted to prefix reachability")
	}
}
