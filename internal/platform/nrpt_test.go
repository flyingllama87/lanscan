package platform

import (
	"net/netip"
	"testing"
)

func TestMatchNRPT(t *testing.T) {
	rules := []NRPTRule{
		{Key: "all", Namespaces: []string{"."}},
		{Key: "corp", Namespaces: []string{".corp.example"}, Servers: []string{"10.0.0.53"}},
		{Key: "lab", Namespaces: []string{".lab.corp.example", ".other.test"}},
		{Key: "exact", Namespaces: []string{"host.lab.corp.example"}},
		{Key: "reverse", Namespaces: []string{".10.in-addr.arpa"}},
	}
	for _, tc := range []struct{ name, rule, ns string }{
		{"www.example.org.", "all", "."},
		{"corp.example", "corp", ".corp.example"},
		{"a.CORP.example.", "corp", ".corp.example"},
		{"a.lab.corp.example", "lab", ".lab.corp.example"},
		{"host.lab.corp.example.", "exact", "host.lab.corp.example"},
		{"x.other.test", "lab", ".other.test"},
		{"notcorp.example", "all", "."},
		{"4.3.2.10.in-addr.arpa.", "reverse", ".10.in-addr.arpa"},
	} {
		r, ns, ok := MatchNRPT(tc.name, rules)
		if !ok || r.Key != tc.rule || ns != tc.ns {
			t.Errorf("%s: got %q %q %v, want %q %q", tc.name, r.Key, ns, ok, tc.rule, tc.ns)
		}
	}
	if _, _, ok := MatchNRPT("a.example", rules[1:2]); ok {
		t.Error("matched outside every namespace")
	}
}

func TestReverseName(t *testing.T) {
	for addr, want := range map[string]string{
		"10.2.3.4":           "4.3.2.10.in-addr.arpa.",
		"::ffff:10.2.3.4":    "4.3.2.10.in-addr.arpa.",
		"2001:db8::567:89ab": "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
		"fe80::1%eth0":       "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
	} {
		if got := ReverseName(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: got %s want %s", addr, got, want)
		}
	}
}
