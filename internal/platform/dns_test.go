package platform

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseResolvectlCache(t *testing.T) {
	out := []byte(`Scope protocol=dns interface=eth0:
    app.corp.example IN A 10.1.1.5
    app.corp.example IN AAAA fd00::5
    alias.corp.example IN CNAME app.corp.example
    bad IN A fd00::6
    x;rm IN A 10.1.1.6
Scope protocol=dns:
    global.example. IN A 192.0.2.1
`)
	got := ParseResolvectlCache(out)
	var s []string
	for _, r := range got {
		s = append(s, r.Name+" "+r.Address.String()+" "+r.Interface)
	}
	want := []string{"app.corp.example 10.1.1.5 eth0", "app.corp.example fd00::5 eth0", "global.example 192.0.2.1 "}
	if !reflect.DeepEqual(s, want) {
		t.Fatalf("got %q", s)
	}
}

// Captured from systemd 255.4 (Ubuntu 24.04) `resolvectl show-cache`.
func TestParseResolvectlCacheSystemd255(t *testing.T) {
	out := []byte("\x1b[0mScope protocol=dns ifindex=2 ifname=ens2\n" +
		"example.com IN AAAA 2606:4700:10::6814:179a\n" +
		"github.com IN A 4.237.22.38\n" +
		"one.one.one.one IN A 1.1.1.1\n" +
		"\n\x1b[0mScope protocol=dns\nNo entries.\n")
	got := ParseResolvectlCache(out)
	if len(got) != 3 {
		t.Fatalf("%+v", got)
	}
	for _, r := range got {
		if r.Interface != "ens2" {
			t.Fatalf("lost scope interface: %+v", r)
		}
	}
}

func TestParsePowerShellCache(t *testing.T) {
	got := ParsePowerShellCache([]byte("app.corp.example|1|10.1.1.5|300\r\nv6.corp.example|28|fd00::5|x\r\nmx|15|mail|1\r\nbad|1|fd00::1|3\r\n"))
	if len(got) != 2 || got[0].TTL != 300 || got[1].TTL != -1 || got[1].Address.String() != "fd00::5" {
		t.Fatalf("%+v", got)
	}
}

func TestParseResolvConf(t *testing.T) {
	c := ParseResolvConf(strings.NewReader("# comment\nnameserver 10.0.0.53\nnameserver ::ffff:10.0.0.54\nsearch corp.example. lab.corp.example\noptions ndots:2\nnameserver bogus\n"))
	if len(c.Nameservers) != 2 || c.Nameservers[1].String() != "10.0.0.54" || !reflect.DeepEqual(c.Search, []string{"corp.example", "lab.corp.example"}) {
		t.Fatalf("%+v", c)
	}
}

func FuzzCacheParsers(f *testing.F) {
	f.Add([]byte("Scope protocol=dns interface=eth0:\n a.b IN A 10.0.0.1\n"))
	f.Add([]byte("a.b|1|10.0.0.1|5\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, r := range append(ParseResolvectlCache(b), ParsePowerShellCache(b)...) {
			if !r.Address.IsValid() || !validDNSName(r.Name) {
				t.Fatalf("invalid record %+v", r)
			}
		}
	})
}
