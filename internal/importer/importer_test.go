package importer

import (
	"os"
	"path/filepath"
	"testing"
)

func input(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(p, []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestSeedsAndLimits(t *testing.T) {
	seeds, err := Seeds(input(t, "# comment\n10.1.2.3\nHOST.example.\nfe80::1%eth0\n"), 3)
	if err != nil || len(seeds) != 3 || seeds[1].Name != "host.example" {
		t.Fatalf("%v %v", seeds, err)
	}
	for _, bad := range []string{"bad;command\n", "a..b\n", "-host\n", "999.1.1.1/24\n"} {
		if _, err := Seeds(input(t, bad), 10); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := Seeds(input(t, "10.1.1.1\n10.1.1.2\n"), 1); err == nil {
		t.Fatal("ignored item limit")
	}
}
func TestInventoryPreservesBasisAndFreshness(t *testing.T) {
	events, err := Inventory(input(t, "realm,prefix,kind,source,observed_at\ncorp,10.2.3.4/27,subnet,ipam,\n"), 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("%v %v", events, err)
	}
	e := events[0]
	if e.Prefix.String() != "10.2.3.0/27" || e.ObservedAt != nil || e.PrefixBasis != "inventory" {
		t.Fatalf("%+v", e)
	}
}

func FuzzImports(f *testing.F) {
	f.Add([]byte("10.1.2.3\nhost.example\n"))
	f.Add([]byte("realm,prefix,kind,source,observed_at\ncorp,10.0.0.0/8,allocation,ipam,\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		p := filepath.Join(t.TempDir(), "input")
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
		seeds, err := Seeds(p, 100)
		if err == nil {
			for _, s := range seeds {
				if s.Address.IsValid() == (s.Name != "") {
					t.Fatalf("seed must be exactly one of address or name: %+v", s)
				}
				if s.Name != "" && !ValidName(s.Name) {
					t.Fatalf("invalid name accepted: %q", s.Name)
				}
			}
		}
		items, err := Inventory(p, 100)
		if err == nil {
			for _, e := range items {
				if e.Prefix == nil || *e.Prefix != e.Prefix.Masked() || e.PrefixBasis != "inventory" {
					t.Fatalf("noncanonical inventory %+v", e)
				}
			}
		}
	})
}
