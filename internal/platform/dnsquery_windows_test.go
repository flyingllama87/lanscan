//go:build windows && (amd64 || arm64)

package platform

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// LANSCAN_WIN_DNS_NAME/ADDR name a record served by the test DNS server;
// LANSCAN_WIN_NRPT_NAMESPACE is an NRPT namespace the harness configured.
func TestDnsClientResolver(t *testing.T) {
	name, want := os.Getenv("LANSCAN_WIN_DNS_NAME"), os.Getenv("LANSCAN_WIN_DNS_ADDR")
	if name == "" || want == "" {
		t.Skip("LANSCAN_WIN_DNS_NAME/ADDR not set")
	}
	r, policy := SystemResolver()
	if policy != "windows_dns_client" {
		t.Fatalf("policy %q", policy)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := r.LookupNetIP(ctx, "ip4", name)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr(want) {
		t.Fatalf("A %s: %v", name, addrs)
	}
	names, err := r.LookupAddr(ctx, want)
	if err != nil {
		t.Logf("PTR %s: %v (no reverse zone is acceptable)", want, err)
	} else {
		t.Logf("PTR %s: %v", want, names)
	}
	_, err = r.LookupNetIP(ctx, "ip4", "does-not-exist."+name)
	var de *net.DNSError
	if !errors.As(err, &de) || !de.IsNotFound {
		t.Fatalf("NXDOMAIN: %v", err)
	}
}

func TestDnsClientResolverHonoursCancellation(t *testing.T) {
	if _, policy := SystemResolver(); policy != "windows_dns_client" {
		t.Skip("DnsQueryEx unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := dnsClientResolver{}.LookupNetIP(ctx, "ip4", "cancel-test.invalid.")
	if !errors.Is(err, context.Canceled) || time.Since(start) > 3*time.Second {
		t.Fatalf("canceled lookup: %v after %v", err, time.Since(start))
	}
	// Many concurrent queries, each canceled mid-flight, must all return.
	done := make(chan error, 32)
	for i := range 32 {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(i)*time.Millisecond)
			defer cancel()
			_, err := dnsClientResolver{}.LookupNetIP(ctx, "ip6", "slow-"+string(rune('a'+i%26))+".invalid.")
			done <- err
		}()
	}
	for range 32 {
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Fatal("query never completed after cancellation")
		}
	}
}

func TestNRPTRulesAndPolicyDetails(t *testing.T) {
	ns := os.Getenv("LANSCAN_WIN_NRPT_NAMESPACE")
	if ns == "" {
		t.Skip("LANSCAN_WIN_NRPT_NAMESPACE not set")
	}
	rules, effective, err := NRPTRules()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("effective=%s rules=%+v", effective, rules)
	d := DNSPolicyDetails("host" + ns + ".")
	if d["nrpt"] != "configured_rule_matches" || d["nrpt_namespace"] != ns {
		t.Fatalf("policy details %v", d)
	}
	if d := DNSPolicyDetails("unrelated.example."); d["nrpt"] == "configured_rule_matches" && d["nrpt_namespace"] == ns {
		t.Fatalf("unrelated name matched %v", d)
	}
}
