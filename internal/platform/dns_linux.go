package platform

import (
	"bufio"
	"bytes"
	"context"
	"net/netip"
	"os"
	"strings"

	"lanscan/internal/model"
)

var resolvectlPaths = []string{"/usr/bin/resolvectl", "/bin/resolvectl"}

var stubResolver = netip.MustParseAddr("127.0.0.53")

// Resolvers records resolver configuration. It sends no DNS queries.
func Resolvers(ctx context.Context, emit Emit) error {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return status(emit, "resolver_config", "failed", err)
	}
	conf := ParseResolvConf(f)
	f.Close()
	stub := false
	for _, a := range conf.Nameservers {
		if a == stubResolver {
			stub = true
		}
	}
	policy := "resolv.conf"
	if stub {
		policy = "systemd-resolved stub; per-link routing domains decide the upstream"
	}
	for _, a := range conf.Nameservers {
		if err := emit(model.Event{Type: "observation", Source: "resolver_config", Address: a.String(), ObservedAt: model.Now(), Details: map[string]any{"file": "/etc/resolv.conf", "search": conf.Search, "policy": policy}}); err != nil {
			return err
		}
	}
	outcome := "complete"
	if stub {
		// Per-link servers and routing domains come from resolved itself.
		out, _, err := runHelper(ctx, resolvectlPaths, "dns")
		if err != nil {
			outcome = "partial"
		} else {
			domains, _, _ := runHelper(ctx, resolvectlPaths, "domain")
			linkDomains := parseResolvectlLinks(domains)
			for link, values := range parseResolvectlLinks(out) {
				for _, v := range values {
					a, err := netip.ParseAddr(strings.SplitN(v, "#", 2)[0])
					if err != nil {
						continue
					}
					if err := emit(model.Event{Type: "observation", Source: "resolver_config", Address: a.Unmap().String(), InterfaceID: link, ObservedAt: model.Now(), Details: map[string]any{"provider": "systemd-resolved", "routing_domains": linkDomains[link], "policy": "per-link"}}); err != nil {
						return err
					}
				}
			}
		}
	}
	return status(emit, "resolver_config", outcome, nil)
}

// parseResolvectlLinks reads "Link N (name): v1 v2" and "Global: v" lines.
func parseResolvectlLinks(b []byte) map[string][]string {
	out := make(map[string][]string)
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		head, values, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		link := "global"
		if open, close := strings.Index(head, "("), strings.Index(head, ")"); open >= 0 && close > open {
			link = head[open+1 : close]
		} else if strings.TrimSpace(head) != "Global" {
			continue
		}
		if fields := strings.Fields(values); len(fields) > 0 {
			out[link] = append(out[link], fields...)
		}
	}
	return out
}

// DNSCache enumerates systemd-resolved's cache where supported (v254+). It
// never flushes or refreshes the cache.
func DNSCache(ctx context.Context, emit Emit) error {
	out, truncated, err := runHelper(ctx, resolvectlPaths, "show-cache")
	if err != nil {
		return status(emit, "dns_cache", helperStatus(err), err)
	}
	return emitCache(emit, "systemd-resolved", ParseResolvectlCache(out), truncated)
}
