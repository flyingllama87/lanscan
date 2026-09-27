package platform

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
)

// Resolver is the lookup interface used for DNS enrichment.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// ReverseName returns the absolute PTR query name for a.
func ReverseName(a netip.Addr) string {
	a = a.Unmap().WithZone("")
	if a.Is4() {
		b := a.As4()
		return strconv.Itoa(int(b[3])) + "." + strconv.Itoa(int(b[2])) + "." + strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[0])) + ".in-addr.arpa."
	}
	const hex = "0123456789abcdef"
	b := a.As16()
	var sb strings.Builder
	for i := len(b) - 1; i >= 0; i-- {
		sb.WriteByte(hex[b[i]&15])
		sb.WriteByte('.')
		sb.WriteByte(hex[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa.")
	return sb.String()
}

// NRPTRule is one Name Resolution Policy Table rule.
type NRPTRule struct {
	Key        string   `json:"key"`
	Source     string   `json:"source"` // group_policy or local
	Namespaces []string `json:"namespaces"`
	Servers    []string `json:"servers,omitempty"`
	Options    uint32   `json:"config_options"`
}

// MatchNRPT returns the rule and namespace that most specifically match name:
// a leading-dot namespace matches the name and names below it, "." matches
// everything, and any other namespace matches only that exact name. It
// mirrors the documented precedence; Windows applies the rule itself.
func MatchNRPT(name string, rules []NRPTRule) (NRPTRule, string, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	var best NRPTRule
	bestNS, bestLen, found := "", -1, false
	for _, r := range rules {
		for _, ns := range r.Namespaces {
			n := strings.ToLower(strings.TrimSuffix(ns, "."))
			length := -1
			switch {
			case ns == ".":
				length = 0
			case strings.HasPrefix(n, "."):
				if name == n[1:] || strings.HasSuffix(name, n) {
					length = len(n)
				}
			case name == n:
				length = len(n) + 1 // an exact name beats an equal suffix
			}
			if length > bestLen {
				best, bestNS, bestLen, found = r, ns, length, true
			}
		}
	}
	return best, bestNS, found
}
