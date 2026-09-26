package discover

import (
	"fmt"
	"net/netip"
)

type Scope struct {
	Include   []netip.Prefix
	Exclude   []netip.Prefix
	Interface string
	// SamplePerPrefix enables synthetic IPv4 samples; zero disables them.
	SamplePerPrefix int
}

func ParsePrefixes(values []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range values {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid scope %q: %w", s, err)
		}
		if p.Addr().Is4In6() {
			return nil, fmt.Errorf("use native IPv4 notation for scope %q", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// RouteScope accepts only prefixes wholly within private address space.
func RouteScope(p netip.Prefix, routeType string) bool {
	if !p.IsValid() || routeType != "unicast" {
		return false
	}
	for _, s := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
		allowed := netip.MustParsePrefix(s)
		if p.Bits() >= allowed.Bits() && allowed.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func (s Scope) Allows(a netip.Addr) (bool, string) {
	if !a.IsValid() {
		return false, "invalid_address"
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a == netip.MustParseAddr("255.255.255.255") {
		return false, "non_unicast"
	}
	if a.IsLinkLocalUnicast() && (s.Interface == "" || !a.Is6() || a.Zone() == "" || a.Zone() != s.Interface) {
		return false, "link_local_requires_interface_zone"
	}
	unzoned := a.WithZone("")
	for _, p := range s.Exclude {
		if p.Contains(unzoned) {
			return false, "excluded"
		}
	}
	for _, p := range s.Include {
		if p.Contains(unzoned) {
			return true, ""
		}
	}
	return false, "outside_scope"
}

// IsBroadcast uses known subnet evidence, never an invented /24 mask.
func IsBroadcast(a netip.Addr, p netip.Prefix) bool {
	if !a.Is4() || !p.IsValid() || !p.Addr().Is4() || p.Bits() > 30 || !p.Contains(a) {
		return false
	}
	bytes := a.As4()
	base := p.Masked().Addr().As4()
	value := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
	start := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	mask := uint32(0xffffffff) >> p.Bits()
	return value == start|mask
}
