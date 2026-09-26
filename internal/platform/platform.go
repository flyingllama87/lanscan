// Package platform provides local-only collectors. No collector resolves names.
package platform

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"lanscan/internal/model"
)

type Emit func(model.Event) error

func status(emit Emit, name, outcome string, err error) error {
	details := map[string]any{}
	if err != nil {
		details["error"] = err.Error()
	}
	return emit(model.Event{Type: "collector_status", Source: name, Outcome: outcome, Details: details, ObservedAt: model.Now()})
}

func Interfaces(ctx context.Context, emit Emit) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return status(emit, "interfaces", "failed", err)
	}
	partial := false
	for _, iface := range interfaces {
		if err := ctx.Err(); err != nil {
			return status(emit, "interfaces", "timed_out", err)
		}
		addrs, err := iface.Addrs()
		if err != nil {
			partial = true
			continue
		}
		for _, addr := range addrs {
			p, err := netip.ParsePrefix(addr.String())
			if err != nil {
				partial = true
				continue
			}
			a := p.Addr()
			p = p.Masked()
			zone := ""
			if a.Is6() && a.IsLinkLocalUnicast() {
				zone = iface.Name
			}
			e := model.Event{Type: "observation", Source: "interfaces", Prefix: &p, Address: a.String(), Zone: zone, PrefixBasis: "interface", InterfaceID: iface.Name, ObservedAt: model.Now(), Details: map[string]any{"index": iface.Index, "flags": iface.Flags.String(), "mtu": iface.MTU}}
			if err := emit(e); err != nil {
				return err
			}
		}
	}
	outcome := "complete"
	if partial {
		outcome = "partial"
	}
	return status(emit, "interfaces", outcome, nil)
}

func interfaceName(index int) string {
	i, err := net.InterfaceByIndex(index)
	if err == nil {
		return i.Name
	}
	return strconv.Itoa(index)
}

func PrefixFromIPNet(n *net.IPNet) (netip.Prefix, error) {
	if n == nil {
		return netip.Prefix{}, fmt.Errorf("nil IPNet")
	}
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("invalid address")
	}
	ones, bits := n.Mask.Size()
	if bits == 0 {
		return netip.Prefix{}, fmt.Errorf("invalid mask")
	}
	a = a.Unmap()
	if a.Is4() && bits == 128 {
		ones -= 96
	}
	p := netip.PrefixFrom(a, ones)
	if !p.IsValid() {
		return p, fmt.Errorf("invalid prefix")
	}
	return p.Masked(), nil
}
