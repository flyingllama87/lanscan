package platform

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"lanscan/internal/model"
)

func Network(ctx context.Context, emit Emit) error {
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return status(emit, "netlink", "failed", err)
	}
	defer h.Close()
	if err = h.SetSocketTimeout(time.Second); err != nil {
		return status(emit, "netlink", "failed", err)
	}
	routes, err := h.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		if err = status(emit, "routes", "failed", err); err != nil {
			return err
		}
	} else {
		for _, route := range routes {
			if err := ctx.Err(); err != nil {
				return status(emit, "routes", "timed_out", err)
			}
			var p netip.Prefix
			if route.Dst == nil {
				if route.Family == unix.AF_INET6 {
					p = netip.MustParsePrefix("::/0")
				} else {
					p = netip.MustParsePrefix("0.0.0.0/0")
				}
			} else {
				p, err = PrefixFromIPNet(route.Dst)
				if err != nil {
					return status(emit, "routes", "failed", err)
				}
			}
			kind := "other"
			switch route.Type {
			case unix.RTN_UNICAST:
				kind = "unicast"
			case unix.RTN_BLACKHOLE:
				kind = "blackhole"
			case unix.RTN_UNREACHABLE:
				kind = "unreachable"
			case unix.RTN_PROHIBIT:
				kind = "prohibit"
			case unix.RTN_LOCAL:
				kind = "local"
			case unix.RTN_BROADCAST:
				kind = "broadcast"
			}
			iface := ""
			if route.LinkIndex > 0 {
				iface = interfaceName(route.LinkIndex)
			}
			e := model.Event{Type: "observation", Source: "routes", Prefix: &p, PrefixBasis: "route", InterfaceID: iface, ObservedAt: model.Now(), Details: map[string]any{"table": route.Table, "metric": route.Priority, "route_type": kind, "protocol": int(route.Protocol), "scope": int(route.Scope)}}
			if len(route.Gw) > 0 {
				e.Details["gateway"] = route.Gw.String()
			}
			if len(route.MultiPath) > 0 {
				e.Details["multipath"] = fmt.Sprint(route.MultiPath)
			}
			if err := emit(e); err != nil {
				return err
			}
			if route.Gw != nil {
				if a, ok := netip.AddrFromSlice(route.Gw); ok {
					a = a.Unmap()
					zone := ""
					if a.Is6() && a.IsLinkLocalUnicast() {
						zone = iface
					}
					if err := emit(model.Event{Type: "observation", Address: a.String(), Zone: zone, Source: "route_gateway", InterfaceID: iface, ObservedAt: model.Now()}); err != nil {
						return err
					}
				}
			}
		}
		if err := status(emit, "routes", "complete", nil); err != nil {
			return err
		}
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := h.RuleList(family)
		if err != nil {
			if err := status(emit, "rules", "failed", err); err != nil {
				return err
			}
			continue
		}
		for _, rule := range rules {
			if err := ctx.Err(); err != nil {
				return status(emit, "rules", "timed_out", err)
			}
			if err := emit(model.Event{Type: "observation", Source: "rules", ObservedAt: model.Now(), Details: map[string]any{"family": family, "rule": rule.String(), "table": rule.Table, "priority": rule.Priority}}); err != nil {
				return err
			}
		}
	}
	if err := status(emit, "rules", "complete", nil); err != nil {
		return err
	}
	neighbors, err := h.NeighList(0, netlink.FAMILY_ALL)
	if err != nil {
		return status(emit, "neighbors", "failed", err)
	}
	for _, neighbor := range neighbors {
		if err := ctx.Err(); err != nil {
			return status(emit, "neighbors", "timed_out", err)
		}
		a, ok := netip.AddrFromSlice(neighbor.IP)
		if !ok {
			continue
		}
		a = a.Unmap()
		iface := interfaceName(neighbor.LinkIndex)
		zone := ""
		if a.Is6() && a.IsLinkLocalUnicast() {
			zone = iface
		}
		if err := emit(model.Event{Type: "observation", Address: a.String(), Zone: zone, Source: "neighbors", ActivityBasis: "cache", InterfaceID: iface, Details: map[string]any{"state": neighbor.State, "state_name": linuxNeighborState(neighbor.State), "mac": neighbor.HardwareAddr.String(), "freshness": "unknown"}}); err != nil {
			return err
		}
	}
	return status(emit, "neighbors", "complete", nil)
}

// linuxNeighborState names the NUD_* state bits; stale, incomplete and failed
// entries are cache evidence only, never current liveness.
func linuxNeighborState(v int) string {
	names := []struct {
		bit  int
		name string
	}{{unix.NUD_PERMANENT, "permanent"}, {unix.NUD_NOARP, "noarp"}, {unix.NUD_REACHABLE, "reachable"}, {unix.NUD_DELAY, "delay"}, {unix.NUD_PROBE, "probe"}, {unix.NUD_STALE, "stale"}, {unix.NUD_INCOMPLETE, "incomplete"}, {unix.NUD_FAILED, "failed"}}
	for _, n := range names {
		if v&n.bit != 0 {
			return n.name
		}
	}
	return "none"
}
