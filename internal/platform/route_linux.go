package platform

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func LookupRoute(target, source netip.Addr, iface string) (Route, error) {
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return Route{}, err
	}
	defer h.Close()
	if err = h.SetSocketTimeout(time.Second); err != nil {
		return Route{}, err
	}
	uid := uint32(os.Getuid())
	opts := &netlink.RouteGetOptions{Oif: iface, UID: &uid}
	if source.IsValid() {
		opts.SrcAddr = net.IP(source.AsSlice())
	}
	if target.Zone() != "" {
		opts.Oif = target.Zone()
	}
	routes, err := h.RouteGetWithOptions(net.IP(target.AsSlice()), opts)
	if err != nil {
		return Route{}, err
	}
	if len(routes) != 1 {
		return Route{}, fmt.Errorf("route lookup returned %d paths", len(routes))
	}
	r := routes[0]
	if r.Type != unix.RTN_UNICAST && r.Type != unix.RTN_LOCAL {
		return Route{}, fmt.Errorf("non-unicast route type %d", r.Type)
	}
	selected := interfaceName(r.LinkIndex)
	if iface != "" && selected != iface {
		return Route{}, fmt.Errorf("route uses interface %s rather than %s", selected, iface)
	}
	a, ok := netip.AddrFromSlice(r.Src)
	if !ok {
		a = source
	}
	a = a.Unmap()
	if !a.IsValid() {
		return Route{}, fmt.Errorf("route lookup returned no source address")
	}
	if a.Is6() && a.IsLinkLocalUnicast() {
		a = a.WithZone(selected)
	}
	gw, _ := netip.AddrFromSlice(r.Gw)
	return Route{Source: a, Interface: selected, Gateway: gw.Unmap(), Table: r.Table}, nil
}

func BindSocket(fd uintptr, ipv6 bool, iface string) error {
	if iface == "" {
		return nil
	}
	return unix.BindToDevice(int(fd), iface)
}
