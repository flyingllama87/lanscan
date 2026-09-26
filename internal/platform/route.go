package platform

import "net/netip"

type Route struct {
	Source    netip.Addr
	Interface string
	Gateway   netip.Addr
	Table     int
}
