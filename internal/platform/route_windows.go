package platform

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var getBestRoute = ipHelper.NewProc("GetBestRoute2")

func nativeAddress(a netip.Addr) (socketAddress, error) {
	var s socketAddress
	if !a.IsValid() {
		return s, fmt.Errorf("invalid address")
	}
	if a.Is4() {
		s.Family = windows.AF_INET
		b := a.As4()
		copy(s.Data[2:6], b[:])
	} else {
		s.Family = windows.AF_INET6
		b := a.As16()
		copy(s.Data[6:22], b[:])
		if a.Zone() != "" {
			i, err := net.InterfaceByName(a.Zone())
			if err != nil {
				return s, err
			}
			n := uint32(i.Index)
			s.Data[22] = byte(n)
			s.Data[23] = byte(n >> 8)
			s.Data[24] = byte(n >> 16)
			s.Data[25] = byte(n >> 24)
		}
	}
	return s, nil
}
func LookupRoute(target, source netip.Addr, iface string) (Route, error) {
	dest, err := nativeAddress(target)
	if err != nil {
		return Route{}, err
	}
	var src socketAddress
	var srcPtr uintptr
	if source.IsValid() {
		src, err = nativeAddress(source)
		if err != nil {
			return Route{}, err
		}
		srcPtr = uintptr(unsafe.Pointer(&src))
	}
	var index uint32
	if iface == "" {
		iface = target.Zone()
	}
	if iface != "" {
		i, err := net.InterfaceByName(iface)
		if err != nil {
			return Route{}, err
		}
		index = uint32(i.Index)
	}
	var row forwardRow
	var best socketAddress
	code, _, _ := getBestRoute.Call(0, uintptr(index), srcPtr, uintptr(unsafe.Pointer(&dest)), 0, uintptr(unsafe.Pointer(&row)), uintptr(unsafe.Pointer(&best)))
	if code != 0 {
		return Route{}, syscall.Errno(code)
	}
	a, zone := best.addr()
	if zone != "" {
		a = a.WithZone(zone)
	}
	gw, _ := row.NextHop.addr()
	return Route{Source: a, Interface: interfaceName(int(row.Index)), Gateway: gw}, nil
}
func BindSocket(fd uintptr, ipv6 bool, iface string) error {
	if iface == "" {
		return nil
	}
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	level := windows.IPPROTO_IP
	option := 31
	index := uint32(i.Index)
	if ipv6 {
		level = windows.IPPROTO_IPV6
	} else {
		index = (index&0xff)<<24 | (index&0xff00)<<8 | (index&0xff0000)>>8 | (index >> 24)
	}
	return windows.SetsockoptInt(windows.Handle(fd), level, option, int(index))
}
