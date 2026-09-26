package platform

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"lanscan/internal/model"
)

var ipHelper = windows.NewLazySystemDLL("iphlpapi.dll")
var getForward = ipHelper.NewProc("GetIpForwardTable2")
var getNeighbors = ipHelper.NewProc("GetIpNetTable2")
var freeTable = ipHelper.NewProc("FreeMibTable")

// Layouts follow netioapi.h for Windows amd64/arm64. No writable APIs are called.
type socketAddress struct {
	Family uint16
	Data   [26]byte
}

func (s socketAddress) addr() (netip.Addr, string) {
	switch s.Family {
	case windows.AF_INET:
		return netip.AddrFrom4([4]byte{s.Data[2], s.Data[3], s.Data[4], s.Data[5]}), ""
	case windows.AF_INET6:
		var b [16]byte
		copy(b[:], s.Data[6:22])
		a := netip.AddrFrom16(b)
		scope := uint32(s.Data[22]) | uint32(s.Data[23])<<8 | uint32(s.Data[24])<<16 | uint32(s.Data[25])<<24
		zone := ""
		if scope != 0 {
			zone = interfaceName(int(scope))
		}
		return a, zone
	}
	return netip.Addr{}, ""
}

type addressPrefix struct {
	Address socketAddress
	Length  uint8
	_       [3]byte
}
type forwardRow struct {
	LUID              uint64
	Index             uint32
	Destination       addressPrefix
	NextHop           socketAddress
	SitePrefixLength  uint8
	_                 [3]byte
	ValidLifetime     uint32
	PreferredLifetime uint32
	Metric            uint32
	Protocol          uint32
	Loopback          uint8
	Autoconfigure     uint8
	Publish           uint8
	Immortal          uint8
	Age               uint32
	Origin            uint32
}
type neighborRow struct {
	Address          socketAddress
	Index            uint32
	LUID             uint64
	Physical         [32]byte
	PhysicalLength   uint32
	State            uint32
	Flags            uint8
	_                [3]byte
	ReachabilityTime uint32
}

func Network(ctx context.Context, emit Emit) error {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return status(emit, "network", "unsupported", fmt.Errorf("native tables require a 64-bit build"))
	}
	if unsafe.Sizeof(forwardRow{}) != 104 || unsafe.Sizeof(neighborRow{}) != 88 {
		return status(emit, "network", "failed", fmt.Errorf("native structure layout mismatch"))
	}
	var table unsafe.Pointer
	code, _, _ := getForward.Call(windows.AF_UNSPEC, uintptr(unsafe.Pointer(&table)))
	if code != 0 {
		if err := status(emit, "routes", "failed", syscall.Errno(code)); err != nil {
			return err
		}
	} else {
		err := func() error {
			if table == nil {
				return status(emit, "routes", "failed", fmt.Errorf("nil native table"))
			}
			defer freeTable.Call(uintptr(table))
			count := *(*uint32)(table)
			if count > 1000000 {
				return status(emit, "routes", "partial", fmt.Errorf("native table exceeds item limit"))
			}
			rows := unsafe.Slice((*forwardRow)(unsafe.Add(table, 8)), int(count))
			for _, row := range rows {
				if err := ctx.Err(); err != nil {
					return status(emit, "routes", "timed_out", err)
				}
				a, _ := row.Destination.Address.addr()
				p := netip.PrefixFrom(a, int(row.Destination.Length)).Masked()
				if !p.IsValid() {
					return status(emit, "routes", "partial", fmt.Errorf("invalid native prefix"))
				}
				gateway, zone := row.NextHop.addr()
				iface := interfaceName(int(row.Index))
				// Administrative types keep --scope-from routes to real unicast routes.
				kind := "unicast"
				switch {
				case row.Loopback != 0 || p.Addr().IsLoopback():
					kind = "local"
				case p.Addr().IsMulticast():
					kind = "multicast"
				case p.Bits() == 32 && p.Addr() == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
					kind = "broadcast"
				}
				details := map[string]any{"route_type": kind, "metric": row.Metric, "protocol": row.Protocol, "interface_luid": strconv.FormatUint(row.LUID, 10), "age_seconds": row.Age}
				if gateway.IsValid() && !gateway.IsUnspecified() {
					details["gateway"] = gateway.String()
				}
				if err := emit(model.Event{Type: "observation", Source: "routes", Prefix: &p, PrefixBasis: "route", InterfaceID: iface, ObservedAt: model.Now(), Details: details}); err != nil {
					return err
				}
				if gateway.IsValid() && !gateway.IsUnspecified() {
					if err := emit(model.Event{Type: "observation", Source: "route_gateway", Address: gateway.String(), Zone: zone, InterfaceID: iface, ObservedAt: model.Now()}); err != nil {
						return err
					}
				}
			}
			return status(emit, "routes", "complete", nil)
		}()
		if err != nil {
			return err
		}
	}
	table = nil
	code, _, _ = getNeighbors.Call(windows.AF_UNSPEC, uintptr(unsafe.Pointer(&table)))
	if code == uintptr(windows.ERROR_NOT_FOUND) {
		return status(emit, "neighbors", "complete", nil)
	}
	if code != 0 {
		return status(emit, "neighbors", "failed", syscall.Errno(code))
	}
	if table == nil {
		return status(emit, "neighbors", "failed", fmt.Errorf("nil native table"))
	}
	defer freeTable.Call(uintptr(table))
	count := *(*uint32)(table)
	if count > 1000000 {
		return status(emit, "neighbors", "partial", fmt.Errorf("native table exceeds item limit"))
	}
	rows := unsafe.Slice((*neighborRow)(unsafe.Add(table, 8)), int(count))
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return status(emit, "neighbors", "timed_out", err)
		}
		a, zone := row.Address.addr()
		if !a.IsValid() {
			continue
		}
		if err := emit(model.Event{Type: "observation", Source: "neighbors", Address: a.String(), Zone: zone, InterfaceID: interfaceName(int(row.Index)), ActivityBasis: "cache", Details: map[string]any{"state": row.State, "state_name": windowsNeighborState(row.State), "freshness": "unknown"}}); err != nil {
			return err
		}
	}
	return status(emit, "neighbors", "complete", nil)
}

// windowsNeighborState names NL_NEIGHBOR_STATE values.
func windowsNeighborState(v uint32) string {
	names := []string{"unreachable", "incomplete", "probe", "delay", "stale", "reachable", "permanent"}
	if int(v) < len(names) {
		return names[v]
	}
	return "unknown"
}
