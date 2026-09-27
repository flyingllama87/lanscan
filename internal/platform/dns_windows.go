package platform

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"lanscan/internal/model"
)

// Resolvers records per-adapter DNS servers and suffixes. It sends no queries.
func Resolvers(ctx context.Context, emit Emit) error {
	size := uint32(15000)
	var buf []byte
	for attempt := 0; attempt < 3; attempt++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == windows.ERROR_BUFFER_OVERFLOW && size <= 4<<20 {
			continue
		}
		if err != nil {
			return status(emit, "resolver_config", "failed", err)
		}
		for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
			if err := ctx.Err(); err != nil {
				return status(emit, "resolver_config", "timed_out", err)
			}
			iface := interfaceName(int(a.IfIndex))
			suffix := windows.UTF16PtrToString(a.DnsSuffix)
			for s := a.FirstDnsServerAddress; s != nil; s = s.Next {
				ip := s.Address.IP()
				addr, ok := netip.AddrFromSlice(ip)
				if !ok {
					continue
				}
				e := model.Event{Type: "observation", Source: "resolver_config", Address: addr.Unmap().String(), InterfaceID: iface, ObservedAt: model.Now(), Details: map[string]any{"provider": "GetAdaptersAddresses", "dns_suffix": suffix, "policy": "adapter configuration; NRPT rules are reported separately and take precedence for matching names"}}
				if err := emit(e); err != nil {
					return err
				}
			}
		}
		outcome := "complete"
		if err := emitNRPT(emit); err != nil {
			outcome = "partial"
		}
		return status(emit, "resolver_config", outcome, nil)
	}
	return status(emit, "resolver_config", "failed", windows.ERROR_BUFFER_OVERFLOW)
}

// emitNRPT records Name Resolution Policy Table rules, one observation per
// namespace and server. Rules without servers (for example DNSSEC-only or
// exemption rules) are recorded by namespace alone.
func emitNRPT(emit Emit) error {
	rules, effective, err := NRPTRules()
	for _, r := range rules {
		servers := r.Servers
		if len(servers) == 0 {
			servers = []string{""}
		}
		for _, ns := range r.Namespaces {
			for _, server := range servers {
				e := model.Event{Type: "observation", Source: "resolver_config", ObservedAt: model.Now(), Details: map[string]any{"provider": "NRPT", "policy": "nrpt", "namespace": ns, "nrpt_source": r.Source, "nrpt_rule": r.Key, "config_options": r.Options, "applied": r.Source == effective}}
				if a, perr := netip.ParseAddr(server); perr == nil {
					e.Address = a.Unmap().String()
				}
				if emitErr := emit(e); emitErr != nil {
					return emitErr
				}
			}
		}
	}
	return err
}

// cacheCommand is fixed text; no imported value is ever interpolated.
const cacheCommand = "Get-DnsClientCache | Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Entry,$_.Type,$_.Data,$_.TimeToLive }"

// DNSCache uses the DnsClient PowerShell module, the documented interface.
func DNSCache(ctx context.Context, emit Emit) error {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	ps := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	out, truncated, err := runHelper(ctx, []string{ps}, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", cacheCommand)
	if err != nil {
		st := helperStatus(err)
		if st == "timed_out" {
			// Measured on Windows 10: standard users are refused CIM access
			// only after ~10s, so a timeout here usually means no permission.
			err = fmt.Errorf("%w; DnsClient CIM access commonly requires administrator rights", err)
		}
		return status(emit, "dns_cache", st, err)
	}
	return emitCache(emit, "DnsClient", ParsePowerShellCache(out), truncated)
}
