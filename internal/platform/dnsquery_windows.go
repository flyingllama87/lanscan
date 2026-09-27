//go:build windows && (amd64 || arm64)

package platform

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The DNS_QUERY_REQUEST/RESULT layouts below match the 64-bit MSVC layouts
// only; 32-bit Windows keeps the Go resolver (see dnsquery_windows32.go).

var (
	dnsapi             = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsQueryEx     = dnsapi.NewProc("DnsQueryEx")
	procDnsCancelQuery = dnsapi.NewProc("DnsCancelQuery")
)

const (
	dnsQueryRequestVersion1 = 1
	dnsQueryResultsVersion1 = 1
	dnsRequestPending       = 9506
	dnsFreeRecordList       = 1
	dnsSectionMask          = 0x3
	dnsSectionAnswer        = 1

	// DNS only, as the system DNS client would send it (including NRPT and
	// per-adapter servers and the client cache), but never the hosts file,
	// NetBIOS, LLMNR/mDNS, or search-suffix expansion.
	dnsClientQueryOptions = 0x40 | // DNS_QUERY_NO_HOSTS_FILE
		0x80 | // DNS_QUERY_NO_NETBT
		0x800 | // DNS_QUERY_NO_MULTICAST
		0x20 | // DNS_QUERY_NO_LOCAL_NAME
		0x1000 // DNS_QUERY_TREAT_AS_FQDN
)

type dnsQueryRequest struct {
	Version        uint32
	QueryName      *uint16
	QueryType      uint16
	QueryOptions   uint64
	DNSServerList  uintptr
	InterfaceIndex uint32
	Completion     uintptr
	Context        uintptr
}

type dnsQueryResult struct {
	Version      uint32
	QueryStatus  int32
	QueryOptions uint64
	Records      *windows.DNSRecord
	Reserved     uintptr
}

type dnsQueryCancel struct{ Reserved [32]byte }

// dnsQuery is one in-flight query. It is pinned while Windows holds pointers
// into it and is found from the completion callback by id, so no Go pointer
// ever round-trips through the OS as an integer.
type dnsQuery struct {
	request dnsQueryRequest
	result  dnsQueryResult
	cancel  dnsQueryCancel
	done    chan struct{}
}

var (
	dnsCallbackOnce sync.Once
	dnsCallback     uintptr
	dnsMu           sync.Mutex
	dnsNextID       uintptr
	dnsInFlight     = make(map[uintptr]*dnsQuery)
)

func dnsComplete(id, _ uintptr) uintptr {
	dnsMu.Lock()
	q := dnsInFlight[id]
	delete(dnsInFlight, id)
	dnsMu.Unlock()
	if q != nil {
		close(q.done)
	}
	return 0
}

// dnsQueryEx runs one asynchronous DnsQueryEx and cancels it with ctx.
func dnsQueryEx(ctx context.Context, name string, qtype uint16) ([]windows.DNSRecord, []string, error) {
	if err := procDnsQueryEx.Find(); err != nil {
		return nil, nil, err
	}
	dnsCallbackOnce.Do(func() { dnsCallback = windows.NewCallback(dnsComplete) })
	qname, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, nil, err
	}
	q := &dnsQuery{done: make(chan struct{})}
	q.request = dnsQueryRequest{Version: dnsQueryRequestVersion1, QueryName: qname, QueryType: qtype, QueryOptions: dnsClientQueryOptions, Completion: dnsCallback}
	q.result.Version = dnsQueryResultsVersion1
	var pin runtime.Pinner
	pin.Pin(q)
	pin.Pin(qname)
	defer pin.Unpin()
	dnsMu.Lock()
	dnsNextID++
	id := dnsNextID
	q.request.Context = id
	dnsInFlight[id] = q
	dnsMu.Unlock()
	status, _, _ := procDnsQueryEx.Call(uintptr(unsafe.Pointer(&q.request)), uintptr(unsafe.Pointer(&q.result)), uintptr(unsafe.Pointer(&q.cancel)))
	if status == dnsRequestPending {
		select {
		case <-q.done:
		case <-ctx.Done():
			procDnsCancelQuery.Call(uintptr(unsafe.Pointer(&q.cancel)))
			<-q.done // the callback always runs, with ERROR_CANCELLED
		}
		status = uintptr(uint32(q.result.QueryStatus))
	} else {
		dnsMu.Lock()
		delete(dnsInFlight, id)
		dnsMu.Unlock()
	}
	var records []windows.DNSRecord
	var ptrs []string
	for r := q.result.Records; r != nil; r = r.Next {
		if r.Dw&dnsSectionMask != dnsSectionAnswer || r.Type != qtype {
			continue
		}
		records = append(records, *r)
		if qtype == windows.DNS_TYPE_PTR {
			if host := *(**uint16)(unsafe.Pointer(&r.Data[0])); host != nil {
				ptrs = append(ptrs, windows.UTF16PtrToString(host))
			}
		}
	}
	if q.result.Records != nil {
		windows.DnsRecordListFree(q.result.Records, dnsFreeRecordList)
	}
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	if status != 0 {
		return nil, nil, dnsStatusError(name, syscall.Errno(status))
	}
	return records, ptrs, nil
}

func dnsStatusError(name string, errno syscall.Errno) error {
	e := &net.DNSError{Err: errno.Error(), Name: name}
	switch errno {
	case windows.DNS_ERROR_RCODE_NAME_ERROR, windows.DNS_INFO_NO_RECORDS:
		e.IsNotFound = true
	case windows.ERROR_TIMEOUT:
		e.IsTimeout = true
	}
	return e
}

// dnsClientResolver resolves through the Windows DNS client with DnsQueryEx.
type dnsClientResolver struct{}

func (dnsClientResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	var types []uint16
	switch network {
	case "ip4":
		types = []uint16{windows.DNS_TYPE_A}
	case "ip6":
		types = []uint16{windows.DNS_TYPE_AAAA}
	case "ip":
		types = []uint16{windows.DNS_TYPE_A, windows.DNS_TYPE_AAAA}
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}
	var out []netip.Addr
	var firstErr error
	for _, t := range types {
		records, _, err := dnsQueryEx(ctx, host, t)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, r := range records {
			if t == windows.DNS_TYPE_A {
				out = append(out, netip.AddrFrom4([4]byte(r.Data[:4])))
			} else {
				out = append(out, netip.AddrFrom16([16]byte(r.Data[:16])))
			}
		}
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no answer", Name: host, IsNotFound: true}
	}
	return out, nil
}

func (dnsClientResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	_, names, err := dnsQueryEx(ctx, ReverseName(a), windows.DNS_TYPE_PTR)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, &net.DNSError{Err: "no answer", Name: addr, IsNotFound: true}
	}
	for i, n := range names {
		if n != "" && n[len(n)-1] != '.' {
			names[i] = n + "."
		}
	}
	return names, nil
}

// SystemResolver returns the resolver for "system" policy DNS: the Windows DNS
// client through DnsQueryEx, which applies NRPT and per-adapter servers.
func SystemResolver() (Resolver, string) {
	if procDnsQueryEx.Find() != nil {
		return net.DefaultResolver, "system"
	}
	return dnsClientResolver{}, "windows_dns_client"
}
