# Go architecture and platform support

## Components

Use a single Go executable with platform adapters behind small interfaces. Prefer standard-library networking, `net/netip` address types, explicit contexts and deadlines, and OS-native read APIs. Avoid a mandatory daemon, packet-capture driver, or shell dependency.

```text
local collectors + imports
          |
          v
    normalized evidence ---> append-only journal ---> output renderers
          |                         |
          v                         v
    evidence reducer <-------- replay/export
          |
          v
 candidate planner ---> scope gate ---> budgeted scheduler
                                            |
                                   OS probe backends
                                            |
                                            +----> normalized evidence
```

Proposed package boundaries:

```text
cmd/lanscan/          CLI and exit handling
internal/model/      versioned events, evidence, findings, routing context
internal/collect/    platform-neutral collector interfaces
internal/platform/   Linux and Windows implementations via build tags
internal/importer/   seed, prefix inventory, and prior-run readers
internal/discover/   candidate generation and evidence reduction
internal/schedule/   budgets, fairness, deadlines, cancellation
internal/probe/      echo, connect, DNS, trace backends
internal/journal/    append, sync, replay, checkpoint
internal/output/     JSONL, CSV, text, offline merge/export
```

Collectors emit individual observations and terminal status (`complete`, `partial`, `denied`, `unsupported`, `failed`, `timed_out`). Probe backends report capabilities such as source/interface binding, ICMP quotation visibility, and hop-limit control. Do not infer all capabilities from effective UID or administrator membership.

The scheduler owns all active work, including enrichment and retries. Collectors must not initiate name resolution while rendering local information. A single writer assigns event sequence numbers and handles short writes/errors. The reducer consumes accepted events so every advertised finding has persisted supporting evidence under the selected durability mode.

Use fixed worker pools and bounded channels. Candidate queues spill to an indexed local store if needed; start with a bounded in-memory queue and journal replay, then choose an embedded store only if benchmarks justify it. Default candidate cap: 100,000; imports and collector enumeration have byte/item limits. Emit `capacity_exceeded` and summary counts when a limit is reached, rather than claiming complete enumeration. Protect journal size with a configurable disk budget; exhaustion stops new probes.

## Platform plan

| Capability | Linux | Windows | Degradation |
| --- | --- | --- | --- |
| Interfaces and prefixes | `net.Interfaces` plus address/netlink metadata | `GetAdaptersAddresses` and adapter metadata | Partial metadata reported |
| Route enumeration | Rtnetlink, all readable tables in current namespace; collect policy rules | `GetIpForwardTable2`; include interface metrics/context | Missing routing policy means route selection confidence is limited |
| Actual route/source selection | Kernel route lookup with applicable source/rules/VRF context | `GetBestRoute2` with source/interface where applicable | Do not emulate complicated policy with destination-only matching |
| Neighbors | Rtnetlink neighbor dump, ARP and NDP | `GetIpNetTable2`, both families | Empty and denied are distinct |
| Resolver config | System resolver service and per-link config where available | DNS client adapter configuration and native resolver policy | Record when split DNS cannot be faithfully represented |
| DNS cache enumeration | Provider adapter; systemd-resolved where supported | Bounded `Get-DnsClientCache` PowerShell adapter | Skip if provider/API unavailable; never flush cache |
| ICMP echo | Try unprivileged ping socket; then permitted raw socket | Native IPv4/IPv6 ICMP APIs | Fall back to TCP; report lost capability |
| TCP connect | `net.Dialer` with context and local binding | Same | Retain OS error and distinguish local failure from remote response |
| Trace | TTL/hop-limit plus supported response/error receiver | Native ICMP TTL/hop-limit support where verified | Disable unsupported backend; preserve other discovery |
| Route changes | Netlink notifications, with bounded resnapshot fallback | IP Helper notifications, with resnapshot fallback | Poll on a bounded interval if notifications fail |

Windows route/neighbor APIs support both address families; native allocations must be freed, and structure layout/padding must match the target architecture. See [GetIpForwardTable2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardtable2), [GetIpNetTable2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipnettable2), and [GetBestRoute2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getbestroute2).

Linux ping sockets depend on host policy, including [`ping_group_range`](https://www.kernel.org/doc/html/v6.15/networking/ip-sysctl.html); raw sockets generally require `CAP_NET_RAW` in the applicable context. The Go [`x/net/icmp` API](https://pkg.go.dev/golang.org/x/net/icmp) supports unprivileged datagram endpoints on Linux but does not provide that same backend on Windows. Use Windows [IcmpSendEcho2](https://learn.microsoft.com/en-us/windows/win32/api/icmpapi/nf-icmpapi-icmpsendecho2) and the corresponding source-selecting/IPv6 APIs, with runtime probes and real OS tests. Async native buffers must remain valid until completion or cancellation has actually finished.

Echo availability does not imply arbitrary ICMP-error reception. A Linux ping socket may suffice for echo but not the desired trace diagnostics. Document precisely which backend produced each result. Native Windows ICMP does not require bundling Npcap; test permissions and endpoint-security restrictions instead of assuming admin is required or sufficient.

## DNS details

There is no universal Linux DNS cache. Support installed providers explicitly; `systemd-resolved` gained `resolvectl show-cache` in version 254 ([upstream manual source](https://github.com/systemd/systemd/blob/main/man/resolvectl.xml)). Feature-detect commands and output, with size/time limits. Windows exposes cache collection through the [DnsClient module](https://learn.microsoft.com/en-us/powershell/module/dnsclient/?view=windowsserver2019-ps). Do not depend on undocumented cache-enumeration DLL exports.

An ordinary Go resolver may not reproduce every OS/VPN split-DNS policy or expose the selected upstream. Prefer platform resolver adapters, such as [DnsQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsqueryex), where necessary; record policy mode and any unknown upstream. An explicit-resolver backend offers tighter query accounting but must be selected deliberately because it can bypass platform policy. Cache-only lookup of an already known name is distinct from enumeration of all cached names.

Use cache TTL/age when available, otherwise mark freshness unknown. Key DNS observations by resolver context and routing epoch. Do not refresh cached entries in passive mode. No fallback to public DNS, multicast DNS, LLMNR, or NetBIOS discovery by default.

## Privileges and packaging

On startup, attempt read-only capabilities and socket creation, without sending discovery packets. Emit the resulting matrix. Retry capability failures only on an explicit refresh or relevant state change. Never invoke sudo, request UAC elevation, change sysctls, enable interfaces, or install drivers automatically.

Current Linux namespace and Windows compartment are the default observation contexts. Additional namespaces, VRFs, and compartments need explicit selection and backend support. Running as root/admin does not automatically traverse them. Record inaccessible contexts as coverage gaps; do not silently label the current context as the whole host.

Candidate dependencies: `golang.org/x/sys` for native access, `golang.org/x/net/icmp` and IPv4/IPv6 helpers, and a maintained netlink package after API/license review. Use `encoding/json`, `encoding/csv`, `flag` or a small CLI library, and `net/netip` for the core. Pin versions when implementation starts; no dependency or Go version is selected by this document. Prefer pure-Go builds, but validate native resolver behavior before making “CGO disabled” a release requirement.

Proposed first support matrix: Linux amd64/arm64 on Ubuntu LTS and a RHEL-compatible distribution; Windows 11 and Windows Server 2022/2025 amd64. Exact minimum kernel/OS versions and Windows arm64 are gated on the capability spike. Cross-compilation alone is not platform validation.

Helpers, where unavoidable, use fixed executable paths/argument arrays without a shell, structured output, bounded output capture, and deadlines. PowerShell absence or execution policy can disable cache collection without disabling discovery. Never interpolate imported names into executable command strings.
