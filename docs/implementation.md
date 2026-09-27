# Implementation progress

The original design documents remain the target. This checklist records current evidence and remaining work; it does not reduce release scope.

## Implemented

- Versioned event model, unknown prefix representation, immutable observations, revisioned findings, source/realm/vantage context, and evidence references.
- Append-only exclusive JSONL journals, file locking, per-record writes, periodic/every-event sync, sticky failures, disk budgets, strict replay, torn-tail detection with backup and truncation under lock.
- Resume: config-hash and input-snapshot verification, cumulative operation and runtime budgets, conservative runtime leases, unknown-outcome recovery of unfinished reservations, explicit budget extensions recorded as configuration revisions, new routing epoch on resume, checkpoints.
- Streaming JSONL/CSV/text, formula-safe CSV, offline latest export, origin-ID merge deduplication, and conflicting-event detection. Text output includes routing epochs, traces, capabilities and a coverage line.
- Validated bounded seed/inventory imports, passive default, exclusions, private-space default scope with optional route-derived scope, scoped planning, no numerical sweeps.
- `--intensity 0..3` presets over the advanced probing controls (explicit flags and config values override; resolved values are journaled), level-3 neighbour guesses (first host of sibling prefixes, claiming no prefix),, and `--no-ipv6`.
- `--listen` on Linux: receive-only AF_PACKET capture (BPF admits received broadcast, multicast and ARP; all-multicast membership, no transmission) that records ARP, DHCP, NDP/RA, OSPF, RIPv2, VRRP, HSRP, LLDP, CDP and service-discovery senders as `listen` observations; fails loudly without CAP_NET_RAW. Parsers are fuzzed; the lab checks heard evidence, `--no-ipv6`, zero transmitted frames and the no-capability failure.
- Collectors: interfaces (all platforms); Linux rtnetlink routes/rules/neighbors; Windows native route/neighbor tables with route-type classification; hosts files; resolver configuration (Linux `resolv.conf` plus systemd-resolved per-link servers and routing domains; Windows adapter DNS servers and suffixes, plus NRPT rules read from the local and Group Policy registry keys); DNS cache (systemd-resolved `show-cache`, Windows `Get-DnsClientCache`) through fixed-path, shell-free, bounded, deadline-limited helpers. Denied and unsupported collectors are reported as such.
- Source-aware kernel route lookup and source/interface socket binding; route recheck after dispatch pacing.
- Echo backends: Linux ping socket or raw ICMP with `IP_RECVERR` error-queue decoding, so hop-limited probes and ICMP errors are correlated on unprivileged ping sockets; Windows `IcmpSendEcho2Ex`/`Icmp6SendEcho2` with native status mapping and payload verification. Administrative prohibition is distinct from other path failures.
- Paris-style traces on Linux (raw and ping sockets): every probe of a trace keeps one ICMP identifier and checksum; only the sequence number changes, and a trailing payload word of `^seq` keeps the ones-complement sum constant (IPv4, and IPv6 with its pseudo-header). Ping sockets pin the identifier by binding it; a probe that cannot is labelled. `trace_finished` reports `flow_stable`. Windows reports `paris: false` because `IcmpSendEcho2Ex` assigns the identifier and sequence number.
- Scheduler: global, per-path, DNS-rate and total budgets; a validation reservation (enrichment is capped at half the remaining budget); first attempts dispatched in planned priority order, round-robin across evidence interfaces and then across prefixes; synthetic samples after all evidence-backed candidates; optional `--retry 1` for silent targets after every first attempt; RTT-informed timeouts that never exceed `--timeout`; per-path backoff after repeated loss or path errors; per-dispatch scope gate. Targets reached only through default, split-default or other very broad routes are planned as individual hosts rather than one "prefix", so one response cannot mark them all satisfied.
- DNS enrichment in active mode: forward resolution of supplied names (absolute queries, no search-list expansion, suffix-constrained when `--dns-suffix` is set), reverse PTR for responders, one forward confirmation of PTR names within approved suffixes, per-name/per-address answer caps, explicit or system resolver policy recorded on every observation, one reservation per exchange. On 64-bit Windows the system policy uses `DnsQueryEx` (DNS only: no hosts file, LLMNR, NetBIOS or suffix expansion; asynchronous and cancellable), so NRPT and per-adapter servers apply, and each observation records the configured NRPT rule that matches its query name.
- Targeted traces (`--trace`): routed responders on distinct egress paths first, then unexplained failures; stops at destination, terminal failure, hop limit, budget, or three silent hops; transit hops recorded without scope expansion or masks.
- Opt-in synthetic sampling (`--sample-per-prefix`): first/last usable and midpoint inside IPv4 unicast prefixes with no host evidence, with `/31` and `/32` semantics; never IPv6.
- Routing epochs during active runs: rtnetlink (link, address, route and rule groups) and IP Helper (`NotifyRouteChange2`, `NotifyUnicastIpAddressChange`, `NotifyIpInterfaceChange`) notifications, coalesced over 200 ms, with polling at `--refresh-interval` as the fallback; new epoch, re-collection of local evidence, route-derived scope refresh (with `--scope-from routes`), and stale-job skipping. Each epoch records its detection method. Resolver configuration changes are detected on the same triggers and recorded as `resolver_change` without a new epoch.
- Coverage accounting in `run_finished`: prefixes by basis, prefixes with responding targets, tested/untested candidate prefixes, observed addresses by activity basis, operations by method, latest outcomes, skips by reason, and accounting limitations.
- Prefix index for containment lookups (planning, response association, sampling).
- Capacity: `--candidate-limit` caps address/name entities and prefix entities separately (findings per entity are bounded too), and the reducer keeps only compact finding state. The CLI sets a 128 MiB soft Go memory limit unless `GOMEMLIMIT` is set.
- Journal sync is group-committed and runs outside the stream lock, so result events are not stalled behind an operation reservation's fsync.
- Library events are copied with a typed deep copy equivalent to the former JSON round trip (verified by test), about 15 times faster.
- Bounded shutdown: a 5-second grace period after interrupt even when an output sink blocks.
- Tests: unit/integration tests for persistence, corruption, scope, imports, evidence, streaming, cancellation, budgets, DNS, trace, sampling, ordering, retries, parsers and ICMP error queues; the whole active pipeline with injected probes (every operation reserved first); a 100,000-candidate / 10,000-prefix scale test; fuzz targets for journal replay, imports, cache parsers, ICMP quotes and error queues; `scripts/netns-lab.sh`, an isolated routed topology that runs the real binary.
- CI workflow (`.github/workflows/ci.yml`): `make vet lint vuln test fuzz lab release-all` on Linux (staticcheck and govulncheck pinned); native Windows Server 2022/2025 test and smoke runs. Dependabot tracks Go modules and actions. `make release-all` produces tarballs for every shipped platform with `SHA256SUMS`.

## Required work remaining

- Windows runtime evidence remaining: VPN clients, endpoint-security products, Windows 11 and Server 2022/2025, arm64, and IPv6 traces over a routed network. Windows 10 and Server 2016 are validated (see below).
- Windows resolver: the effective NRPT decision is not exposed by a documented API, so observations record the configured rule that matches, which can differ from Windows' choice (see below). Resolver-change detection on Windows relies on interface notifications and polling rather than a dedicated DNS-change notification.
- Flow-stable traces on Windows would need a raw-socket backend; `IcmpSendEcho2Ex` cannot hold the checksum constant.
- Candidate spill to an indexed store: not needed at the 100,000-candidate target (measured below); revisit only for larger limits.
- Delivery gates still open: failed-sync fault injection (needs a block-device fault layer such as dm-flakey), Windows VM multi-router topologies, WAN variants on Windows, and signed release artifacts.

## Verification so far

- `go test -race ./...` and `go vet ./...`: pass on Linux amd64.
- `GOOS=windows go vet ./...`: passes; Windows amd64/arm64 and Linux arm64 cross-builds compile. Cross-builds do not validate Windows runtime behaviour.
- `scripts/netns-lab.sh`: passes all scenarios with both the raw ICMP and ping-socket backends: passive traffic-free run, echo, TCP fallback when echo is dropped, two-hop trace with error-queue correlation, explicit-resolver DNS with suffix enforcement and PTR confirmation, and a route removed mid-run (new epoch; stale job skipped).
- Lab additions, run on 27 September 2026:
  - Paris traces checked on the wire: both backends' hop-limited probes carried one identifier and checksum, for example `id 20316`, `seq 30234` then `30235`.
  - A route removed mid-run with a 60-second poll interval started a new epoch by rtnetlink notification.
  - Passive run with 100 seeds and 100 inventory prefixes: zero packets captured, while a control ping in the same capture was seen.
  - Acceptance estate, default profile: 100/100 prefixes detected, run complete in 71.5 s (the extra time is 100 reverse-DNS lookups at 2/s). The vantage sent 102 packets for 100 echoes: the echoes plus ARP.
  - The same estate with 80 ms delay and 2% loss each way (netem): 100/100 in 80.1 s.
  - Journal on a 64 KiB tmpfs: exit 1 with "no space left on device"; all 139 streamed records were recoverable, and `export` reports the incomplete run (exit 3).
  - Output into a pipe closed after one record: the process stops at once with SIGPIPE (exit 141).
- Resources, 100,000 seeds and 10,000 inventory prefixes (plan mode, Linux amd64): 130 MiB peak RSS without a journal and 131 MiB with one (163 MiB journal, 7.7 s), down from 212 MiB. Previously all prefixes were dropped at this scale because seeds exhausted a shared findings cap. A durable operation reservation costs about 1.3–1.7 ms on ext4, far above the default per-path pacing of 5 per second.
- Windows Server 2016 VM, 27 September 2026, administrator and standard user: every test package passed.
  - IP Helper notifications fired for a route added and removed; a mid-run route change with a 60-second poll started an epoch by notification.
  - `DnsQueryEx` resolved a name routed only by an NRPT rule, returned NXDOMAIN correctly, and honoured cancellation with 32 concurrent canceled queries.
  - NRPT rules were read from the registry, including as a standard user.
  - A rule listing a forward namespace and a reverse namespace had its servers applied by Windows only to the forward one (`Get-DnsClientNrptPolicy` and `Resolve-DnsName` agreed). Separate rules applied to both. lanscan's resolution matched Windows, but the recorded configured-rule match overstated the reverse namespace, hence the wording `configured_rule_matches`.
- Native Windows, run in lab VMs on 26 September 2026: Windows 10 LTSC 21H2 (19044) and Windows Server 2016 (14393), each as administrator and as a standard user (medium integrity).
  - Every test package passed.
  - Native route and neighbor tables matched `Get-NetRoute`/`Get-NetNeighbor` exactly (16/16 and 23/23 routes, including Teredo IPv6).
  - Resolver configuration matched `Get-DnsClientServerAddress`, and cache parsing matched `Get-DnsClientCache`.
  - IPv4 and IPv6 native echo worked, including as a standard user, so ICMP and trace need no elevation.
  - A native trace across the libvirt router reported hop 1 as time exceeded (status 11013) and the router's reject as a terminal failure (11005).
  - These runs found and fixed three bugs: Winsock refusal/unreachable codes were misclassified, millisecond-rounded RTTs disabled timeout adaptation, and a killed helper was reported as `failed` instead of `timed_out`.
  - As a standard user, the `Get-DnsClientCache` CIM call is denied after about 10.7s, so the collector reports `timed_out` with that hint.
  - The Server 2022 VM has no completed Windows install and was not tested.
- Wire traffic, measured by host-side capture on a libvirt bridge between two Ubuntu 24.04 VMs (kernel 6.8, systemd 255):
  - Passive runs send nothing. Six passive runs (three unprivileged, three as root including DNS cache reading) produced zero packets; a control ping in the same capture was seen.
  - Packets per operation:

    | Operation | Packets |
    |---|---|
    | Echo with reply | 2 |
    | Echo dropped | 1 |
    | TCP connect, completed | 7 (SYN, SYN-ACK, ACK, server-pushed banner, ACK, FIN, RST; no payload sent) |
    | TCP refused | 2 |
    | Silent on-link address | 0 IP packets, 3 ARP requests |

    Each first contact with a neighbor adds 2 ARP packets.
  - Budget fix: when unprivileged echo is unavailable, echo attempts previously consumed operation budget while sending nothing. They are now skipped without reservation, so every reservation corresponds to a real attempt.
  - The systemd-resolved cache parser was checked against real `resolvectl show-cache` output as root: 15/15 records. That output uses `ifname=` and an ANSI prefix, which revealed and fixed a lost interface attribution.
- On this development host, unprivileged ping sockets are disabled (`ping_group_range` is `1 0`), so the loopback ICMP unit test skips outside the namespace lab.

No claim of complete organisational subnet visibility is made.
