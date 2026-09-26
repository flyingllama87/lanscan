# Implementation progress

The original design documents remain the target. This checklist records current evidence and remaining work; it does not reduce release scope.

## Implemented

- Versioned event model, unknown prefix representation, immutable observations, revisioned findings, source/realm/vantage context, and evidence references.
- Append-only exclusive JSONL journals, file locking, per-record writes, periodic/every-event sync, sticky failures, disk budgets, strict replay, torn-tail detection with backup and truncation under lock.
- Resume: config-hash and input-snapshot verification, cumulative operation and runtime budgets, conservative runtime leases, unknown-outcome recovery of unfinished reservations, explicit budget extensions recorded as configuration revisions, new routing epoch on resume, checkpoints.
- Streaming JSONL/CSV/text, formula-safe CSV, offline latest export, origin-ID merge deduplication, and conflicting-event detection. Text output includes routing epochs, traces, capabilities and a coverage line.
- Validated bounded seed/inventory imports, passive default, explicit active scope, exclusions, private-route scope filtering, scoped planning, no numerical sweeps.
- Collectors: interfaces (all platforms); Linux rtnetlink routes/rules/neighbors; Windows native route/neighbor tables with route-type classification; hosts files; resolver configuration (Linux `resolv.conf` plus systemd-resolved per-link servers and routing domains; Windows adapter DNS servers and suffixes); DNS cache (systemd-resolved `show-cache`, Windows `Get-DnsClientCache`) through fixed-path, shell-free, bounded, deadline-limited helpers. Denied and unsupported collectors are reported as such.
- Source-aware kernel route lookup and source/interface socket binding; route recheck after dispatch pacing.
- Echo backends: Linux ping socket or raw ICMP with `IP_RECVERR` error-queue decoding, so hop-limited probes and ICMP errors are correlated on unprivileged ping sockets; Windows `IcmpSendEcho2Ex`/`Icmp6SendEcho2` with native status mapping and payload verification. Administrative prohibition is distinct from other path failures.
- Scheduler: global, per-path, DNS-rate and total budgets; a validation reservation (enrichment is capped at half the remaining budget); first attempts dispatched in planned priority order; synthetic samples after all evidence-backed candidates; RTT-informed timeouts that never exceed `--timeout`; per-path backoff after repeated loss or path errors; per-dispatch scope gate.
- DNS enrichment in active mode: forward resolution of supplied names (absolute queries, no search-list expansion, suffix-constrained when `--dns-suffix` is set), reverse PTR for responders, one forward confirmation of PTR names within approved suffixes, per-name/per-address answer caps, explicit or system resolver policy recorded on every observation, one reservation per exchange.
- Targeted traces (`--trace`): routed responders on distinct egress paths first, then unexplained failures; stops at destination, terminal failure, hop limit, budget, or three silent hops; transit hops recorded without scope expansion or masks.
- Opt-in synthetic sampling (`--sample-per-prefix`): first/last usable and midpoint inside IPv4 unicast prefixes with no host evidence, with `/31` and `/32` semantics; never IPv6.
- Routing epochs during active runs: topology polling (`--refresh-interval`), new epoch, re-collection of local evidence, route-derived scope refresh, and stale-job skipping.
- Coverage accounting in `run_finished`: prefixes by basis, prefixes with responding targets, tested/untested candidate prefixes, observed addresses by activity basis, operations by method, latest outcomes, skips by reason, and accounting limitations.
- Prefix index for containment lookups (planning, response association, sampling).
- Bounded shutdown: a 5-second grace period after interrupt even when an output sink blocks.
- Tests: unit/integration tests for persistence, corruption, scope, imports, evidence, streaming, cancellation, budgets, DNS, trace, sampling, ordering, parsers and ICMP error queues; fuzz targets for journal replay, imports, cache parsers, ICMP quotes and error queues; `scripts/netns-lab.sh`, an isolated routed topology that runs the real binary.
- CI workflow (`.github/workflows/ci.yml`): Linux race tests, short fuzzing, the namespace lab and cross-builds; native Windows Server 2022/2025 test and smoke runs.

## Required work remaining

- Windows runtime evidence remaining: VPN clients, endpoint-security products, Windows 11 and Server 2022/2025, arm64, and IPv6 traces over a routed network. Windows 10 and Server 2016 are validated (see below).
- Windows resolver fidelity: DnsQueryEx adapter and NRPT policy representation. Currently the Go system resolver is used and the limitation is recorded.
- Change notifications (netlink, IP Helper) instead of polling; resolver-change detection.
- Paris-style flow-stable tracing; Windows trace runtime validation.
- Optional single explicit retry per target; explicit round-robin fairness across interfaces beyond breadth-first ordering and per-path pacing.
- Candidate spill to an indexed store if benchmarks require it; complete memory bounds under the 100,000-candidate target.
- Delivery gates: packet-capture wire-traffic validation, the 100-prefix / 120-second acceptance estate, WAN latency/loss variants, performance and resource measurements, disk-full/short-write/failed-sync fault injection against the real binary, Windows VM topologies, and packaging/release artifacts.

## Verification so far

- `go test -race ./...` and `go vet ./...`: pass on Linux amd64.
- `GOOS=windows go vet ./...`: passes; Windows amd64/arm64 and Linux arm64 cross-builds compile. Cross-builds do not validate Windows runtime behaviour.
- `scripts/netns-lab.sh`: passes all scenarios with both the raw ICMP and ping-socket backends: passive traffic-free run, echo, TCP fallback when echo is dropped, two-hop trace with error-queue correlation, explicit-resolver DNS with suffix enforcement and PTR confirmation, and a route removed mid-run (new epoch; stale job skipped).
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
