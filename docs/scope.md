# Product scope

## Users and jobs

- IT teams: discover reachable office and VPN address ranges before troubleshooting or inventory work.
- Network teams: compare installed routes and actual endpoint reachability across sites and VPN states.
- Security teams: establish evidence-backed discovery scope and identify visibility gaps before further assessment.

The output is a time-bound discovery report, not an authoritative IPAM replacement or a declaration that an entire network is reachable.

## Definitions and result contract

| Concept | Meaning |
| --- | --- |
| Configured prefix | Prefix reported by a local interface or named inventory source; configuration may be stale |
| Route prefix | Destination range in a routing table; may aggregate many subnets or be a default, reject, or blackhole route |
| Observed address | IP from a cache, DNS, hop response, connection table, or imported source; mask may be unknown |
| Used | Activity evidence with a timestamp and source; cached evidence is historical, not proof of present use |
| Endpoint response | Correlated ICMP echo, TCP connection/refusal, or other response for a specific address and protocol |
| Reachability | Outcome for a target, protocol/port, source address, routing context, and time; not a universal property |
| Subnet with responding endpoint | Known prefix contains a responding address; does not establish reachability of every address or prove a VLAN boundary |
| Unknown | Insufficient evidence, including silence, blocked collectors, and exhausted budgets |

Do not overload one confidence score with all these meanings. Report `prefix_basis`, `activity_basis`, `reachability`, and supporting evidence separately. An optional ranking score is for scheduling only and must not be presented as a probability.

Prefix basis is `interface`, `route`, `inventory`, or `unknown`. Route evidence establishes a route boundary, not necessarily a physical subnet. An imported administrative allocation can also contain many subnets. DNS and traceroute alone never establish a prefix length. A host route remains a host route, not an inferred LAN.

Examples:

- `10.0.0.0/8` through a VPN: installed aggregate route, downstream layout unknown.
- `10.24.7.19` answers TCP/443: endpoint response; no invented `10.24.7.0/24`.
- An interface declares `10.24.7.0/27`: configured local prefix; a neighbor response adds evidence of activity.
- Router returns network-unreachable for `10.24.7.19`: path failure for that probe, not proof that a `/24`, `/16`, or the entire VPN is unused.
- PTR record exists: naming evidence; neither present host activity nor connectivity is established.

## Requirements

| Priority | Requirement | Observable acceptance condition |
| --- | --- | --- |
| P0 | Honest coverage | Every prefix has provenance; standalone IPs retain unknown masks; untested candidates and collector gaps are reported |
| P0 | Multiple techniques | Interfaces/routes, neighbor caches, imported seeds, ICMP and TCP validation available; DNS/cache and trace adapters degrade explicitly |
| P0 | Low noise | Central rate and total budgets cover all active jobs; no address-range sweep by default |
| P0 | Timely results | Findings written as produced; no dependency on scan completion |
| P0 | Linux and Windows | Native collectors and actual OS integration tests under standard and elevated users |
| P0 | Capability-based operation | Attempt supported operations; report denied/unsupported capabilities and continue useful work |
| P0 | Ergonomics | CSV, JSONL, text; stable machine schemas; progress on stderr |
| P0 | Bounded resources | Finite queues, deadlines, memory limits, cancellation, output backpressure |
| P0 | Reproducibility | Record configuration, scope, capabilities, versions, routing context, seeds, and stop reason |
| P1 | Broader coverage | Resolver-aware enrichment, selected traces, offline merge across vantage points, inventory imports |
| P1 | Recovery | Journal replay, explicit incomplete runs, conservative resume after network changes |

## Scope and traffic policy

Bare `lanscan` (intensity 0) performs local collection only. This is a useful zero-probe baseline, including any readable DNS cache. At intensity 1 and above, scope defaults to RFC 1918 and IPv6 ULA space unless `--include` is given; the intensity's target generators, not the scope, bound what is probed. `--plan` shows candidates and budgets without emitting discovery traffic.

Route-derived scope (`--scope-from routes`) accepts explicit non-default unicast route prefixes in RFC 1918 or IPv6 ULA space. Other ranges, including organisation-owned public space and shared address space, require explicit inclusion. Do not treat private addressing as proof of ownership. Default routes, including split-default pairs, are not scope grants. Loopback, unspecified, multicast, and IPv4 broadcast destinations are never generated as unicast probes. IPv6 link-local destinations require an interface zone and explicit interface scope.

Exclusions always win, including after DNS resolution. Link-local collection remains useful even when active link-local probes are disabled. Administrative scope and candidate generation are separate: including `10.0.0.0/8` permits selected probes; it does not enqueue every address.

DNS servers are separate infrastructure destinations. Use only configured or explicitly supplied resolvers; validate resolved target IPs against scope before probing. Reject name expansion outside configured organisational suffixes. Do not send internal names to public fallback resolvers. System DNS can still follow organisational forwarding rules; record resolver selection and limitations.

## Coverage boundaries

VLANs invisible to the local machine, disconnected VPNs, silent endpoints, overlapping address space, firewalls, NAT, policy routing, IPv6 privacy addresses, and split DNS all limit coverage. A default route contributes almost no information about remote subnet boundaries. Root does not remove these limits.

Report counts of configured/route/inventory prefixes, observed hosts, prefixes with responsive targets, tested/untried candidates, and failures/skips by reason. Only report a coverage percentage against a named inventory or explicit candidate denominator. Never call candidate completion “percent of organisation discovered.”

Organisation-wide discovery requires multiple vantage points and/or administrative data: IPAM, router/SD-WAN route exports, DHCP scopes/leases, DNS exports, and cloud route inventories. Store source timestamps and compare disagreements. Do not automatically equate a DHCP scope, address allocation, route, and VLAN.

## Release boundaries

First release: standalone CLI, IPv4/IPv6 data model, Linux/Windows collectors, file imports, bounded validation, DNS enrichment where available, targeted trace capability where verified, streamed outputs, offline export/merge, and recovery.

Later adapters: authenticated IPAM, DNS/DHCP, router, SNMPv3, cloud, and SD-WAN APIs. These are valuable for coverage but need vendor-specific authentication, pagination, access, and testing. Start with exports to avoid delaying the core.

Out of scope: vulnerability scanning, port enumeration, credentials guessing, automatic routing changes, arbitrary packet capture, automatic network namespace traversal, unrestricted DNS brute force or zone transfers, and comprehensive host inventory. An explicitly selected TCP service is a reachability probe; it is not a service scanner.
