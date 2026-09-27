# How lanscan finds subnets

This document describes what the current code does. For the design rationale and evidence rules, see [discovery.md](discovery.md).

A single host cannot see every subnet in an organisation. lanscan collects evidence in layers, from free and silent sources to bounded active probes, and it labels every result with its source. Every layer from a lower intensity also runs at the higher ones.

| Layer | Intensity | Sends traffic | Needs |
| --- | --- | --- | --- |
| [Local state](#local-state) | 0–3 | No | Standard user |
| [Your inputs](#your-inputs) | 0–3 | No | Files you supply |
| [Passive listening](#passive-listening) | 0–3 with `--listen` | No | Linux, CAP_NET_RAW |
| [Validation probes](#validation-probes) | 1–3 | ICMP echo, one TCP port | Standard user (ICMP may need CAP_NET_RAW) |
| [DNS enrichment](#dns-enrichment) | 1–3 | DNS queries to the system resolver | Standard user |
| [Traceroute](#traceroute) | 2–3, or `--trace N` | Hop-limited ICMP echo | As for ICMP |
| [Prefix sampling](#prefix-sampling) | 2–3 | Probes to guessed addresses | As above |
| [Neighbour guesses](#neighbour-guesses) | 3 | Probes to guessed addresses | As above |

Run order: inputs → local collectors → listening → planning → forward DNS → validation → reverse DNS → traceroute. Everything heard or read before planning can become a probe target.

## Local state

These collectors read the host's own state. They send nothing.

| Source | Linux | Windows | What it yields |
| --- | --- | --- | --- |
| `interfaces` | rtnetlink | `GetAdaptersAddresses` | The subnets this host is attached to, with exact prefix lengths, and this host's own addresses |
| `routes` | rtnetlink, all routing tables | `GetIpForwardTable2` | Every routed prefix, next hops, reject/blackhole routes, and the default gateway |
| `rules` | rtnetlink policy rules | — | Which routing tables are used; this explains policy routing and VRF setups |
| `neighbors` | rtnetlink ARP/NDP cache | `GetIpNetTable2` | Recently used on-link addresses and their MACs, including cache state (a stale entry is not a live host) |
| `resolver_config` | resolv.conf, `resolvectl dns`/`domain` | adapter DNS settings, NRPT | DNS server addresses and search domains, which often sit in server subnets |
| `dns_cache` | `resolvectl show-cache` | `Get-DnsClientCache` | Addresses the host resolved recently, often internal services in other subnets |
| `hosts` | `/etc/hosts` | `drivers\etc\hosts` | Names for addresses. A hosts entry only names a host that other evidence found; it never adds a subnet |
| `topology_watch` | rtnetlink notifications | `NotifyRouteChange2` and similar | Starts a new routing epoch when a VPN or interface comes or goes during a run |

A route or interface prefix is a **known subnet** with an exact length. A single address from a neighbour, cache or resolver entry is a **host**. lanscan never invents a mask for it, such as assuming /24.

## Your inputs

- `--seeds FILE`: addresses, prefixes and names you know about, one per line.
- `--inventory FILE`: prefixes from an IPAM export or similar. These are reported with basis `inventory`.
- `resume` and `merge` carry evidence forward from earlier journals, recorded as source `history`.

Seed names are the only names lanscan resolves forward (see [DNS enrichment](#dns-enrichment)).

## Passive listening

`--listen DURATION` (short form `-l`) opens a receive-only `AF_PACKET` socket on Linux. This needs root or `cap_net_raw`. On other platforms, or without the capability, the run fails with an error and a `setcap` hint rather than silently skipping the step.

- A kernel BPF filter admits only received broadcast, multicast and ARP frames. It drops every frame this host sends and all unicast traffic addressed to other hosts.
- The socket sets `PACKET_MR_ALLMULTI` so the NIC delivers all multicast groups. This changes only the local receive filter, and nothing is transmitted.
- Listening runs for the given duration, before planning.

| Protocol | Evidence |
| --- | --- |
| ARP | Sender addresses and MACs on the local link |
| DHCP | The offered address and subnet mask (a prefix), the router, DNS servers, the DHCP server, and **classless static routes (option 121)**, which often name subnets beyond this link |
| RIPv2 | Advertised routes with their masks |
| OSPF hello | The link's network mask, router ID and area |
| VRRP, HSRP | Virtual gateway addresses |
| IPv6 router advertisements | On-link prefixes (PIO), route information (RIO) and DNS servers (RDNSS) |
| LLDP, CDP | Neighbouring switches and routers, their management addresses, port and system names |
| mDNS, SSDP, LLMNR, NetBIOS, IGMP | Sender addresses of live hosts |

Heard evidence is recorded with source `listen` and activity basis `passive_capture`. Up to 10,000 distinct sightings are kept. `--no-ipv6` ignores IPv6 frames.

## Planning

The planner builds a bounded list of targets from the evidence above:

1. Evidence-backed hosts: neighbours, gateways, DNS servers, cached or heard addresses, and seeds.
2. Samples inside known prefixes that have no host evidence (intensity 2 and above).
3. Neighbour guesses (intensity 3).

It only plans targets that are in scope:

- Active scope defaults to private address space: 10/8, 172.16/12, 192.168/16 and fc00::/7.
- `--scope-from routes` limits scope to prefixes this host routes.
- `--include` and `--exclude` narrow it further, and `--no-ipv6` drops IPv6 targets.

The planner never plans this host's own addresses or subnet broadcast addresses. IPv6 ranges are never enumerated. There is no sweep of any range. `--plan` prints the plan and sends nothing.

## Validation probes

For each target, in breadth-first order across prefixes and interfaces:

1. **Route lookup.** lanscan asks the kernel which interface, source and gateway it would use. It checks again just before sending, and records `route_changed` if the route moved, for example when a VPN dropped.
2. **ICMP echo.** On Linux this uses an unprivileged ping socket, falling back to raw ICMP. On Windows it uses `IcmpSendEcho2` or `Icmp6SendEcho2`.
3. **TCP connect** to one port (`--tcp-port`, default 443), sent only if the echo got no answer. A completed connection or a refusal (RST) both count as a response.

A response marks the target's prefix as satisfied, so the rest of that prefix is skipped. Each prefix gets at most three first attempts. At intensity 2 and above, a silent target gets one retry after all first attempts. An ICMP error or a refusal is already an answer, so it isn't retried.

A response means *this address answered from this vantage point, now*. It does not prove the rest of the prefix is reachable. Silence means unknown, not absent.

## DNS enrichment

All queries go through the system resolver or `--resolver`. There is never a fallback to public DNS, mDNS, LLMNR or NetBIOS. Queries are limited by the DNS budget for the intensity and `--dns-budget`.

- **Forward:** names from seeds are resolved once each for A and AAAA (A only with `--no-ipv6`). With `--dns-suffix`, only names inside those suffixes are resolved. The answers become candidates and go through scope like any other target.
- **Reverse:** after validation, PTR lookups are made for addresses that responded. There is no PTR sweep. PTR names inside an approved suffix are forward-confirmed once.

DNS gives names and extra candidates. It never gives prefix boundaries, and a missing record is not evidence that a range is unused.

## Traceroute

`--trace N` traces up to N destinations. It defaults to 4 at intensity 2 and 16 at intensity 3.

- **Targets:** routed responders on distinct egress paths come first, then targets with unexplained path failures. A discovered hop or an on-link target is never traced.
- **Probes:** one hop-limited ICMP echo per hop, on a stable flow (Paris-style), which reduces ECMP artefacts.
- **Stops:** at the destination, a correlated terminal error, the hop limit (`--trace-hops`), or three silent hops in a row. The route is re-checked between hops.

Each responding hop is a router address on a path, which is often a gateway into another subnet. Hops are recorded but never widen scope, and a hop address says nothing about its subnet mask.

## Prefix sampling

At intensity 2 and above (`--sample-per-prefix N`), lanscan probes up to N deterministic addresses inside each known IPv4 prefix that has no host evidence yet:

- the first usable host;
- then the last usable host;
- then the midpoint.

/31 and /32 prefixes follow their own rules. Samples are marked `synthetic_sample` and run after all evidence-backed targets.

## Neighbour guesses

At intensity 3 (`--neighbours N`), lanscan looks at each known IPv4 prefix from /16 to /30 and probes the first usable host of up to N sibling prefixes of the same size on each side. For example, 10.1.2.0/24 leads to 10.1.1.1 and 10.1.3.1. Networks are usually allocated next to each other, so this finds unrouted or summarised siblings cheaply.

- A sibling that is already known is left to sampling. A sibling counts as known when it falls inside a known prefix at least as specific as itself, or at least /24.
- Broad summary routes don't suppress guesses.
- Each guess is a single address, marked `neighbour_of` its source prefix.
- A response to a guess records the address as a host. It does **not** claim the sibling prefix exists with that length.

## Budgets and safety

Every active step draws from the same limits:

- a global operation cap (`--max-operations`);
- a start rate and per-path rate, with backoff after repeated loss;
- a concurrency limit;
- a per-operation timeout that adapts to measured RTT;
- an overall deadline (`--duration`).

DNS and traceroute together can use at most half of the remaining operations, so enrichment can't starve validation. When a limit runs out, the remaining targets stay *unknown* and the stop reason is reported.

Operations are counted when they start. They are not a packet count: TCP handshakes, ARP resolution and resolver retries add wire traffic that lanscan does not control.

## What it cannot see

- Subnets hidden behind a default or summary route, unless something names them: DNS, a trace hop, a DHCP route, or your inventory.
- Hosts and subnets that filter ICMP and the probed TCP port.
- Networks that are only reachable from another site or VPN. Run lanscan from each vantage point and `merge` the journals.
- Masks for remote addresses. A responding address stays a host until a route, interface, inventory or protocol advertisement supplies its prefix.
