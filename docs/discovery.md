# Discovery and inference

## Pipeline

1. Open outputs and journal; emit run configuration and detected capabilities.
2. Collect interface addresses, routes/rules, neighbors, resolver configuration and readable caches; import user-provided seeds/inventories.
3. Normalize evidence without losing source, interface, routing table, network realm, or timestamp.
4. Generate a bounded candidate set from actual observations and explicit prefixes.
5. In active mode, validate selected addresses; enrich names and trace selected paths within budgets.
6. Append evidence and changed findings immediately. Repeat local collection when topology changes.
7. Emit coverage accounting and stop reason. Budget exhaustion leaves candidates unknown.

## Technique assessment

| Technique | Useful evidence | Cost and privileges | Limitations / design decision |
| --- | --- | --- | --- |
| Interfaces and addresses | Exact configured prefix, address family, local attachment | Local reads, usually standard user | Point-to-point and virtual interfaces need classification; local configuration is not remote liveness |
| Routes and policy rules | Explicit prefixes, next hops, rejects, routing contexts | Local reads, normally standard user in current context | Aggregates/defaults hide subnets; table presence does not prove selection or forwarding |
| ARP / IPv6 neighbor cache | Recently used on-link addresses and neighbor states | Local reads, normally standard user | Stale/incomplete entries are not live hosts; remote traffic normally resolves only its next hop; proxy ARP can mislead |
| DNS cache | Names and candidate IPs recently resolved | Local reads, provider-dependent | Incomplete, stale, app-private caches inaccessible; negative answers are not unused networks |
| Hosts/configured DNS/DHCP server addresses | High-value known endpoints | Local reads | Small, potentially stale seed set |
| Optional local connection table | Recently contacted remote addresses | Visibility depends on OS/privilege | No process payloads; historical contacts and external targets require filtering; later collector |
| Forward DNS | A/AAAA and configured SRV records yield candidates | Resolver traffic; standard user | Split DNS and wildcard records; no prefix boundary; query only supplied/cached names and explicit service records |
| Reverse DNS | PTR names for known target IPs | Resolver traffic; standard user | No PTR sweep; reverse zones/delegations do not reliably describe IP subnet boundaries |
| ICMP echo | Positive endpoint response, RTT | Linux ping/raw socket or Windows ICMP API | Filtering and rate limits; silence is unknown |
| ICMP errors | Diagnostic path/address/protocol outcome | Depends on backend and available error detail | Validate correlation; no universal subnet pruning |
| TCP connect | Connection or refusal on selected port | Standard user, normal sockets | Firewall/proxy may respond; silent drops; no payload or service fingerprinting |
| Targeted traceroute | Responding transit addresses, path diversity | TTL/hop-limit probes; backend-dependent | MPLS, tunnels, asymmetry, ECMP, and hidden routers; hops reveal addresses, not subnet masks |
| Administrative imports | Named prefixes and high-quality seeds | Local files initially | Preserve allocation/route/subnet distinction, age, and source trust |

Linux exposes route and neighbor information through [rtnetlink](https://man7.org/linux/man-pages/man7/rtnetlink.7.html). Route selection can depend on source, policy, and VRF context; a destination-only longest-prefix lookup is insufficient ([ip-route](https://man7.org/linux/man-pages/man8/ip-route.8.html)).

## Candidate generation

Prefer specific evidence over synthetic addresses:

1. Fresh observed endpoints and imported known-live hosts within scope.
2. Gateways, DNS servers, and named service endpoints, when separately in scope.
3. Stale neighbors and positive DNS-cache records.
4. If explicitly enabled, a small deterministic sample inside a known IPv4 prefix with no host evidence.

No automatic RFC 1918 sweep, recursive binary subdivision, or one-probe-per-`/24` across aggregates. Common `.1`/`.254` guesses are only optional low-priority samples and must fit the actual prefix. For `/31` and `/32`, apply their semantics rather than excluding all addresses as network/broadcast. Never derive `/24` from an arbitrary IPv4 address or `/64` from an arbitrary IPv6 address. IPv6 candidates come from evidence rather than range enumeration; its address scale and discovery pitfalls are documented in [RFC 7707](https://www.rfc-editor.org/info/rfc7707/).

Retain parent aggregates and more-specific prefixes separately. A responsive address may be associated with all containing route ranges for reporting, but that does not create extra physical subnets. Use the most-specific known subnet/inventory unit for validation scheduling and deduplicate actual probe jobs across parent ranges.

Deduplication key: network realm, vantage point, routing epoch, source/interface, target (including IPv6 zone), method, and port. Cache successful probes within the run; do not repeat them because DNS or another route yields the same target. Host candidates without a known prefix receive a small per-host budget, not an invented subnet assignment.

Names learned through PTR can be resolved forward once within approved suffixes. Bound recursion depth, CNAME length, names per address, and total DNS answers. Wildcards and repeated answers cannot expand the queue indefinitely. DNS lookup failures only affect naming evidence. [RFC 8020](https://www.rfc-editor.org/info/rfc8020/) describes DNS subtree nonexistence; it is not evidence that the corresponding address range is unused.

## Evidence interpretation

| Observation | Recorded interpretation | Forbidden inference |
| --- | --- | --- |
| Correlated echo reply | Target-address response at this time | All addresses in containing prefix are reachable |
| TCP success | Service endpoint reachable for this source/port | Target is a physical host rather than a proxy/NAT endpoint |
| TCP refusal / correlated RST | Response on target flow, with responder uncertainty | Service is open or physical target identity is proven |
| ICMP time exceeded | Responding transit hop for this probe | Remote subnet mask or final-target reachability |
| Network / host unreachable | Reported path failure for quoted destination | Entire enclosing prefix is nonexistent |
| Administrative prohibition | Policy denial for this flow/path | Network unused |
| UDP port unreachable | Likely endpoint response if attributable to destination | Echo reachability or physical identity |
| No response / timeout | Unknown for this method and deadline | Offline host or unused subnet |
| Local no-route / reject / blackhole | Local routing constraint at observation time | Same result from another site or source |

Record ICMP family, type/code, reporting address, quoted destination and transport tuple, probe ID, and timing. Reject unrelated or malformed replies. Unattributable ICMP is an observation, not a probe verdict. ICMPv4 and ICMPv6 need separate decoding. Some native APIs expose only status codes; retain the status and mark missing quotation/responder data rather than claiming full correlation.

Router errors follow forwarding and policy conditions, with rate limiting; their meaning and restrictions are specified in [RFC 1812](https://www.rfc-editor.org/info/rfc1812/). The design therefore uses repeated path failures to reduce scheduling priority temporarily, never to erase prefixes or conclude that untested siblings are absent. A responder address itself may be outside probe scope: record it, but do not expand active scope to it.

## Scheduler and budgets

Proposed conservative active defaults, to be tuned in the lab:

| Control | Default |
| --- | --- |
| Maximum runtime | 120 seconds, including collector deadlines |
| Discovery operation starts | 20/second globally, burst 5 |
| Per egress interface / next hop | 5/second, burst 2; unknown path uses a shared bucket |
| In-flight network operations | 32 total; DNS maximum 4 |
| Total operation budget | 1,000, including retry attempts, DNS exchanges, and trace hops |
| Per known prefix validation | Up to 3 evidence-backed target addresses, stop after first positive unless detail requested |
| Per target | One echo, then one configured TCP port on inconclusive echo; at most one explicit retry |
| DNS budget | 100 exchanges total, 2 starts/second; included in global budget |
| Trace budget | At most 3 destinations, 16 hops each, 1 probe/hop, no retry by default |
| Synthetic address sampling | Disabled |

All limits apply together; the first exhausted hard limit stops relevant work. Allocate a validation reservation (at least half of operation budget) so enrichment cannot starve core probes. Breadth-first scheduling covers candidate prefixes before extra methods or additional samples; use fairness across interfaces/sites and aging so low-priority candidates are not indefinitely displaced. Once a prefix has a response, further probing needs a specific purpose, such as verifying a different routing context.

An operation budget is **not a hard packet budget**. TCP retransmissions/teardown, neighbor resolution, resolver retries and recursive DNS, and VPN encapsulation create additional traffic. Record application starts exactly and wire traffic estimates as estimates. Native resolver calls may hide multiple DNS messages; charge a conservative allowance and identify opaque accounting. A strict packet-rate guarantee is outside the first release. Measure actual wire amplification in validation and expose conservative timeout/retry settings.

Estimate probe service time as `max(operation_count/rate, operation_count × mean_duration/concurrency)`, plus dependencies and collection time; this is a planning approximation, not a deadline guarantee. For 1,000 starts at 20/second with a 2-second mean and 32 slots, the lower bound is roughly 63 seconds before path buckets or dependencies. A 120-second run may leave substantial unknown space on a large estate.

Use initial 1-second endpoint and 2-second DNS/trace deadlines, then per-path RTT-informed timeouts clamped to 250 milliseconds–3 seconds. Back off on repeated loss/errors and cap retries. Timeouts stay unknown, so slower VPNs can be assessed with a longer profile without corrupting earlier conclusions.

## Targeted path discovery

Trace evidence-backed destinations selected for distinct egress paths and unexplained failures. Hold flow identifiers stable where the backend allows to reduce ECMP artifacts; do not promise Paris traceroute without implementing it. Stop at the destination, a correlated terminal failure, hop limit, or three consecutive silent hops, recording the truncation. Shared responding hops can reduce trace priority but cannot prove downstream equivalence. Do not recursively trace every discovered hop.

## Changes and multiple vantage points

Associate observations with a routing epoch. Interface, route, VPN, or resolver changes start a new epoch; cancel stale queued probes, refresh scope/routing decisions, and retain historical observations. Recheck the selected route immediately before dispatch; if the intended interface cannot be enforced, skip with a reason rather than silently use another egress. A race with OS route changes remains possible and must be acknowledged in diagnostics.

Offline merge groups by operator-supplied network realm and keeps per-vantage reachability. Identical `10.1.0.0/16` prefixes in two overlapping VPN realms must not collapse. Without a supplied common realm, retain separation. Merge can say “observed reachable from office A, unknown from office B,” never “reachable everywhere.”
