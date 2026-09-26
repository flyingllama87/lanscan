# Delivery plan and validation

## Milestones

Each milestone produces independently reviewable behavior. Effort ranges are planning estimates for one experienced Go developer with Windows and Linux test environments; they exclude vendor integrations and external release processes.

| Milestone | Deliverable | Exit gate | Indicative effort |
| --- | --- | --- | --- |
| 0: feasibility | Native route/neighbor reads, standard-user ICMP, DNS cache/resolver and trace prototypes on both OSes | Record actual permission and routing behavior; settle support matrix and backend limitations | 1–2 weeks |
| 1: passive foundation | CLI, evidence model, imports, local collectors, JSONL/CSV/text, scope planner | No discovery traffic in passive mode; streamed and replayable output; no fabricated prefixes | 2–3 weeks |
| 2: bounded validation | Scheduler, source/route checks, IPv4/IPv6 echo/TCP, budgets, change epochs | Controlled traffic and correct unknown/negative semantics in lab | 2–3 weeks |
| 3: coverage and recovery | Resolver-aware DNS, supported targeted trace, resume, export, offline merge | Split-DNS, interrupted runs, overlapping realms and multiple vantage points pass | 2–3 weeks |
| 4: hardening | Native OS CI, fault injection, performance tuning, packaging/help | Acceptance matrix passes; documented limitations and measured profile defaults | 1–2 weeks |

Total planning envelope: roughly 8–13 developer-weeks. Re-estimate after milestone 0; Windows native bindings, split-DNS fidelity, route-context binding, and crash recovery are the main uncertainties. Do not shorten the estimate by treating cross-compilation as cross-platform testing.

## Test environments

Use isolated Linux namespaces/virtual routers and Windows VMs with a controlled DNS server and packet capture outside the tool. Include an independently maintained ground-truth inventory. Test non-admin Windows, elevated Windows, ordinary Linux user with and without ping socket permission, and Linux with specific capabilities/root.

| Scenario | Required behavior |
| --- | --- |
| Flat LAN, `/27`, `/31`, `/32`, IPv6 `/64` and `/128` | Preserve configured masks; no address-based mask guesses; valid edge-address handling |
| Default-only route | Report limited topology visibility; no automatic sweep |
| VPN aggregate containing several hidden subnets | Retain aggregate; discover seeded endpoints without inventing downstream boundaries |
| Split-tunnel and full-tunnel VPN, including split default routes | Scope defaults remain bounded; route changes create new epochs |
| Policy routing, multiple NICs, VRFs/compartments | Source/context are recorded; unsupported forced egress yields an explicit skip |
| Overlapping office ranges | Separate realms; merge never collapses unrelated networks |
| ICMP blocked but TCP/443 responding | Fallback produces endpoint evidence |
| All methods silently dropped | Unknown; no false “unused subnet” verdict |
| Network/host unreachable and administrative deny | Preserve type/code/status and reporting context; no sibling-prefix pruning |
| Proxy ARP, stale neighbors, NAT and TCP proxy | No physical-host identity claim from address response alone |
| Asymmetric, ECMP, tunneled and silent-hop paths | Trace reports partial path and uncertainties; does not infer masks |
| Split DNS, wildcard DNS, NXDOMAIN, stale cache, missing cache provider | Correct resolver context, bounded queue growth, no DNS-to-liveness inference |
| IPv6-only, link-local with duplicate address on different interfaces | IPv6 validation and zone-aware identity; no numerical address sweep |
| VPN disappears during scan | Stop stale work, refresh context, preserve prior observations |
| Low privileges / blocked PowerShell / unsupported native API | Useful remaining techniques continue; capability gaps visible |
| Slow sink, disk full, broken pipe, short write, failed sync | Backpressure or fail promptly; no silent evidence loss |
| Kill during record, checkpoint, and probe execution | Complete records replay; incomplete run explicit; unknown operations count against budget |
| Malformed inputs/replies, DNS loops, massive imports | Bounded parsing, no command injection, no unbounded recursion/allocation |

## Acceptance criteria

Accuracy:

- Every reported prefix has source evidence and the original prefix length; zero invented masks in the ground-truth suite.
- All supplied, readable interface/route/inventory prefixes appear unless excluded by a documented resource limit. Test import completeness independently of active reachability.
- Known eligible seeded endpoints that respond within deadlines are detected in the deterministic lab; report seeded endpoint recall separately from subnet inventory coverage.
- No silence, PTR, cache record, or unrelated ICMP error is promoted to current endpoint reachability.
- Positive responses are associated only with correlated targets/context; overlapping routes do not multiply subnet counts.
- Compared with ground truth, report prefix provenance precision, inventory coverage, responding-target recall, and unknown/skipped counts. Do not combine them into a misleading single accuracy percentage.

Noise and time:

- Passive mode generates no tool-initiated discovery traffic, verified by packet capture. Incidental OS traffic is identified separately.
- Application operations never exceed configured global, per-path, method, or total budgets, including retries and trace hops.
- Measure wire packets/bytes, TCP retransmissions, ARP/NDP, and DNS amplification separately from application operations.
- In a controlled 100-prefix estate with one known responsive seed per prefix and sufficient budget, detect all 100 within the 120-second profile. Include WAN latency/loss variants and explain incomplete results.
- Proposed local-collection target: first finding within 2 seconds when a local collector can return within that time. A stalled optional collector must not delay other results.
- Proposed resource target: below 150 MiB resident memory for 100,000 candidates and 10,000 prefixes, with journal size measured separately. Benchmark CPU, handles, file descriptors, and steady-state allocations; these are release gates to validate, not achieved measurements.
- Compare the same fixtures against a naive sweep baseline by response coverage per packet and elapsed time. The goal is evidence-led coverage at lower traffic, not equal coverage of all silent or unseeded networks.

Reliability and platform behavior:

- Findings are readable before run completion, including through a slow pipe.
- Kill tests recover every complete readable journal record; sync tests verify ordering and errors. Distinguish process-crash testing from power-loss durability claims.
- Resume does not reset the spent operation budget, duplicate entity revisions incorrectly, or use obsolete routing context as current evidence.
- Real Linux and Windows integration tests validate native structure layout, cancellation, source/interface selection, IPv6, and standard-user fallback.
- Fuzz imported records and ICMP/DNS decoding; run race detection for scheduler, writer, cancellation, and native callback ownership.

## Decisions and remaining research

Already selected: standalone Go CLI; evidence before inference; no default sweeps; passive default; explicit active scope; IPv4/IPv6 model; per-vantage reachability; canonical JSONL; append-only result revisions; capability detection rather than mandatory elevation.

Resolve during milestone 0:

1. Which OS-native backends reliably expose ICMP errors and TTL-limited results without elevation?
2. Can source/interface binding be enforced for each backend under relevant VPN and policy-routing configurations?
3. Which resolver APIs preserve Windows policy and Linux per-link domains, and what traffic accounting can they expose?
4. Is a maintained netlink library sufficient for route rules and source-aware lookups, or are additional native messages needed?
5. Are journal replay and bounded queues sufficient at target scale, or is an embedded index justified?
6. Which exact Linux/Windows releases are required by early adopters, and what corpus of VPN products should be tested?

Later product research: preferred IPAM and SD-WAN integrations, central orchestration versus offline run collection, authenticated router inventories, and operator-selected higher-coverage profiles. These should extend the evidence model rather than relax its inference rules.
