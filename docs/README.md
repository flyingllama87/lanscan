# LAN subnet discovery: scope and design

Status: design target. Research checked 26 September 2026. Implementation status and remaining release gates are tracked in [implementation.md](implementation.md); performance figures here are targets, not measurements.

Build a Go command-line tool for IT, network, and security teams that discovers evidence of organisational IP networks and validates selected endpoints from the machine on which it runs. Prioritise defensible results, broad coverage, short runtime, and bounded traffic across Linux and Windows.

The central constraint is observability: **a single endpoint cannot guarantee discovery of all used or reachable subnets**. Default routes hide topology; VPNs and access policies restrict visibility; silent hosts reveal nothing; a responding IP does not reveal its subnet mask. The tool must expose those gaps rather than manufacture a complete network map.

## Documents

| Document | Contents |
| --- | --- |
| [Product scope](scope.md) | Requirements, terminology, coverage contract, release boundaries |
| [Discovery design](discovery.md) | Techniques, evidence rules, candidate generation, probe scheduling |
| [Go architecture and platforms](architecture.md) | Components, Linux/Windows adapters, privilege degradation |
| [CLI, data, and reliability](operations.md) | Commands, schemas, streaming, durability, resume, exit codes |
| [Delivery and validation](delivery.md) | Milestones, acceptance criteria, lab scenarios, open decisions |

## Recommended direction

Start with local route/interface/neighbor collection, seed and inventory imports, and bounded ICMP/TCP validation. Add resolver-aware DNS enrichment and targeted traceroute without turning either into a bulk enumerator. Preserve IPv4 and IPv6 evidence from the beginning. Support independent runs in different offices or routing domains and an offline merge for organisation-wide coverage.

Keep prefix existence, observed activity, and source-specific reachability separate. Preserve the prefix length supplied by an interface, route, or inventory; retain standalone IP observations when the network boundary is unknown. Use an append-only JSONL journal as the canonical record, with CSV and text renderers.

The first release should be useful without root/admin, a packet-capture driver, credentials, or a central service. Privileged operation should improve evidence collection using detected capabilities; it should not silently increase traffic budgets.
