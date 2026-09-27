# CLI, output, and reliability contract

All commands and flags below are proposed interfaces.

## Typical workflow

```sh
# Local collection: no active DNS, echo, TCP, or trace traffic.
lanscan --format text

# Preview what intensity 2 would probe; sends nothing.
lanscan --intensity 2 --seeds hosts.txt --plan

# Bounded validation with a recoverable journal and streamed CSV view.
lanscan --intensity 2 --include 10.20.0.0/16 --exclude 10.20.50.0/24 \
  --seeds hosts.txt --realm corporate --vantage brisbane --journal scan.jsonl \
  --format csv --output hosts.csv

# A preset with one advanced override and stronger journal durability.
lanscan --intensity 3 --trace 0 --journal durable.jsonl --sync every-event

# Recover after interruption; refresh network context before new work.
lanscan resume --journal scan.jsonl

# Offline materialization and combination: no discovery traffic.
lanscan export --journal scan.jsonl --format csv-findings --view latest
lanscan merge office-a.jsonl office-b.jsonl --format jsonl
```

`hosts.txt` contains one IP or approved FQDN per line, with blank lines and `#` comments allowed. FQDN seeds require active DNS to resolve; passive mode records them as unresolved. Explicit `--dns-suffix` controls allowable name queries. Prefix inventories use CSV fields `realm,prefix,kind,source,observed_at`; `kind` distinguishes subnet, allocation, and route. Invalid lines identify file/line and fail validation before active work. Hostnames, IPs, and CIDRs are validated as data.

`--intensity` (0 to 3, default 0) is the one probing control most runs need; the README tabulates what each level adds. Each level is a preset of the advanced controls `--rate`, `--concurrency`, `--max-operations`, `--timeout`, `--tcp-port`, `--dns-budget`, `--trace`, `--trace-hops`, `--trace-budget`, `--sample-per-prefix`, `--neighbours`, `--retry` and `--refresh-interval`, which are rejected at intensity 0. `--listen DURATION` (Linux, CAP_NET_RAW) records evidence from broadcast and multicast traffic before planning and fails rather than continuing without capture; see the README for what it parses. Other controls: `--interface`, `--source`, `--dns-suffix`, `--resolver`, `--no-ipv6`, `--scope-from`, `--candidate-limit`, and `--disk-budget`. `--retry 1` gives each target whose attempts all ended in silence one more attempt (echo, or TCP when echo is unavailable) after every first attempt; ICMP errors and refusals are answers and are not retried. `--neighbours N` guesses the first usable host of N sibling prefixes on each side of each known IPv4 prefix from /16 to /30, skipping siblings inside a known prefix at least as specific as the sibling (or /24); probe events carry `neighbour_of`. `--candidate-limit` caps distinct address/name entities and, separately, distinct prefixes, so a large seed list cannot crowd out prefix evidence. The fallback TCP port is 443, one connect attempt after inconclusive echo; it sends no application payload. Absence of a service response is inconclusive.

Configuration precedence: built-in defaults, the intensity preset, config file, then CLI. Print the resolved configuration in the run header. `--plan` performs local reads only and shows unresolved names, candidate counts, scope, budgets, and capabilities; it cannot predict later DNS answers or guarantee a final packet count.

## Data model

Canonical journal event types:

- `run_started`, `capability`, `collector_status`, `routing_epoch` (with `detection`: `notification` from rtnetlink or IP Helper, or `polling`), `resolver_change`.
- `observation`: immutable source evidence, including routes, addresses, cache records, and probe outcomes.
- `finding_upsert`: derived host/prefix state, with monotonically increasing per-entity revision and evidence references.
- `checkpoint`, `run_finished`: progress and completion/stop reason.

Every event has `schema_version`, `event_id`, `run_id`, `seq`, `observed_at`, `recorded_at`, `type`, `realm_id`, `vantage_id`, and `routing_epoch`. IDs and ordering are local-run stable; merge preserves origin IDs. Wall clock timestamps use UTC RFC 3339; elapsed deadlines use a monotonic clock. Cached observation time can be unknown and must not default to “now.”

Entity keys include realm and prefix/address; reachability assertions also include vantage, epoch, source/interface, protocol and port. IPv6 zones are separate fields. Normalize prefix bits and mapped addresses deliberately, preserving original input in evidence when needed. Unknown prefix is `null`, not `/32` or `/128` masquerading as a subnet. Route-derived host prefixes remain distinguishable by basis.

Illustrative finding event (pretty-printed here; the actual journal uses one physical line):

```json
{
  "schema_version": 1,
  "event_id": "r1:42",
  "run_id": "r1",
  "seq": 42,
  "observed_at": "2026-09-26T00:03:02Z",
  "recorded_at": "2026-09-26T00:03:02Z",
  "type": "finding_upsert",
  "realm_id": "corporate",
  "vantage_id": "brisbane",
  "routing_epoch": 1,
  "entity_id": "corporate:prefix:10.20.8.0/24",
  "revision": 2,
  "prefix": "10.20.8.0/24",
  "prefix_basis": "route",
  "activity_basis": "active_response",
  "reachability": "endpoint_response",
  "target": "10.20.8.17",
  "source_address": "10.20.1.8",
  "interface_id": "eth0",
  "protocol": "tcp",
  "port": 443,
  "outcome": "connected",
  "evidence_ids": ["r1:9", "r1:41"]
}
```

The `/24` above came from a route observation, not from the TCP result. A route-only finding has no active-response assertion. Preserve conflicting and historical evidence; a new timeout does not delete an earlier positive response. The latest view distinguishes last tested outcome from last positive observation and displays their timestamps.

## Formats

JSONL is the lossless event stream and canonical journal. Unknown optional fields are tolerated by readers; unknown major schema versions fail clearly. JSON control characters are escaped, so truncated final lines can be isolated.

CSV streams finding revisions with a fixed header: `schema_version,run_id,seq,entity_id,revision,realm_id,vantage_id,routing_epoch,observed_at,prefix,address,prefix_basis,activity_basis,reachability,protocol,port,outcome,evidence_ids`. List fields use compact JSON inside a properly escaped CSV cell. Empty unknown values are documented, not converted to zero. Append-only CSV can contain multiple revisions of the same entity; `export --view latest` materializes one row per entity and reachability context. A companion JSONL journal retains full provenance and diagnostic detail. CSV intended for spreadsheets neutralizes formula-leading text; offer explicit raw export for exact field fidelity.

Text prints one useful change per line plus a final coverage summary; no full-screen refresh is required. Progress, warnings and diagnostics go to stderr. Machine output on stdout must never contain banners, colors, or progress bars. Terminal color is auto-detected and disabled when redirected.

## Streaming and durability

Open and validate output files before active work. `--journal FILE` creates an exclusive recoverable journal; without it, results only stream to the output. Fail before probing if that location is unwritable. Do not overwrite existing files; appending to an existing run requires `resume`.

Write every event promptly through one writer; flush user-space buffers at each complete record. Derived findings follow their evidence in the journal. CSV and text findings flush on each row/line. Streaming means data is handed to the OS or pipe as produced, not held until scan completion.

Default regular-file sync policy: sync at least every second or 100 events, whichever comes first, plus clean shutdown. This limits the intended unsynced tail under normal storage behavior but is not a hard power-loss guarantee. `--sync every-event` calls file sync before acknowledging each event; the increased disk latency can throttle discovery. Filesystem/hardware behavior still matters. Flushing a buffer is not equivalent to syncing storage. Pipes and remote filesystems cannot promise local-disk durability; describe the selected sink accurately.

On disk full, sync error, journal failure, or broken required output pipe: cancel new work, report the failure on stderr, and exit nonzero. Never silently drop records and continue probing. Slow sinks apply bounded backpressure all the way to scheduling. Collectors that cannot be backpressured must resnapshot or emit a gap, not quietly lose evidence.

SIGINT/termination handling stops scheduling, cancels operations, drains completed evidence with a bounded grace period (proposed 5 seconds), syncs, and emits `run_finished` if possible. Forced termination can leave a partial final line. Previously complete JSONL records remain independently readable; absence of `run_finished` marks an incomplete run. Live CSV may have an incomplete final row; regenerate it from the journal after recovery.

## Replay and resume

1. Acquire an exclusive run lock; reject concurrent writers.
2. Validate schema, config hash, sequence integrity, and complete records. Preserve a backup of a torn final fragment before truncating it. Fail on corruption in the middle of the journal.
3. Rebuild findings and completed work from events; checkpoints accelerate replay but never replace the journal as authority.
4. Re-read interfaces/routes/resolver policy and begin a new epoch. Recompute pending scope and candidates. Retain the original scan scope/exclusions unless explicitly revised and journaled.
5. Reuse fresh observations for planning, but do not relabel historical positive responses as current reachability. Revalidation consumes the remaining budget.

Checkpoint files use a temp file plus replacement, reference a synced journal sequence, and are disposable if invalid. Record operation reservation before dispatch. After a crash, an operation with no result is “outcome unknown”; count its reservation as spent to avoid silently exceeding the budget. Repeating it is allowed only as a newly budgeted attempt. Delivery/replay is at-least-once with ID deduplication, not an exactly-once network guarantee.

Per-run operation budgets persist across resume. The duration limit applies to cumulative active runtime; explicit budget extension creates a recorded configuration revision. Merge deduplicates origin event IDs, not unrelated observations of the same IP. Imported journals are data only and cannot change active scope or configuration.

## Completion and exit behavior

| Code | Meaning |
| --- | --- |
| 0 | Finished configured work; no claim of complete organisational coverage |
| 1 | Fatal runtime/output failure |
| 2 | Invalid arguments, scope, or input |
| 3 | Partial run: time/budget/capacity exhausted, required collector failure, or unavailable explicitly required capability |
| 130 | Interrupted by user, where supported by platform invocation |

Optional unsupported collectors are warnings and appear in coverage accounting; they do not automatically make otherwise completed work fail. `--require-capability` can make a capability mandatory. Zero responding hosts alone is not an error.

The final event includes elapsed time, operation counts by backend, accounting limitations, candidates attempted/untried, skips by reason, prefix evidence categories, collector status, output/sync mode, and stop reason. Do not include secrets from future authenticated adapters in the resolved configuration or journal. Local DNS names and addresses are inventory data; create files with restrictive permissions where supported and no automatic uploads.
