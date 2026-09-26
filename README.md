# lanscan

Evidence-led LAN subnet discovery for Linux and Windows, written in Go.

This project is under active implementation. It reports configured and routed prefixes, observed addresses, and source-specific endpoint responses separately. An endpoint response never creates a guessed subnet mask. See [the design](docs/README.md) and [implementation status](docs/implementation.md).

## Build and use

```sh
go build -o lanscan ./cmd/lanscan

# Local information only; creates an incremental JSONL journal.
./lanscan discover

# Inspect candidates without sending probes.
./lanscan discover --active --include 10.20.0.0/16 --plan

# Validate evidence-backed addresses with bounded echo/TCP attempts.
./lanscan discover --active --include 10.20.0.0/16 \
  --seeds hosts.txt --tcp-port 443 --max-operations 1000 \
  --journal scan.jsonl --format csv --output findings.csv

# Recover complete records and materialize the latest findings offline.
./lanscan export --journal scan.jsonl --view latest --format csv
./lanscan merge --format jsonl office-a.jsonl office-b.jsonl
```

`hosts.txt` accepts one IP or hostname per line. In active mode, hostnames are resolved (A and AAAA, absolute names only) within `--dns-budget`; with `--dns-suffix`, only names inside approved suffixes are queried. `--resolver IP` selects an explicit DNS server, which can bypass platform split-DNS policy; by default the system resolver is used and its upstream is recorded as unknown. Responders get one PTR lookup, and PTR names within approved suffixes are forward-confirmed once. DNS answers are candidates and naming evidence, never reachability. Repeated `--include` and `--exclude` flags define scope; exclusions win, including after resolution. Scope inclusion does not enumerate its addresses. `--scope-from routes` explicitly accepts private non-default unicast route ranges.

```sh
# DNS-aware validation, two targeted traces, and explicit sampling of
# known IPv4 prefixes that have no host evidence.
./lanscan discover --active --include 10.20.0.0/16 --seeds hosts.txt \
  --dns-suffix corp.example --trace 2 --sample-per-prefix 1
```

Discovery is passive unless `--active` is specified. Passive runs also read resolver configuration and, where permitted, the local DNS cache (systemd-resolved 254+ or the Windows DnsClient module) without sending queries. Active validation uses ICMP echo, then one TCP connect on `--tcp-port` if echo is inconclusive. Linux uses a ping socket or raw socket with correlated ICMP errors; Windows uses the native ICMP APIs. Neither sends application payloads. `--trace N` sends hop-limited echoes to up to N routed destinations within `--trace-budget`. DNS and trace together may use at most half of the remaining operation budget. Operations are bounded, but OS-managed retransmissions and neighbor resolution mean operation counts are not packet counts. Unknown or silent targets are not declared unused. During active runs, interface and route changes (polled every `--refresh-interval`) start a new routing epoch.

JSONL contains all events; CSV/text stream findings as they change. `run_finished` carries coverage counts relative to known prefixes and planned candidates. Journal and output files are created exclusively and never silently overwritten. `--no-journal` opts out of recoverable local storage. `--sync every-event` requests stronger file durability at additional I/O cost. Progress and errors go to stderr. After an interrupt, the process drains for at most five seconds.

Go 1.27 is the current build environment. Run `go test -race ./...` and `go vet ./...`. Unit tests exercise loopback echo/TCP only; they do not scan the host's LAN. `scripts/netns-lab.sh` builds a routed topology in unprivileged Linux user and network namespaces and runs the real binary end to end. Windows native tests run only on Windows (see `.github/workflows/ci.yml`); a cross-build does not validate native APIs at runtime.

## Make targets

Run `make` for help. `make build` creates `build/lanscan` (or
`build/lanscan.exe` for Windows); `make test` runs the race-enabled test suite.
Use `make install BINDIR="$HOME/.local/bin"` for a local installation.
`make release` packages the selected platform, and `make release-all` builds
Linux amd64/arm64/386 and Windows amd64/arm64 tarballs. Override `VERSION`,
`BUILDDIR`, `GOOS`, or `GOARCH` as needed. Cross-building does not validate
native networking at runtime.

## Go package integration

The root package exposes `DefaultConfig`, `Config`, `Discover`, `Event`, and
`Result`. It uses the same discovery pipeline as the CLI, in-process. No signal
handlers or process exits are installed, and the library defaults to no journal
and no active network traffic.

```go
cfg := lanscan.DefaultConfig()
cfg.Realm = "office"
// To enable validation:
// cfg.Active = true
// cfg.Include = []string{"10.20.0.0/16"}
// cfg.Seeds = "hosts.txt"

result, err := lanscan.Discover(ctx, cfg, func(e lanscan.Event) error {
    if e.Type == "finding_upsert" {
        fmt.Printf("prefix=%v address=%s reachability=%s\n",
            e.Prefix, e.Address, e.Reachability)
    }
    return nil
})
if err != nil && !errors.Is(err, lanscan.ErrPartial) {
    return err
}
if result.Finished != nil {
    fmt.Println(result.Finished.Details["coverage"])
}
```

Start with `DefaultConfig()`; a zero `Config` is not valid. `Include` and
`Exclude` are CIDR strings; `Seeds` and `Inventory` are file paths. Set
`NoJournal = false` and `Journal` to enable recoverable storage. `Output` is
CLI-only; library consumers handle their own output through the callback.

Callbacks are serialized, receive independent snapshots, and may retain them.
Numbers in `Event.Details` use `json.Number`. Return an error to stop discovery;
the error is propagated. Callbacks must return promptly because context
cancellation cannot interrupt consumer code. `Discover` returns context errors
for caller cancellation and `ErrPartial` for incomplete runs. Findings already
emitted remain usable; inspect `run_finished` for the stop reason, collector
statuses, budgets, and coverage. Successful completion does not imply complete
network coverage. Resume, export, and merge remain CLI commands.

The current module name is `lanscan`. To integrate from another local module:

```sh
go mod edit -require=lanscan@v0.0.0
go mod edit -replace=lanscan=/absolute/path/to/lanscan
```

Then import `"lanscan"` and run `go mod tidy`. Before publishing for remote
`go get`, change the module path and internal imports to the repository's
canonical hosting path. Linux and Windows are the supported platforms.
