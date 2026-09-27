# lanscan

Evidence-led LAN subnet discovery for Linux and Windows, written in Go.

This project is under active implementation. It reports configured and routed prefixes, observed addresses, and source-specific endpoint responses separately. An endpoint response never creates a guessed subnet mask. See [how subnets are found](docs/techniques.md), [the design](docs/README.md) and [implementation status](docs/implementation.md).

## Build and use

```sh
go build -o lanscan ./cmd/lanscan

./lanscan                    # passive: local state only, sends nothing
./lanscan -i 1               # also confirm addresses already in local evidence
./lanscan -i 2               # also sample known prefixes and trace a few paths
./lanscan -i 3               # also guess neighbouring prefixes
./lanscan -i 2 --plan        # show what it would probe; sends nothing
./lanscan --listen 30s       # first listen to the local segments (Linux)
./lanscan --help             # every flag, grouped, with examples

# Recover complete records and materialize the latest findings offline.
./lanscan export --journal scan.jsonl --view latest --format csv
./lanscan merge --format jsonl office-a.jsonl office-b.jsonl
```

### Intensity

| Intensity | Probes | Default budget |
|---|---|---|
| 0 (default) | nothing; reads interfaces, routes, neighbours, resolver configuration and, where permitted, the DNS cache | 0 |
| 1 | addresses already in local evidence (gateways, neighbours, DNS cache, seeds, inventory), plus reverse DNS for responders | 500 operations, 10/s |
| 2 | also up to 2 addresses in each known IPv4 prefix without host evidence, 4 traces, one retry for silent targets | 2,000 operations, 20/s |
| 3 | also the first host of 2 sibling prefixes on each side of every known IPv4 prefix (/16 to /30), 16 traces | 10,000 operations, 50/s |

No intensity sweeps prefixes or scans ports: every target is an evidenced address or a small, fixed number of guesses per known prefix. A response to a guess is reported as a host; it never invents a subnet mask. Without `--include`, active runs are scoped to private address space (RFC 1918 and fc00::/7); `--include` narrows that and `--exclude` always wins. `--no-ipv6` sends, captures and looks up nothing over IPv6. `--max-operations` caps the total.

### Permissions

On Linux, ICMP probes (where ping sockets are disabled) and `--listen` need root or CAP_NET_RAW. Grant it to the binary once with `sudo setcap cap_net_raw+ep "$(command -v lanscan)"`; without it, probes fall back to a TCP connect (the summary says so) and `--listen` stops with an error. Windows needs no extra rights to probe.

### Listening

`--listen DURATION` (Linux) first listens to broadcast and multicast traffic on every up, non-loopback interface (or `--interface`), then continues at the chosen intensity; heard prefixes are sampled at intensity 2 and above like any other known prefix. It records senders and what their frames claim: ARP (including hosts in subnets this machine has no address in), DHCP (leases with masks, gateways, DNS servers, relays, classless routes), IPv6 router advertisements (prefixes, routes, DNS servers), OSPF hellos (interface prefixes), RIPv2 routes, VRRP/HSRP virtual gateways, LLDP/CDP neighbours (name, port, VLAN, management address) and mDNS/SSDP/LLMNR/NetBIOS senders. It uses an AF_PACKET socket with a kernel filter that admits only received broadcast, multicast and ARP frames, and sets the interfaces to accept all multicast for its duration; it never transmits. It needs CAP_NET_RAW (see Permissions); without it, or on Windows, `--listen` fails before creating any file.

Every preset setting has an advanced flag (`--rate`, `--trace`, `--sample-per-prefix`, `--neighbours`, `--retry`, `--tcp-port` and others; see `lanscan --help`); explicit flags and `--config` values override the preset, and the journal records the resolved values. Library callers set `Config.Intensity` and optionally `Config.Tuning`, starting from `lanscan.Preset(n)`.

```sh
# Seeds, approved DNS suffixes and a narrower scope.
./lanscan --intensity 2 --include 10.20.0.0/16 --exclude 10.20.50.0/24 \
  --seeds hosts.txt --dns-suffix corp.example --journal scan.jsonl --format csv --output findings.csv
```

`hosts.txt` accepts one IP or hostname per line. Active runs resolve hostnames (A and AAAA, absolute names only) within the DNS budget; with `--dns-suffix`, only names inside approved suffixes are queried. `--resolver IP` selects an explicit DNS server, which can bypass platform split-DNS policy; by default the system resolver is used and its upstream is recorded as unknown. On 64-bit Windows the system resolver is the DNS client via `DnsQueryEx` (DNS only, so NRPT and per-adapter servers apply), and each DNS observation records the configured NRPT rule matching its name. Responders get one PTR lookup, and PTR names within approved suffixes are forward-confirmed once. DNS answers are candidates and naming evidence, never reachability. `--scope-from routes` adds private unicast routes of the current routing epoch to an explicit scope.

Active validation uses ICMP echo, then one TCP connect on `--tcp-port` if echo is inconclusive. Linux uses a ping socket or raw socket with correlated ICMP errors; Windows uses the native ICMP APIs. Neither sends application payloads. Traces send hop-limited echoes to selected responders; on Linux each trace keeps one ICMP identifier and checksum (Paris-style), so per-flow ECMP keeps it on one path. DNS and trace together may use at most half of the remaining operation budget. Operations are bounded, but OS-managed retransmissions and neighbor resolution mean operation counts are not packet counts. Unknown or silent targets are not declared unused. During active runs, interface, address, route and rule changes start a new routing epoch. They are detected by rtnetlink or IP Helper notifications, with polling as the fallback; resolver configuration changes are recorded too.

The default text output is a summary printed when the run ends: the subnets found (interface, this host's address, gateway, host counts), the hosts (names, MAC addresses, how each is known and, when probing, whether it responded), traced paths, the default route and DNS servers, anything that did not work, and a suggested next step. It leaves out loopback, multicast, link-local and this host's own routes. With `--plan` it lists the addresses it would probe and why. While a run works, a status line on stderr shows progress when stderr is a terminal. `-f csv` writes the same subnets and hosts as a table (one row each, spreadsheet-safe). For tools, `-f jsonl` streams every event and `-f csv-findings` streams finding revisions. `lanscan export -j run.jsonl` prints the summary from a journal. Without `--duration`, a run may take up to 1, 5, 15 or 30 minutes at intensity 0 to 3 (plus any `--listen` time) and ends sooner when its work is done. `run_finished` carries coverage counts relative to known prefixes and planned candidates. Journal and output files are created exclusively and never silently overwritten. A recoverable journal is kept only with `--journal FILE` (`-j`); `resume` needs one. `--sync every-event` requests stronger file durability at additional I/O cost. Progress and errors go to stderr. After an interrupt, the process drains for at most five seconds.

Go 1.27 is the current build environment. Run `make check` (vet, gofmt, staticcheck and race tests for Linux and Windows). Unit tests exercise loopback echo/TCP and injected probes only; they do not scan the host's LAN. `make lab` (`scripts/netns-lab.sh`, needs `tcpdump`) builds routed topologies in unprivileged Linux user and network namespaces and runs the real binary end to end, including wire captures, the 100-prefix acceptance estate and fault injection. Windows native tests run only on Windows (see `.github/workflows/ci.yml`); a cross-build does not validate native APIs at runtime.

## Make targets

Run `make` for help. `make build` creates `build/lanscan` (or
`build/lanscan.exe` for Windows), versioned from `git describe`. `make check`
runs vet, lint and the race-enabled tests; `make vuln`, `make fuzz`,
`make bench` and `make lab` run govulncheck, the fuzz targets, benchmarks and
the namespace lab. Linters are pinned and installed under `build/tools`.
Use `make install BINDIR="$HOME/.local/bin"` for a local installation.
`make release` packages the selected platform into `dist/`, and
`make release-all` builds Linux amd64/arm64/386 and Windows amd64/arm64
tarballs plus `SHA256SUMS`. Override `VERSION`, `BUILDDIR`, `DISTDIR`, `GOOS`,
or `GOARCH` as needed. Cross-building does not validate native networking at
runtime.

## Versions

`lanscan version` (or `--version`), `lanscan.Version()` and every journal's `run_started` event report the build's version. The source of truth is `Base` in `internal/version/version.go`. A build of an exact `v<Base>` tag reports `<Base>`, as does `go install` of that tag; any other build reports `<Base>-dev+<revision>`, with `.dirty` for uncommitted changes. To release, commit the final `Base` and then run `git tag v<Base>`; `make release` refuses a tag that disagrees with `Base`. Afterwards, bump `Base` to the next release. The journal schema version (currently 1) is separate and changes only with the event format.

The CLI sets a 128 MiB soft Go memory limit (`GOMEMLIMIT` overrides it); a
100,000-candidate, 10,000-prefix plan peaks at about 130 MiB resident.

## Go package integration

The root package exposes `DefaultConfig`, `Config`, `Tuning`, `Preset`,
`Discover`, `Event`, `Result` and `Version`. It uses the same discovery pipeline as the CLI, in-process. No signal
handlers or process exits are installed, and the library defaults to no journal
and no active network traffic.

```go
cfg := lanscan.DefaultConfig()
cfg.Realm = "office"
// To enable validation (Tuning follows the preset unless set):
// cfg.Intensity = 2
// cfg.Include = []string{"10.20.0.0/16"} // default: private address space
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
