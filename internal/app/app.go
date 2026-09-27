// Package app connects the CLI to local discovery, journals, and renderers.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"lanscan/internal/importer"
	"lanscan/internal/listen"
	"lanscan/internal/model"
	"lanscan/internal/output"
	"lanscan/internal/version"
)

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

// Run returns an exit code without terminating the caller, allowing
// integration tests. Discovery is the default command.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cmd, rest := "discover", args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, rest = args[0], args[1:]
	}
	if len(args) > 0 && (args[0] == "--version" || args[0] == "-version" || args[0] == "-v") {
		cmd = "version"
	}
	var code int
	var err error
	switch cmd {
	case "discover":
		code, err = runDiscover(ctx, rest, stdout, stderr)
	case "export":
		code, err = runExport(rest, stdout, stderr)
	case "merge":
		code, err = runMerge(rest, stdout, stderr)
	case "resume":
		code, err = runResume(ctx, rest, stdout, stderr)
	case "help":
		return runHelp(rest, stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "lanscan %s (schema %d, %s %s/%s)\n", version.String(), model.SchemaVersion, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	default:
		fmt.Fprintf(stderr, "lanscan: unknown command %q\nRun 'lanscan --help' for usage.\n", cmd)
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	var usage usageError
	if errors.As(err, &usage) {
		hint := "lanscan --help"
		if cmd != "discover" {
			hint = "lanscan help " + cmd
		}
		fmt.Fprintf(stderr, "lanscan: %v\nRun '%s' for usage.\n", err, hint)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "lanscan:", err)
	}
	return code
}

// runHelp prints the help for a command, or the main help.
func runHelp(args []string, stdout, stderr io.Writer) int {
	cmd := "discover"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "discover":
		c := defaults()
		discoverPage.write(stdout, discoverFlags(&c))
	case "export":
		exportPage.write(stdout, exportFlags(new(exportOptions)))
	case "merge":
		mergePage.write(stdout, mergeFlags(new(mergeOptions)))
	case "resume":
		resumePage.write(stdout, resumeFlags(new(resumeOptions)))
	default:
		fmt.Fprintf(stderr, "lanscan: no help for %q; commands are resume, export and merge\n", cmd)
		return 2
	}
	return 0
}

// Config configures a discovery run. Start with DefaultConfig and set
// Intensity; Tuning is filled from the intensity's preset unless set.
type Config struct {
	// Intensity selects how much discovery may send: 0 is passive (local state
	// only), 1 confirms evidenced addresses, 2 also samples known prefixes and
	// traces, 3 also guesses the first host of neighbouring prefixes. No level
	// sweeps whole prefixes or scans ports.
	Intensity int `json:"intensity"`
	// Listen captures broadcast and multicast traffic for this long before
	// planning. Linux only; it needs CAP_NET_RAW. Zero disables it.
	Listen time.Duration `json:"listen,omitempty"`
	// NoIPv6 sends, captures and looks up nothing over IPv6. Local IPv6 state
	// is still reported.
	NoIPv6 bool `json:"no_ipv6,omitempty"`
	// Tuning holds the advanced probing settings; see Preset.
	Tuning     `json:"tuning"`
	Source     string        `json:"source"`
	Plan       bool          `json:"plan"`
	Include    []string      `json:"include"`
	Exclude    []string      `json:"exclude"`
	ScopeFrom  string        `json:"scope_from"`
	Seeds      string        `json:"seeds"`
	Inventory  string        `json:"inventory"`
	Interface  string        `json:"interface"`
	Realm      string        `json:"realm"`
	Vantage    string        `json:"vantage"`
	Format     string        `json:"format"`
	Output     string        `json:"output"`
	Journal    string        `json:"journal"`
	Sync       string        `json:"sync"`
	Limit      int           `json:"candidate_limit"`
	DiskBudget int64         `json:"disk_budget"`
	Duration   time.Duration `json:"duration"`
	Require    []string      `json:"require_capability"`
	DNSSuffix  []string      `json:"dns_suffix,omitempty"`
	Resolver   string        `json:"resolver,omitempty"`
}

// Tuning is the advanced probing configuration an intensity implies.
type Tuning struct {
	Rate          float64       `json:"rate"`
	Concurrency   int           `json:"concurrency"`
	MaxOperations int           `json:"max_operations"`
	Timeout       time.Duration `json:"timeout"`
	Port          int           `json:"tcp_port"`
	DNSBudget     int           `json:"dns_budget"`
	Trace         int           `json:"trace"`
	TraceHops     int           `json:"trace_hops"`
	TraceBudget   int           `json:"trace_budget"`
	// SamplePerPrefix guesses up to 3 addresses in known IPv4 prefixes that
	// have no host evidence.
	SamplePerPrefix int `json:"sample_per_prefix"`
	// Neighbours guesses the first host of this many sibling prefixes on each
	// side of known IPv4 prefixes.
	Neighbours int           `json:"neighbours"`
	Retry      int           `json:"retry"`
	Refresh    time.Duration `json:"refresh_interval"`
}

// MaxIntensity is the highest supported intensity.
const MaxIntensity = 3

// presets is indexed by intensity; intensity 0 sends nothing.
var presets = [MaxIntensity + 1]Tuning{
	{},
	{Rate: 10, Concurrency: 8, MaxOperations: 500, Timeout: time.Second, Port: 443, DNSBudget: 50, TraceHops: 16, TraceBudget: 32, Refresh: 5 * time.Second},
	{Rate: 20, Concurrency: 32, MaxOperations: 2000, Timeout: time.Second, Port: 443, DNSBudget: 100, Trace: 4, TraceHops: 16, TraceBudget: 64, SamplePerPrefix: 2, Retry: 1, Refresh: 5 * time.Second},
	{Rate: 50, Concurrency: 64, MaxOperations: 10000, Timeout: time.Second, Port: 443, DNSBudget: 500, Trace: 16, TraceHops: 16, TraceBudget: 256, SamplePerPrefix: 3, Neighbours: 2, Retry: 1, Refresh: 5 * time.Second},
}

// Preset returns the tuning for an intensity, or the zero Tuning if it is out
// of range.
func Preset(intensity int) Tuning {
	if intensity < 0 || intensity > MaxIntensity {
		return Tuning{}
	}
	return presets[intensity]
}

type config = Config

// DefaultConfig returns the CLI defaults: intensity 0.
func DefaultConfig() Config { return defaults() }

func defaults() config {
	return config{Format: "text", Sync: "periodic", Limit: 100000, DiskBudget: 256 << 20}
}

// durations are the default run limits by intensity; listening time is
// added on top. Runs end sooner when their work is done.
var durations = [MaxIntensity + 1]time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute}

// resolved fills an unset Tuning from the intensity preset and an unset
// Duration from the intensity's default.
func (c Config) resolved() Config {
	if c.Tuning == (Tuning{}) {
		c.Tuning = Preset(c.Intensity)
	}
	if c.Duration == 0 && c.Intensity >= 0 && c.Intensity <= MaxIntensity {
		c.Duration = durations[c.Intensity] + c.Listen
	}
	return c
}

// active reports whether c may send network traffic.
func (c Config) active() bool { return c.Intensity > 0 && !c.Plan }

func discoverFlags(c *config) *flag.FlagSet {
	fs := flag.NewFlagSet("lanscan", flag.ContinueOnError)
	fs.IntVar(&c.Intensity, "intensity", c.Intensity, "how much traffic to send:\n0  passive: read local state only, send nothing (default)\n1  confirm addresses the machine already knows\n2  also sample known subnets and trace a few paths\n3  also guess hosts in neighbouring subnets")
	fs.DurationVar(&c.Listen, "listen", c.Listen, "first listen this long to broadcast/multicast traffic, e.g. 30s\n(Linux; needs root or CAP_NET_RAW; sends nothing)")
	fs.BoolVar(&c.Plan, "plan", c.Plan, "show what the intensity would probe, then stop; sends nothing")
	fs.BoolVar(&c.NoIPv6, "no-ipv6", c.NoIPv6, "no IPv6 probes, lookups or capture")
	fs.DurationVar(&c.Duration, "duration", c.Duration, "stop after at most this long")
	fs.Var((*stringsFlag)(&c.Include), "include", "probe only inside this `CIDR`; repeatable (default: private address space)")
	fs.Var((*stringsFlag)(&c.Exclude), "exclude", "never probe inside this `CIDR`; repeatable, always wins")
	fs.StringVar(&c.Interface, "interface", c.Interface, "use only this network `INTERFACE`")
	fs.StringVar(&c.Source, "source", c.Source, "send from this source `IP`")
	fs.StringVar(&c.ScopeFrom, "scope-from", c.ScopeFrom, "also allow private routes of the current routing table (`routes` is the only value)")
	fs.StringVar(&c.Seeds, "seeds", c.Seeds, "extra addresses or hostnames to check, one per line in `FILE`")
	fs.StringVar(&c.Inventory, "inventory", c.Inventory, "known prefixes from a `CSV` with columns realm,prefix,kind,source,observed_at")
	fs.Var((*stringsFlag)(&c.DNSSuffix), "dns-suffix", "only query names under this `DOMAIN`; repeatable")
	fs.StringVar(&c.Resolver, "resolver", c.Resolver, "query this DNS server `IP` instead of the system resolver")
	fs.String("config", "", "read settings from this JSON `FILE`; flags override it")
	fs.StringVar(&c.Format, "format", c.Format, "results `FORMAT`:\ntext          a readable summary\ncsv           subnets and hosts, one row each\njsonl         every event, streamed (for tools)\ncsv-findings  every finding revision, streamed (for tools)")
	fs.StringVar(&c.Output, "output", c.Output, "write results to this new `FILE` instead of stdout")
	fs.StringVar(&c.Journal, "journal", c.Journal, "also keep a recoverable event journal in this new `FILE` (needed for resume)")
	fs.StringVar(&c.Sync, "sync", c.Sync, "journal durability `MODE`: periodic or every-event")
	fs.StringVar(&c.Realm, "realm", c.Realm, "network `NAME` recorded with results (default: unique per run)")
	fs.StringVar(&c.Vantage, "vantage", c.Vantage, "observation point `NAME` (default: host name)")
	fs.IntVar(&c.MaxOperations, "max-operations", c.MaxOperations, "hard cap on network operations")
	fs.IntVar(&c.Limit, "candidate-limit", c.Limit, "maximum retained hosts, and separately prefixes")
	fs.Int64Var(&c.DiskBudget, "disk-budget", c.DiskBudget, "maximum journal size in `BYTES`")
	fs.Var((*stringsFlag)(&c.Require), "require-capability", "exit 3 unless this collector or capability `NAME` works; repeatable")
	fs.Float64Var(&c.Rate, "rate", c.Rate, "operations started per second")
	fs.IntVar(&c.Concurrency, "concurrency", c.Concurrency, "operations in flight")
	fs.DurationVar(&c.Timeout, "timeout", c.Timeout, "wait per echo or TCP attempt")
	fs.IntVar(&c.Port, "tcp-port", c.Port, "TCP `PORT` tried when echo gets no answer")
	fs.IntVar(&c.DNSBudget, "dns-budget", c.DNSBudget, "maximum DNS queries; 0 disables DNS")
	fs.IntVar(&c.Trace, "trace", c.Trace, "trace paths to up to `N` responders")
	fs.IntVar(&c.TraceHops, "trace-hops", c.TraceHops, "maximum hops per trace")
	fs.IntVar(&c.TraceBudget, "trace-budget", c.TraceBudget, "maximum trace probes in total")
	fs.IntVar(&c.SamplePerPrefix, "sample-per-prefix", c.SamplePerPrefix, "addresses guessed in each known IPv4 subnet without hosts, up to 3")
	fs.IntVar(&c.Neighbours, "neighbours", c.Neighbours, "neighbouring subnets guessed on each side of known IPv4 subnets, up to 8")
	fs.IntVar(&c.Retry, "retry", c.Retry, "extra attempts for silent targets, at most 1")
	fs.DurationVar(&c.Refresh, "refresh-interval", c.Refresh, "how often to poll for route changes; 0 disables")
	alias(fs)
	return fs
}

// tuningNotes show each tuning flag's value at intensities 1, 2 and 3.
func tuningNotes() map[string]string {
	notes := map[string]string{}
	for name, get := range map[string]func(Tuning) string{
		"rate":              func(t Tuning) string { return fmt.Sprint(t.Rate) },
		"concurrency":       func(t Tuning) string { return fmt.Sprint(t.Concurrency) },
		"max-operations":    func(t Tuning) string { return fmt.Sprint(t.MaxOperations) },
		"timeout":           func(t Tuning) string { return t.Timeout.String() },
		"tcp-port":          func(t Tuning) string { return fmt.Sprint(t.Port) },
		"dns-budget":        func(t Tuning) string { return fmt.Sprint(t.DNSBudget) },
		"trace":             func(t Tuning) string { return fmt.Sprint(t.Trace) },
		"trace-hops":        func(t Tuning) string { return fmt.Sprint(t.TraceHops) },
		"trace-budget":      func(t Tuning) string { return fmt.Sprint(t.TraceBudget) },
		"sample-per-prefix": func(t Tuning) string { return fmt.Sprint(t.SamplePerPrefix) },
		"neighbours":        func(t Tuning) string { return fmt.Sprint(t.Neighbours) },
		"retry":             func(t Tuning) string { return fmt.Sprint(t.Retry) },
		"refresh-interval":  func(t Tuning) string { return t.Refresh.String() },
	} {
		notes[name] = fmt.Sprintf("intensity 1/2/3: %s/%s/%s", get(presets[1]), get(presets[2]), get(presets[3]))
	}
	notes["disk-budget"] = "default 256 MiB"
	notes["duration"] = fmt.Sprintf("intensity 0/1/2/3: %s/%s/%s/%s, plus --listen; runs end sooner when done", minutes(durations[0]), minutes(durations[1]), minutes(durations[2]), minutes(durations[3]))
	return notes
}

var discoverPage = helpPage{
	about: `lanscan finds the subnets and hosts this machine can reach. It starts from
what the machine already knows (interfaces, routes, neighbours, DNS) and sends
traffic only when you raise --intensity. It never sweeps address ranges.`,
	usage: []string{
		"lanscan [flags]                     discover (the default command)",
		"lanscan resume|export|merge [flags] work with saved journals",
		"lanscan help [command] | version",
	},
	examples: [][2]string{
		{"lanscan", "passive: local state only, sends nothing"},
		{"lanscan -i 1", "also confirm known addresses (a handful of packets)"},
		{"lanscan -i 2 --listen 30s", "listen first, then sample known subnets"},
		{"lanscan -i 3 --plan", "show what intensity 3 would probe; sends nothing"},
		{"lanscan -i 2 -f csv -o hosts.csv", "subnets and hosts as a spreadsheet"},
		{"lanscan -i 2 --include 10.20.0.0/16", "probe only inside one range"},
	},
	template: []string{
		"lanscan -i <0-3> [--listen <30s>]",
		"        [--include <CIDR>]... [--exclude <CIDR>]... [--seeds <hosts.txt>]",
		"        [-f text|jsonl|csv] [-o <results-file>] [-j <journal.jsonl>]",
	},
	sections: []helpSection{
		{"SCAN", []string{"intensity", "listen", "plan", "no-ipv6", "duration"}},
		{"SCOPE", []string{"include", "exclude", "interface", "source", "scope-from"}},
		{"INPUT", []string{"seeds", "inventory", "dns-suffix", "resolver", "config"}},
		{"OUTPUT", []string{"format", "output", "journal", "sync", "realm", "vantage"}},
		{"LIMITS", []string{"max-operations", "candidate-limit", "disk-budget", "require-capability"}},
		{"TUNING (set by --intensity; a flag here overrides the preset)", []string{"rate", "concurrency", "timeout", "tcp-port", "dns-budget", "trace", "trace-hops", "trace-budget", "sample-per-prefix", "neighbours", "retry", "refresh-interval"}},
	},
	footer: `PERMISSIONS:
  Probing prefers ICMP echo. On Linux, ICMP (without ping sockets) and
  --listen need root or CAP_NET_RAW. Grant it to the binary once:
    sudo setcap cap_net_raw+ep "$(command -v lanscan)"
  Without it, probes fall back to one TCP connect and --listen stops with
  an error. Windows needs no extra rights for probing; --listen is Linux only.

COMMANDS:
  resume   continue an interrupted run from its journal
  export   rewrite a journal as events or latest findings
  merge    combine journals from several machines
Run 'lanscan help <command>' for a command's flags.

Exit status: 0 complete, 1 error, 2 usage error, 3 incomplete (budget,
duration or a required capability), 130 interrupted.`,
	notes: tuningNotes(),
}

// loadConfigFile decodes any --config file in args over c.
func loadConfigFile(args []string, c *config) error {
	for i, a := range args {
		path := ""
		if strings.HasPrefix(a, "--config=") {
			path = strings.TrimPrefix(a, "--config=")
		}
		if a == "--config" && i+1 < len(args) {
			path = args[i+1]
		}
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		d := json.NewDecoder(io.LimitReader(f, 1<<20))
		d.DisallowUnknownFields()
		err = d.Decode(c)
		if err == nil {
			var extra any
			if e := d.Decode(&extra); e != io.EOF {
				err = errors.New("config contains trailing data")
			}
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// parseConfig layers the intensity preset, then any JSON configuration, then
// flags, so explicit values always override the preset.
func parseConfig(args []string, stdout io.Writer) (config, error) {
	// The first pass only learns the final intensity.
	probe := defaults()
	if err := loadConfigFile(args, &probe); err != nil {
		return probe, err
	}
	if err := parseFlags(discoverFlags(&probe), args, stdout, discoverPage); err != nil {
		return probe, err
	}
	c := defaults()
	c.Tuning = Preset(probe.Intensity)
	if err := loadConfigFile(args, &c); err != nil {
		return c, err
	}
	// Repeated list flags replace the config list, then append in CLI order.
	for _, entry := range []struct {
		name  string
		value *[]string
	}{{"include", &c.Include}, {"exclude", &c.Exclude}, {"require-capability", &c.Require}, {"dns-suffix", &c.DNSSuffix}} {
		for _, arg := range args {
			if arg == "--"+entry.name || strings.HasPrefix(arg, "--"+entry.name+"=") {
				*entry.value = nil
				break
			}
		}
	}
	fs := discoverFlags(&c)
	if err := parseFlags(fs, args, io.Discard, discoverPage); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, usageError{fmt.Errorf("unexpected argument %q", fs.Arg(0))}
	}
	if c.Intensity == 0 && c.Tuning != (Tuning{}) {
		return c, usageError{errors.New("tuning flags need --intensity 1 or higher")}
	}
	c = c.resolved()
	if err := validateConfig(c); err != nil {
		return c, usageError{err}
	}
	return c, nil
}

func validateConfig(c config) error {
	if c.Intensity < 0 || c.Intensity > MaxIntensity {
		return fmt.Errorf("intensity must be 0..%d", MaxIntensity)
	}
	if c.Limit < 1 || c.Limit > 1000000 || c.Duration <= 0 || c.DiskBudget < 1 {
		return errors.New("positive duration/disk budget and candidate limit 1..1000000 required")
	}
	if !validFormat(c.Format) {
		return errors.New("format must be text, csv, jsonl or csv-findings")
	}
	if c.Sync != "periodic" && c.Sync != "every-event" {
		return errors.New("sync must be periodic or every-event")
	}
	if c.ScopeFrom != "" && c.ScopeFrom != "routes" {
		return errors.New("scope-from must be routes")
	}
	if c.Listen < 0 || c.Listen >= c.Duration {
		return errors.New("listen must be nonnegative and shorter than duration")
	}
	if c.Listen > 0 && !listen.Supported {
		return errors.New("--listen is supported on Linux only")
	}
	if c.Intensity == 0 {
		return commonChecks(c)
	}
	if math.IsNaN(c.Rate) || math.IsInf(c.Rate, 0) || c.Rate <= 0 || c.Rate > 10000 || c.Concurrency < 1 || c.Concurrency > 1024 || c.MaxOperations < 1 || c.Timeout <= 0 || c.Port < 1 || c.Port > 65535 {
		return errors.New("invalid probe budgets, concurrency, timeout or TCP port")
	}
	if c.Neighbours < 0 || c.Neighbours > 8 {
		return errors.New("neighbours must be 0..8")
	}
	if err := tuningChecks(c); err != nil {
		return err
	}
	return commonChecks(c)
}

// commonChecks validates settings that apply at every intensity.
func commonChecks(c config) error {
	if c.Source != "" {
		if _, err := netip.ParseAddr(c.Source); err != nil {
			return fmt.Errorf("invalid source: %w", err)
		}
	}
	if c.Resolver != "" {
		if a, err := netip.ParseAddr(c.Resolver); err != nil || a.IsUnspecified() || a.IsMulticast() {
			return errors.New("resolver must be a unicast IP address")
		}
	}
	for _, s := range c.DNSSuffix {
		if !importer.ValidName(s) {
			return fmt.Errorf("invalid DNS suffix %q", s)
		}
	}
	return nil
}

func tuningChecks(c config) error {
	if c.DNSBudget < 0 || c.Trace < 0 || c.Trace > 64 || c.TraceBudget < 0 || c.SamplePerPrefix < 0 || c.SamplePerPrefix > 3 {
		return errors.New("DNS/trace budgets must be nonnegative; trace 0..64; sample-per-prefix 0..3")
	}
	if c.Trace > 0 && (c.TraceHops < 1 || c.TraceHops > 64) {
		return errors.New("trace-hops must be 1..64")
	}
	if c.Retry < 0 || c.Retry > 1 {
		return errors.New("retry must be 0 or 1")
	}
	if c.Refresh < 0 || (c.Refresh > 0 && c.Refresh < 500*time.Millisecond) {
		return errors.New("refresh-interval must be 0 (disabled) or at least 500ms")
	}
	return nil
}

func openOutput(path string, fallback io.Writer) (io.Writer, func() error, error) {
	if path == "" {
		return fallback, func() error { return nil }, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}

func validFormat(f string) bool { return slices.Contains(output.Formats, f) }

// minutes prints whole minutes as "5m" rather than "5m0s".
func minutes(d time.Duration) string {
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}
