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
	"strings"
	"time"

	"lanscan/internal/importer"
	"lanscan/internal/listen"
)

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

// Version can be set at build time via -ldflags.
var Version = "development"

// Run returns an exit code without terminating the caller, allowing integration tests.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	var code int
	var err error
	switch args[0] {
	case "discover":
		code, err = runDiscover(ctx, args[1:], stdout, stderr)
	case "export":
		code, err = runExport(args[1:], stdout, stderr)
	case "merge":
		code, err = runMerge(args[1:], stdout, stderr)
	case "resume":
		code, err = runResume(ctx, args[1:], stdout, stderr)
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	case "version", "--version":
		fmt.Fprintf(stdout, "lanscan %s (schema 1)\n", Version)
		return 0
	default:
		usage(stderr)
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "lanscan:", err)
	}
	return code
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: lanscan discover [options] | resume --journal FILE | export [options] | merge [options] journals...\n\nDiscovery defaults to local-only collection. Use discover --help for options.")
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
	NoJournal  bool          `json:"no_journal"`
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
	return config{Format: "text", Sync: "periodic", Limit: 100000, DiskBudget: 256 << 20, Duration: 2 * time.Minute}
}

// resolved fills an unset Tuning from the intensity preset.
func (c Config) resolved() Config {
	if c.Tuning == (Tuning{}) {
		c.Tuning = Preset(c.Intensity)
	}
	return c
}

// active reports whether c may send network traffic.
func (c Config) active() bool { return c.Intensity > 0 && !c.Plan }

// advancedFlags are listed separately in help; the preset sets them.
var advancedFlags = map[string]bool{"rate": true, "concurrency": true, "max-operations": true, "timeout": true, "tcp-port": true, "dns-budget": true, "trace": true, "trace-hops": true, "trace-budget": true, "sample-per-prefix": true, "neighbours": true, "retry": true, "refresh-interval": true, "scope-from": true, "source": true, "interface": true, "realm": true, "vantage": true, "sync": true, "candidate-limit": true, "disk-budget": true, "require-capability": true, "config": true}

func discoverFlags(c *config, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.IntVar(&c.Intensity, "intensity", c.Intensity, "0 passive (default): local state only, no packets\n1 confirm addresses already in local evidence\n2 also sample known prefixes and trace a few paths\n3 also guess the first host of neighbouring prefixes")
	fs.DurationVar(&c.Listen, "listen", c.Listen, "listen to broadcast/multicast traffic for this long first, e.g. 30s (Linux, needs CAP_NET_RAW)")
	fs.BoolVar(&c.NoIPv6, "no-ipv6", c.NoIPv6, "no IPv6 probes, lookups or capture")
	fs.BoolVar(&c.Plan, "plan", c.Plan, "show what the intensity would probe, without sending anything")
	fs.Var((*stringsFlag)(&c.Include), "include", "probe only inside this CIDR; repeatable (default: private address space)")
	fs.Var((*stringsFlag)(&c.Exclude), "exclude", "never probe inside this CIDR; repeatable, always wins")
	fs.StringVar(&c.Seeds, "seeds", c.Seeds, "file with one IP or hostname per line")
	fs.StringVar(&c.Inventory, "inventory", c.Inventory, "prefix inventory CSV")
	fs.Var((*stringsFlag)(&c.DNSSuffix), "dns-suffix", "approved organisational DNS suffix; repeatable")
	fs.StringVar(&c.Resolver, "resolver", c.Resolver, "explicit DNS server IP (default: system resolver policy)")
	fs.StringVar(&c.Format, "format", c.Format, "text, jsonl, or csv")
	fs.StringVar(&c.Output, "output", c.Output, "exclusive output file (default: stdout)")
	fs.StringVar(&c.Journal, "journal", c.Journal, "exclusive JSONL journal path")
	fs.BoolVar(&c.NoJournal, "no-journal", c.NoJournal, "stream only, without a recoverable journal")
	fs.DurationVar(&c.Duration, "duration", c.Duration, "maximum run duration")

	fs.Float64Var(&c.Rate, "rate", c.Rate, "maximum operation starts per second")
	fs.IntVar(&c.Concurrency, "concurrency", c.Concurrency, "maximum concurrent validation jobs")
	fs.IntVar(&c.MaxOperations, "max-operations", c.MaxOperations, "maximum operation reservations, including failed starts")
	fs.DurationVar(&c.Timeout, "timeout", c.Timeout, "deadline per echo or TCP attempt")
	fs.IntVar(&c.Port, "tcp-port", c.Port, "single fallback TCP service port; silence is inconclusive")
	fs.IntVar(&c.DNSBudget, "dns-budget", c.DNSBudget, "maximum DNS exchanges; 0 disables DNS")
	fs.IntVar(&c.Trace, "trace", c.Trace, "trace up to N selected destinations; 0 disables")
	fs.IntVar(&c.TraceHops, "trace-hops", c.TraceHops, "maximum hop limit per trace")
	fs.IntVar(&c.TraceBudget, "trace-budget", c.TraceBudget, "maximum trace hop operations")
	fs.IntVar(&c.SamplePerPrefix, "sample-per-prefix", c.SamplePerPrefix, "synthetic IPv4 samples in known prefixes without host evidence (0-3)")
	fs.IntVar(&c.Neighbours, "neighbours", c.Neighbours, "guess the first host of N sibling prefixes each side of known IPv4 prefixes (0-8)")
	fs.IntVar(&c.Retry, "retry", c.Retry, "extra attempts for silent targets after all first attempts (0 or 1)")
	fs.DurationVar(&c.Refresh, "refresh-interval", c.Refresh, "topology poll interval during active runs; change notifications apply as well; 0 disables")
	fs.StringVar(&c.ScopeFrom, "scope-from", c.ScopeFrom, "routes: add private unicast routes of the current routing epoch to the scope")
	fs.StringVar(&c.Source, "source", c.Source, "source IP address for validation")
	fs.StringVar(&c.Interface, "interface", c.Interface, "restrict planned egress interface")
	fs.StringVar(&c.Realm, "realm", c.Realm, "network realm (default: unique to this run)")
	fs.StringVar(&c.Vantage, "vantage", c.Vantage, "observation point (default: host name)")
	fs.StringVar(&c.Sync, "sync", c.Sync, "periodic or every-event journal sync")
	fs.IntVar(&c.Limit, "candidate-limit", c.Limit, "maximum retained findings and candidates")
	fs.Int64Var(&c.DiskBudget, "disk-budget", c.DiskBudget, "maximum journal bytes")
	fs.Var((*stringsFlag)(&c.Require), "require-capability", "collector or capability that must be available; repeatable")
	fs.String("config", "", "JSON configuration file (durations in nanoseconds)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage: lanscan discover [--intensity 0-3] [--listen 30s] [options]\n\nOptions:\n")
		printFlags(fs, false)
		fmt.Fprint(fs.Output(), "\nAdvanced (intensity presets set the probing options; explicit values win):\n")
		printFlags(fs, true)
	}
	return fs
}

// simpleFlags lists the everyday options first, in this order.
var simpleFlags = []string{"intensity", "listen", "plan", "include", "exclude", "no-ipv6", "seeds", "inventory", "dns-suffix", "resolver", "format", "output", "journal", "no-journal", "duration"}

func printFlags(fs *flag.FlagSet, advanced bool) {
	w := fs.Output()
	show := func(f *flag.Flag) {
		fmt.Fprintf(w, "  --%s\n", f.Name)
		for _, line := range strings.Split(f.Usage, "\n") {
			fmt.Fprintf(w, "        %s\n", line)
		}
	}
	if !advanced {
		for _, name := range simpleFlags {
			show(fs.Lookup(name))
		}
		return
	}
	fs.VisitAll(func(f *flag.Flag) {
		if advancedFlags[f.Name] {
			show(f)
		}
	})
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
func parseConfig(args []string, stderr io.Writer) (config, error) {
	// The first pass only learns the final intensity.
	probe := defaults()
	if err := loadConfigFile(args, &probe); err != nil {
		return probe, err
	}
	if err := discoverFlags(&probe, stderr).Parse(args); err != nil {
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
	fs := discoverFlags(&c, io.Discard)
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, errors.New("unexpected positional arguments")
	}
	if c.Intensity == 0 && c.Tuning != (Tuning{}) {
		return c, errors.New("probing options need --intensity 1 or higher")
	}
	return c, validateConfig(c)
}

func validateConfig(c config) error {
	if c.Limit < 1 || c.Limit > 1000000 || c.Duration <= 0 || c.DiskBudget < 1 {
		return errors.New("positive duration/disk budget and candidate limit 1..1000000 required")
	}
	if c.Format != "text" && c.Format != "jsonl" && c.Format != "csv" {
		return errors.New("format must be text, jsonl, or csv")
	}
	if c.Sync != "periodic" && c.Sync != "every-event" {
		return errors.New("sync must be periodic or every-event")
	}
	if c.NoJournal && c.Journal != "" {
		return errors.New("--no-journal and --journal are mutually exclusive")
	}
	if c.ScopeFrom != "" && c.ScopeFrom != "routes" {
		return errors.New("scope-from must be routes")
	}
	if c.Intensity < 0 || c.Intensity > MaxIntensity {
		return fmt.Errorf("intensity must be 0..%d", MaxIntensity)
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
