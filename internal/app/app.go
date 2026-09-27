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

// Config configures a discovery run. Start with DefaultConfig.
type Config struct {
	Rate          float64       `json:"rate"`
	Concurrency   int           `json:"concurrency"`
	MaxOperations int           `json:"max_operations"`
	Timeout       time.Duration `json:"timeout"`
	Port          int           `json:"tcp_port"`
	Source        string        `json:"source"`
	Active        bool          `json:"active"`
	Plan          bool          `json:"plan"`
	Include       []string      `json:"include"`
	Exclude       []string      `json:"exclude"`
	ScopeFrom     string        `json:"scope_from"`
	Seeds         string        `json:"seeds"`
	Inventory     string        `json:"inventory"`
	Interface     string        `json:"interface"`
	Realm         string        `json:"realm"`
	Vantage       string        `json:"vantage"`
	Format        string        `json:"format"`
	Output        string        `json:"output"`
	Journal       string        `json:"journal"`
	NoJournal     bool          `json:"no_journal"`
	Sync          string        `json:"sync"`
	Limit         int           `json:"candidate_limit"`
	DiskBudget    int64         `json:"disk_budget"`
	Duration      time.Duration `json:"duration"`
	Require       []string      `json:"require_capability"`
	// Fields added after schema 1 omit zero values so earlier configuration
	// hashes remain verifiable on resume.
	DNSSuffix       []string      `json:"dns_suffix,omitempty"`
	Resolver        string        `json:"resolver,omitempty"`
	DNSBudget       int           `json:"dns_budget,omitempty"`
	Trace           int           `json:"trace,omitempty"`
	TraceHops       int           `json:"trace_hops,omitempty"`
	TraceBudget     int           `json:"trace_budget,omitempty"`
	SamplePerPrefix int           `json:"sample_per_prefix,omitempty"`
	Refresh         time.Duration `json:"refresh_interval,omitempty"`
	Retry           int           `json:"retry,omitempty"`
}

type config = Config

// DefaultConfig returns the CLI defaults.
func DefaultConfig() Config { return defaults() }

func defaults() config {
	return config{Rate: 20, Concurrency: 32, MaxOperations: 1000, Timeout: time.Second, Port: 443, Format: "text", Sync: "periodic", Limit: 100000, DiskBudget: 256 << 20, Duration: 2 * time.Minute, DNSBudget: 100, TraceHops: 16, TraceBudget: 48, Refresh: 5 * time.Second}
}

func parseConfig(args []string, stderr io.Writer) (config, error) {
	c := defaults()
	// Load JSON configuration before flags so explicit CLI values always win.
	for i, a := range args {
		path := ""
		if strings.HasPrefix(a, "--config=") {
			path = strings.TrimPrefix(a, "--config=")
		}
		if a == "--config" && i+1 < len(args) {
			path = args[i+1]
		}
		if path != "" {
			f, err := os.Open(path)
			if err != nil {
				return c, err
			}
			d := json.NewDecoder(io.LimitReader(f, 1<<20))
			d.DisallowUnknownFields()
			err = d.Decode(&c)
			if err == nil {
				var extra any
				if e := d.Decode(&extra); e != io.EOF {
					err = errors.New("config contains trailing data")
				}
			}
			f.Close()
			if err != nil {
				return c, err
			}
		}
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
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configPath string
	fs.Float64Var(&c.Rate, "rate", c.Rate, "maximum operation starts per second")
	fs.IntVar(&c.Concurrency, "concurrency", c.Concurrency, "maximum concurrent validation jobs")
	fs.IntVar(&c.MaxOperations, "max-operations", c.MaxOperations, "maximum operation reservations, including failed starts")
	fs.DurationVar(&c.Timeout, "timeout", c.Timeout, "deadline per echo or TCP attempt")
	fs.IntVar(&c.Port, "tcp-port", c.Port, "single fallback TCP service port; silence is inconclusive")
	fs.StringVar(&c.Source, "source", c.Source, "source IP address for validation")
	fs.StringVar(&configPath, "config", "", "JSON configuration file (duration in nanoseconds)")
	fs.BoolVar(&c.Active, "active", c.Active, "enable explicitly scoped network validation")
	fs.BoolVar(&c.Plan, "plan", c.Plan, "collect locally and show the bounded candidate plan; no probes")
	fs.Var((*stringsFlag)(&c.Include), "include", "allowed CIDR; repeatable")
	fs.Var((*stringsFlag)(&c.Exclude), "exclude", "excluded CIDR; repeatable, always wins")
	fs.StringVar(&c.ScopeFrom, "scope-from", c.ScopeFrom, "routes: use explicit private unicast routes as scope")
	fs.StringVar(&c.Seeds, "seeds", c.Seeds, "file with one IP or hostname per line")
	fs.StringVar(&c.Inventory, "inventory", c.Inventory, "prefix inventory CSV")
	fs.StringVar(&c.Interface, "interface", c.Interface, "restrict planned egress interface")
	fs.StringVar(&c.Realm, "realm", c.Realm, "network realm (default: unique to this run)")
	fs.StringVar(&c.Vantage, "vantage", c.Vantage, "observation point (default: host name)")
	fs.StringVar(&c.Format, "format", c.Format, "text, jsonl, or csv")
	fs.StringVar(&c.Output, "output", c.Output, "exclusive output file (default: stdout)")
	fs.StringVar(&c.Journal, "journal", c.Journal, "exclusive JSONL journal path")
	fs.BoolVar(&c.NoJournal, "no-journal", c.NoJournal, "stream only, without a recoverable journal")
	fs.StringVar(&c.Sync, "sync", c.Sync, "periodic or every-event journal sync")
	fs.IntVar(&c.Limit, "candidate-limit", c.Limit, "maximum retained findings and candidates")
	fs.Int64Var(&c.DiskBudget, "disk-budget", c.DiskBudget, "maximum journal bytes")
	fs.DurationVar(&c.Duration, "duration", c.Duration, "maximum run duration")
	fs.Var((*stringsFlag)(&c.Require), "require-capability", "collector or capability that must be available; repeatable")
	fs.Var((*stringsFlag)(&c.DNSSuffix), "dns-suffix", "approved organisational DNS suffix; repeatable")
	fs.StringVar(&c.Resolver, "resolver", c.Resolver, "explicit DNS server IP (default: system resolver policy)")
	fs.IntVar(&c.DNSBudget, "dns-budget", c.DNSBudget, "maximum DNS exchanges in active mode; 0 disables DNS")
	fs.IntVar(&c.Trace, "trace", c.Trace, "trace up to N selected destinations; 0 disables")
	fs.IntVar(&c.TraceHops, "trace-hops", c.TraceHops, "maximum hop limit per trace")
	fs.IntVar(&c.TraceBudget, "trace-budget", c.TraceBudget, "maximum trace hop operations")
	fs.IntVar(&c.SamplePerPrefix, "sample-per-prefix", c.SamplePerPrefix, "synthetic IPv4 samples in known prefixes without host evidence (0-3)")
	fs.DurationVar(&c.Refresh, "refresh-interval", c.Refresh, "topology poll interval during active runs; change notifications apply as well; 0 disables")
	fs.IntVar(&c.Retry, "retry", c.Retry, "extra attempts for silent targets after all first attempts (0 or 1)")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, errors.New("unexpected positional arguments")
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
	if c.Active && len(c.Include) == 0 && c.ScopeFrom == "" {
		return errors.New("active discovery requires --include or --scope-from routes")
	}
	if math.IsNaN(c.Rate) || math.IsInf(c.Rate, 0) || c.Rate <= 0 || c.Rate > 10000 || c.Concurrency < 1 || c.Concurrency > 1024 || c.MaxOperations < 1 || c.Timeout <= 0 || c.Port < 1 || c.Port > 65535 {
		return errors.New("invalid probe budgets, concurrency, timeout or TCP port")
	}
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
