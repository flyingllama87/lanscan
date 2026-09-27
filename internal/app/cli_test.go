package app

import (
	"bytes"
	"context"
	"flag"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"lanscan/internal/model"
)

func run(args ...string) (int, string, string) {
	var out, stderr bytes.Buffer
	code := Run(context.Background(), args, &out, &stderr)
	return code, out.String(), stderr.String()
}

func TestBareCommandRunsPassiveDiscovery(t *testing.T) {
	code, out, stderr := run("--format", "jsonl", "--realm", "cli")
	if code != 0 || !strings.Contains(out, `"type":"run_finished"`) {
		t.Fatalf("%d %s", code, stderr)
	}
	if strings.Contains(out, `"type":"operation_reserved"`) {
		t.Fatal("bare run sent traffic")
	}
}

func TestHelpEverywhere(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}, {"-i", "2", "--help"}, {"discover", "--help"}} {
		code, out, stderr := run(args...)
		if code != 0 || stderr != "" || !strings.Contains(out, "Examples:") || !strings.Contains(out, "SCAN:") || !strings.Contains(out, "With placeholders:") {
			t.Errorf("%v: %d %q %q", args, code, out, stderr)
		}
	}
	for _, cmd := range []string{"export", "merge", "resume"} {
		for _, args := range [][]string{{"help", cmd}, {cmd, "--help"}} {
			code, out, _ := run(args...)
			if code != 0 || !strings.Contains(out, "lanscan "+cmd) || !strings.Contains(out, "FLAGS:") {
				t.Errorf("%v: %d %q", args, code, out)
			}
		}
	}
}

func TestUsageErrorsAreShortAndHelpful(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"--gwlp"}, "unknown flag --gwlp\nRun 'lanscan --help' for usage.\n"},
		{[]string{"--intensty", "2"}, "unknown flag --intensty (did you mean --intensity?)"},
		{[]string{"-i", "x"}, `invalid value "x" for -i: not a valid int`},
		{[]string{"--listen", "soon"}, `invalid value "soon" for --listen: not a valid duration`},
		{[]string{"--listen"}, "--listen needs a value"},
		{[]string{"frobnicate"}, `unknown command "frobnicate"`},
		{[]string{"--trace", "2"}, "tuning flags need --intensity 1 or higher"},
		{[]string{"-i", "9"}, "intensity must be 0..3"},
		{[]string{"export"}, "--journal is required\nRun 'lanscan help export' for usage."},
	} {
		code, out, stderr := run(test.args...)
		if code != 2 || out != "" || !strings.Contains(stderr, test.want) || strings.Count(stderr, "\n") > 2 {
			t.Errorf("%v: %d %q", test.args, code, stderr)
		}
	}
}

func TestVersionSpellings(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"-v"}} {
		if code, out, _ := run(args...); code != 0 || !strings.HasPrefix(out, "lanscan ") {
			t.Errorf("%v: %d %q", args, code, out)
		}
	}
}

// Every flag appears in exactly one help section, and every section entry
// is a real flag.
func TestHelpSectionsCoverEveryFlag(t *testing.T) {
	c := defaults()
	for _, page := range []struct {
		page helpPage
		fs   *flag.FlagSet
	}{
		{discoverPage, discoverFlags(&c)},
		{exportPage, exportFlags(new(exportOptions))},
		{mergePage, mergeFlags(new(mergeOptions))},
		{resumePage, resumeFlags(new(resumeOptions))},
	} {
		var all []string
		page.fs.VisitAll(func(f *flag.Flag) {
			if len(f.Name) > 1 {
				all = append(all, f.Name)
			}
		})
		sort.Strings(all)
		if got := page.page.sectionedFlags(); !reflect.DeepEqual(got, all) {
			t.Errorf("%s: sections %v\nflags %v", page.fs.Name(), got, all)
		}
	}
}

func TestShortFlagsShareValues(t *testing.T) {
	c, err := parseConfig([]string{"-i", "2", "-f", "csv", "-l", "5s"}, nil)
	if err != nil || c.Intensity != 2 || c.Format != "csv" || c.Listen == 0 {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestProgressLineDrawsAndClears(t *testing.T) {
	var b bytes.Buffer
	p := newProgress(&b)
	p.last = time.Time{} // draw immediately
	if err := p.Write(model.Event{Type: "operation_reserved"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "lanscan: probing · 1 operations · 0 responded") {
		t.Fatalf("%q", b.String())
	}
	b.Reset()
	_ = p.Write(model.Event{Type: "run_finished"})
	if s := b.String(); !strings.HasPrefix(s, "\r") || !strings.HasSuffix(s, "\r") || strings.TrimSpace(s) != "" {
		t.Fatalf("not cleared: %q", s)
	}
	if isTerminal(&b) {
		t.Fatal("a buffer is not a terminal")
	}
}

func TestExportPrintsSummaryByDefault(t *testing.T) {
	path := t.TempDir() + "/run.jsonl"
	if code, _, stderr := run("-j", path, "--realm", "cli"); code != 0 {
		t.Fatal(stderr)
	}
	code, out, stderr := run("export", "-j", path)
	if code != 0 || !strings.Contains(out, "SUBNETS (") || strings.Count(out, "SUBNETS (") != 1 || !strings.Contains(out, "passive (nothing sent)") {
		t.Fatalf("%d %s %s", code, out, stderr)
	}
}
