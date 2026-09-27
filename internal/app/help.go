package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
)

// usageError is a command-line mistake; Run adds a pointer to the help.
type usageError struct{ error }

// helpSection is a titled group of flags, listed in this order.
type helpSection struct {
	title string
	flags []string
}

// helpPage is one command's help.
type helpPage struct {
	about    string
	usage    []string
	examples [][2]string // command, explanation
	template []string    // a worked example with placeholders
	sections []helpSection
	footer   string
	// notes replace the "(default ...)" suffix for flags whose default
	// depends on other settings.
	notes map[string]string
}

// shortNames maps a long flag name to its one-letter alias.
var shortNames = map[string]string{"intensity": "i", "listen": "l", "output": "o", "format": "f", "journal": "j"}

// alias registers the short spelling of each long flag that has one.
func alias(fs *flag.FlagSet) {
	for long, short := range shortNames {
		if f := fs.Lookup(long); f != nil {
			fs.Var(f.Value, short, "")
		}
	}
}

// parseFlags parses args quietly: help requests return flag.ErrHelp after
// writing the page to stdout, and mistakes return a usageError.
func parseFlags(fs *flag.FlagSet, args []string, stdout io.Writer, page helpPage) error {
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	err := fs.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		page.write(stdout, fs)
		return err
	}
	if err != nil {
		return usageError{friendlyFlagError(fs, err)}
	}
	return nil
}

// friendlyFlagError rewrites the flag package's messages in the --name
// spelling used by the help, suggesting the closest flag for a typo.
func friendlyFlagError(fs *flag.FlagSet, err error) error {
	msg := err.Error()
	if name, ok := strings.CutPrefix(msg, "flag provided but not defined: -"); ok {
		msg = "unknown flag " + dashed(name)
		if best := closestFlag(fs, name); best != "" {
			msg += " (did you mean --" + best + "?)"
		}
		return errors.New(msg)
	}
	if name, ok := strings.CutPrefix(msg, "flag needs an argument: -"); ok {
		return errors.New(dashed(name) + " needs a value")
	}
	// invalid value "x" for flag -name: parse error
	if before, after, ok := strings.Cut(msg, " for flag -"); ok {
		name, rest, _ := strings.Cut(after, ": ")
		if rest == "parse error" {
			rest = "not a valid " + flagType(fs.Lookup(name))
		}
		return fmt.Errorf("%s for %s: %s", before, dashed(name), rest)
	}
	return err
}

// dashed spells a flag as the help does: -i or --intensity.
func dashed(name string) string {
	if len(name) == 1 {
		return "-" + name
	}
	return "--" + name
}

func flagType(f *flag.Flag) string {
	if f == nil {
		return "value"
	}
	if arg, _ := flag.UnquoteUsage(f); arg != "" {
		return arg
	}
	return "value"
}

// closestFlag returns the defined flag nearest to name, if it is close.
func closestFlag(fs *flag.FlagSet, name string) string {
	best, bestDist := "", 3
	fs.VisitAll(func(f *flag.Flag) {
		if len(f.Name) < 2 {
			return
		}
		if d := editDistance(name, f.Name); d < bestDist || (strings.HasPrefix(f.Name, name) && len(name) >= 3 && best == "") {
			best, bestDist = f.Name, min(d, bestDist)
		}
	})
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

// write renders the page: about, usage, examples, then each flag section
// with aligned names, argument types and defaults.
func (p helpPage) write(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintln(w, p.about)
	fmt.Fprintln(w, "\nUsage:")
	for _, u := range p.usage {
		fmt.Fprintln(w, "  "+u)
	}
	if len(p.examples) > 0 {
		fmt.Fprintln(w, "\nExamples:")
		width := 0
		for _, e := range p.examples {
			width = max(width, len(e[0]))
		}
		for _, e := range p.examples {
			fmt.Fprintf(w, "  %-*s  # %s\n", width, e[0], e[1])
		}
	}
	if len(p.template) > 0 {
		fmt.Fprintln(w, "\n  With placeholders:")
		for _, line := range p.template {
			fmt.Fprintln(w, "  "+line)
		}
	}
	for _, s := range p.sections {
		fmt.Fprintf(w, "\n%s:\n", s.title)
		var names []string
		for _, name := range s.flags {
			f := fs.Lookup(name)
			arg, _ := flag.UnquoteUsage(f)
			n := "--" + name
			if short := shortNames[name]; short != "" {
				n = "-" + short + ", " + n
			} else {
				n = "    " + n
			}
			if arg != "" {
				n += " " + arg
			}
			names = append(names, n)
		}
		width := 0
		for _, n := range names {
			width = max(width, len(n))
		}
		for i, name := range s.flags {
			f := fs.Lookup(name)
			_, usage := flag.UnquoteUsage(f)
			if note, ok := p.notes[name]; ok {
				usage += " (" + note + ")"
			} else if showDefault(f.DefValue) {
				usage += fmt.Sprintf(" (default %s)", f.DefValue)
			}
			lines := strings.Split(usage, "\n")
			fmt.Fprintf(w, "  %-*s  %s\n", width, names[i], lines[0])
			for _, line := range lines[1:] {
				fmt.Fprintf(w, "  %-*s    %s\n", width, "", line)
			}
		}
	}
	if p.footer != "" {
		fmt.Fprintln(w, "\n"+p.footer)
	}
}

func showDefault(v string) bool {
	switch v {
	case "", "0", "false", "0s", "[]":
		return false
	}
	return true
}

// sectionedFlags returns every flag a page lists, for completeness tests.
func (p helpPage) sectionedFlags() []string {
	var out []string
	for _, s := range p.sections {
		out = append(out, s.flags...)
	}
	sort.Strings(out)
	return out
}
