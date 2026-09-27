package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"lanscan/internal/journal"
	"lanscan/internal/model"
	"lanscan/internal/output"
)

type exportOptions struct {
	path, format, view, output string
	raw                        bool
}

func exportFlags(o *exportOptions) *flag.FlagSet {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.StringVar(&o.path, "journal", "", "journal `FILE` to read")
	fs.StringVar(&o.view, "view", "events", "`VIEW`: events (everything) or latest (current findings only)")
	fs.StringVar(&o.format, "format", "jsonl", "results `FORMAT`: text, jsonl or csv")
	fs.StringVar(&o.output, "output", "", "write to this new `FILE` instead of stdout")
	fs.BoolVar(&o.raw, "raw-csv", false, "keep formula-like text as is instead of neutralizing it for spreadsheets")
	alias(fs)
	return fs
}

var exportPage = helpPage{
	about: "lanscan export rewrites a journal offline; it sends nothing.",
	usage: []string{"lanscan export -j <journal.jsonl> [--view events|latest] [-f text|jsonl|csv] [-o <file>]"},
	examples: [][2]string{
		{"lanscan export -j scan.jsonl --view latest -f csv -o findings.csv", "current findings as CSV"},
		{"lanscan export -j scan.jsonl", "every event as JSONL"},
	},
	sections: []helpSection{{"FLAGS", []string{"journal", "view", "format", "output", "raw-csv"}}},
}

func runExport(args []string, stdout, stderr io.Writer) (int, error) {
	var o exportOptions
	fs := exportFlags(&o)
	if err := parseFlags(fs, args, stdout, exportPage); err != nil {
		return 2, err
	}
	path, format, view, outputPath, raw := &o.path, &o.format, &o.view, &o.output, &o.raw
	if *path == "" {
		return 2, usageError{errors.New("--journal is required")}
	}
	if fs.NArg() > 0 {
		return 2, usageError{fmt.Errorf("unexpected argument %q", fs.Arg(0))}
	}
	if *view != "events" && *view != "latest" {
		return 2, usageError{errors.New("--view must be events or latest")}
	}
	f, err := os.Open(*path)
	if err != nil {
		return 1, err
	}
	defer f.Close()
	out, closeOut, err := openOutput(*outputPath, stdout)
	if err != nil {
		return 1, err
	}
	r, err := output.New(out, *format, *raw)
	if err != nil {
		closeOut()
		return 2, err
	}
	latest := make(map[string]model.Event)
	result, err := journal.Replay(f, func(e model.Event) error {
		if *view == "latest" {
			if e.Type == "finding_upsert" {
				latest[model.FindingKey(e)] = e
			}
			return nil
		}
		return r.Write(e)
	})
	if err == nil && *view == "latest" {
		keys := make([]string, 0, len(latest))
		for k := range latest {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if err = r.Write(latest[k]); err != nil {
				break
			}
		}
	}
	closeErr := closeOut()
	if err != nil {
		return 1, err
	}
	if closeErr != nil {
		return 1, closeErr
	}
	partial := len(result.TornTail) > 0
	for _, complete := range result.Runs {
		if !complete {
			partial = true
		}
	}
	if partial {
		fmt.Fprintln(stderr, "Warning: incomplete run or torn final record; complete records were exported.")
		return 3, nil
	}
	return 0, nil
}

type mergeOptions struct{ format, output string }

func mergeFlags(o *mergeOptions) *flag.FlagSet {
	fs := flag.NewFlagSet("merge", flag.ContinueOnError)
	fs.StringVar(&o.format, "format", "jsonl", "results `FORMAT`: text, jsonl or csv")
	fs.StringVar(&o.output, "output", "", "write to this new `FILE` instead of stdout")
	alias(fs)
	return fs
}

var mergePage = helpPage{
	about: "lanscan merge combines journals from several runs or machines, offline.",
	usage: []string{"lanscan merge [-f text|jsonl|csv] [-o <file>] <journal.jsonl> <journal.jsonl>..."},
	examples: [][2]string{
		{"lanscan merge office-a.jsonl office-b.jsonl -o all.jsonl", "one combined journal"},
	},
	sections: []helpSection{{"FLAGS", []string{"format", "output"}}},
}

func runMerge(args []string, stdout, stderr io.Writer) (int, error) {
	var o mergeOptions
	fs := mergeFlags(&o)
	format, outputPath := &o.format, &o.output
	// Flags may come before or after the journal paths.
	var options, inputs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			inputs = append(inputs, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") {
			inputs = append(inputs, arg)
			continue
		}
		options = append(options, arg)
		name := strings.TrimLeft(arg, "-")
		if f := fs.Lookup(name); f != nil && !strings.Contains(name, "=") && i+1 < len(args) {
			if b, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok || !b.IsBoolFlag() {
				i++
				options = append(options, args[i])
			}
		}
	}
	if err := parseFlags(fs, append(append(options, "--"), inputs...), stdout, mergePage); err != nil {
		return 2, err
	}
	paths := fs.Args()
	if len(paths) < 2 {
		return 2, usageError{errors.New("merge needs at least two journals")}
	}
	out, closeOut, err := openOutput(*outputPath, stdout)
	if err != nil {
		return 1, err
	}
	r, err := output.New(out, *format, false)
	if err != nil {
		closeOut()
		return 2, err
	}
	seen := make(map[string]string)
	partial := false
	for _, path := range paths {
		f, e := os.Open(path)
		if e != nil {
			err = e
			break
		}
		result, e := journal.Replay(f, func(e model.Event) error {
			b, _ := json.Marshal(e)
			if old, ok := seen[e.EventID]; ok {
				if old != string(b) {
					return fmt.Errorf("conflicting event %s", e.EventID)
				}
				return nil
			}
			seen[e.EventID] = string(b)
			return r.Write(e)
		})
		f.Close()
		if e != nil {
			err = e
			break
		}
		if len(result.TornTail) > 0 {
			partial = true
		}
		for _, complete := range result.Runs {
			if !complete {
				partial = true
			}
		}
	}
	closeErr := closeOut()
	if err != nil {
		return 1, err
	}
	if closeErr != nil {
		return 1, closeErr
	}
	if partial {
		fmt.Fprintln(stderr, "Warning: at least one input run is incomplete.")
		return 3, nil
	}
	return 0, nil
}
