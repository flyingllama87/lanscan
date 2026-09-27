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

func runExport(args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("journal", "", "input JSONL journal")
	format := fs.String("format", "jsonl", "jsonl, csv, or text")
	view := fs.String("view", "events", "events or latest findings")
	outputPath := fs.String("output", "", "exclusive output file")
	raw := fs.Bool("raw-csv", false, "preserve formula-leading text without spreadsheet neutralization")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *path == "" || fs.NArg() > 0 || (*view != "events" && *view != "latest") {
		return 2, errors.New("--journal required; --view must be events or latest")
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

func runMerge(args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("merge", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "jsonl", "jsonl, csv, or text")
	outputPath := fs.String("output", "", "exclusive output file")
	// Accept the documented command form with options after input paths.
	var options, inputs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			inputs = append(inputs, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") {
			options = append(options, arg)
			if (arg == "--format" || arg == "--output" || arg == "-format" || arg == "-output") && i+1 < len(args) {
				i++
				options = append(options, args[i])
			}
		} else {
			inputs = append(inputs, arg)
		}
	}
	if err := fs.Parse(append(append(options, "--"), inputs...)); err != nil {
		return 2, err
	}
	paths := fs.Args()
	if len(paths) < 2 {
		return 2, errors.New("merge requires at least two journals; flags precede paths")
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
