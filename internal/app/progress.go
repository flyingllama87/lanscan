package app

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"lanscan/internal/model"
)

// progress keeps one status line on a terminal while a run works. The stream
// serializes Write calls.
type progress struct {
	w          io.Writer
	start      time.Time
	last       time.Time
	shown      int
	phase      string
	ops        int
	responded  int
	traces     int
	listenDone time.Time
}

func newProgress(w io.Writer) *progress {
	now := time.Now()
	return &progress{w: w, start: now, last: now, phase: "reading local state"}
}

// isTerminal reports whether w is a character device, such as a console.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func (p *progress) Write(e model.Event) error {
	switch {
	case e.Type == "capability" && e.Source == "listen":
		var d struct {
			Duration int64 `json:"duration_ns"`
		}
		_ = decodeValue(e.Details, &d)
		p.listenDone = time.Now().Add(time.Duration(d.Duration))
		p.phase = "listening"
	case e.Type == "operation_reserved":
		p.ops++
		p.phase = "probing"
	case e.Type == "observation" && e.Source == "probe" && e.Reachability == "endpoint_response":
		p.responded++
	case e.Type == "trace_finished":
		p.traces++
	case e.Type == "run_finished":
		p.clear()
		return nil
	}
	if time.Since(p.last) < 150*time.Millisecond {
		return nil
	}
	p.last = time.Now()
	p.draw()
	return nil
}

func (p *progress) draw() {
	parts := []string{"lanscan: " + p.phase}
	if p.phase == "listening" {
		if left := time.Until(p.listenDone).Round(time.Second); left > 0 {
			parts[0] += fmt.Sprintf(" (%s left)", left)
		}
	}
	if p.ops > 0 {
		parts = append(parts, fmt.Sprintf("%d operations", p.ops), fmt.Sprintf("%d responded", p.responded))
	}
	if p.traces > 0 {
		parts = append(parts, fmt.Sprintf("%d paths traced", p.traces))
	}
	parts = append(parts, time.Since(p.start).Round(time.Second).String())
	line := strings.Join(parts, " · ")
	// Pad over a longer previous line; no escape sequences, so any console works.
	fmt.Fprintf(p.w, "\r%-*s", p.shown, line)
	p.shown = len(line)
}

func (p *progress) clear() {
	if p.shown > 0 {
		fmt.Fprintf(p.w, "\r%s\r", strings.Repeat(" ", p.shown))
		p.shown = 0
	}
}

// tee writes each event to both renderers, progress first so its line is
// cleared before the summary prints.
type tee struct {
	first, second interface{ Write(model.Event) error }
}

func (t tee) Write(e model.Event) error {
	if err := t.first.Write(e); err != nil {
		return err
	}
	return t.second.Write(e)
}
