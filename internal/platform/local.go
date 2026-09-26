package platform

import (
	"bufio"
	"context"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"lanscan/internal/model"
)

func Hosts(ctx context.Context, emit Emit) error {
	path := "/etc/hosts"
	if runtime.GOOS == "windows" {
		path = filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts")
	}
	f, err := os.Open(path)
	if err != nil {
		return status(emit, "hosts", "failed", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 1<<20))
	sc.Buffer(make([]byte, 4096), 64<<10)
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return status(emit, "hosts", "timed_out", err)
		}
		fields := strings.Fields(strings.SplitN(sc.Text(), "#", 2)[0])
		if len(fields) < 2 {
			continue
		}
		a, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		for _, name := range fields[1:] {
			if err := emit(model.Event{Type: "observation", Address: a.Unmap().String(), Name: name, Source: "hosts", Details: map[string]any{"file": path}}); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return status(emit, "hosts", "partial", err)
	}
	return status(emit, "hosts", "complete", nil)
}
