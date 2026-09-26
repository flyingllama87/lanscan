// Package importer validates bounded local files before active work can begin.
package importer

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"lanscan/internal/model"
)

const MaxInputBytes = 32 << 20

type Seed struct {
	Address netip.Addr
	Name    string
	Source  string
}

func ValidName(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func openBounded(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > MaxInputBytes {
		f.Close()
		return nil, errors.New("input must be a regular file no larger than 32 MiB")
	}
	return f, nil
}

func Seeds(path string, limit int) ([]Seed, error) {
	f, err := openBounded(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, MaxInputBytes+1))
	sc.Buffer(make([]byte, 4096), 4096)
	var out []Seed
	for n := 1; sc.Scan(); n++ {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if len(out) >= limit {
			return nil, fmt.Errorf("%s:%d: seed limit exceeded", path, n)
		}
		v := Seed{Source: fmt.Sprintf("%s:%d", path, n)}
		if a, e := netip.ParseAddr(s); e == nil {
			v.Address = a.Unmap()
		} else if ValidName(s) {
			v.Name = strings.ToLower(strings.TrimSuffix(s, "."))
		} else {
			return nil, fmt.Errorf("%s:%d: invalid IP or hostname", path, n)
		}
		out = append(out, v)
	}
	return out, sc.Err()
}

func Inventory(path string, limit int) ([]model.Event, error) {
	f, err := openBounded(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rd := csv.NewReader(io.LimitReader(f, MaxInputBytes+1))
	rd.FieldsPerRecord = 5
	header, err := rd.Read()
	if err != nil {
		return nil, err
	}
	if strings.Join(header, ",") != "realm,prefix,kind,source,observed_at" {
		return nil, errors.New("inventory header must be realm,prefix,kind,source,observed_at")
	}
	var out []model.Event
	for {
		row, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		line, _ := rd.FieldPos(0)
		if len(out) >= limit {
			return nil, fmt.Errorf("%s:%d: inventory limit exceeded", path, line)
		}
		p, err := netip.ParsePrefix(row[1])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		p = p.Masked()
		if row[0] == "" || row[3] == "" {
			return nil, fmt.Errorf("%s:%d: realm and source required", path, line)
		}
		if row[2] != "subnet" && row[2] != "allocation" && row[2] != "route" {
			return nil, fmt.Errorf("%s:%d: invalid kind", path, line)
		}
		var at *time.Time
		if row[4] != "" {
			t, err := time.Parse(time.RFC3339Nano, row[4])
			if err != nil {
				return nil, fmt.Errorf("%s:%d: invalid observed_at", path, line)
			}
			at = &t
		}
		out = append(out, model.Event{Type: "observation", RealmID: row[0], Prefix: &p, PrefixBasis: "inventory", Source: row[3], ObservedAt: at, Details: map[string]any{"kind": row[2], "import_file": path, "line": line}})
	}
	return out, nil
}
