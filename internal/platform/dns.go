package platform

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"lanscan/internal/model"
)

const (
	helperOutputLimit = 1 << 20
	helperTimeout     = 3 * time.Second
	maxCacheEntries   = 10000
)

var errHelperMissing = errors.New("helper not installed")

// ansiEscape strips terminal colour sequences some helpers emit regardless of
// SYSTEMD_COLORS.
var ansiEscape = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")

type limitedBuffer struct {
	bytes.Buffer
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := helperOutputLimit - b.Len(); len(p) > room {
		b.truncated = true
		if room > 0 {
			b.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// runHelper runs a fixed executable path with a fixed argument array: no
// shell, no interpolated input, bounded output and a deadline.
func runHelper(ctx context.Context, paths []string, args ...string) ([]byte, bool, error) {
	path := ""
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			path = p
			break
		}
	}
	if path == "" {
		return nil, false, errHelperMissing
	}
	ctx, cancel := context.WithTimeout(ctx, helperTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=")
	var out, stderr limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	cmd.Stdin = nil
	err := cmd.Run()
	// A killed helper reports only an exit status; the deadline is the cause.
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out.Bytes(), out.truncated, fmt.Errorf("helper exceeded %s deadline: %w", helperTimeout, context.DeadlineExceeded)
	}
	if err != nil && stderr.Len() > 0 {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 200 {
			msg = msg[:200]
		}
		err = errors.New(err.Error() + ": " + msg)
	}
	return out.Bytes(), out.truncated, err
}

func helperStatus(err error) string {
	switch {
	case errors.Is(err, errHelperMissing):
		return "unsupported"
	case errors.Is(err, context.DeadlineExceeded):
		return "timed_out"
	case err != nil && (strings.Contains(strings.ToLower(err.Error()), "access is denied") || strings.Contains(strings.ToLower(err.Error()), "access denied") || strings.Contains(strings.ToLower(err.Error()), "permission") || strings.Contains(strings.ToLower(err.Error()), "not authorized")):
		return "denied"
	}
	return "failed"
}

// CacheRecord is one positive A/AAAA record read from a local DNS cache.
type CacheRecord struct {
	Name      string
	Address   netip.Addr
	Interface string
	TTL       int
}

// ParseResolvectlCache reads `resolvectl show-cache` output. Unknown lines are
// ignored; only positive A/AAAA records are retained.
func ParseResolvectlCache(b []byte) []CacheRecord {
	var out []CacheRecord
	iface := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 4096), 64<<10)
	for sc.Scan() && len(out) < maxCacheEntries {
		fields := strings.Fields(ansiEscape.ReplaceAllString(sc.Text(), ""))
		if len(fields) > 0 && fields[0] == "Scope" {
			iface = ""
			for _, f := range fields[1:] {
				// systemd 255 prints ifname=; older documentation shows interface=.
				for _, key := range []string{"ifname=", "interface="} {
					if v, ok := strings.CutPrefix(f, key); ok {
						iface = strings.TrimSuffix(v, ":")
					}
				}
			}
			continue
		}
		if len(fields) < 4 || fields[1] != "IN" || (fields[2] != "A" && fields[2] != "AAAA") {
			continue
		}
		a, err := netip.ParseAddr(fields[3])
		if err != nil || (fields[2] == "A") != a.Is4() {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(fields[0], "."))
		if !validDNSName(name) {
			continue
		}
		out = append(out, CacheRecord{Name: name, Address: a, Interface: iface, TTL: -1})
	}
	return out
}

// ParsePowerShellCache reads "entry|type|data|ttl" lines from the fixed
// Get-DnsClientCache adapter command; type 1 is A and 28 is AAAA.
func ParsePowerShellCache(b []byte) []CacheRecord {
	var out []CacheRecord
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 4096), 64<<10)
	for sc.Scan() && len(out) < maxCacheEntries {
		parts := strings.Split(strings.TrimSpace(sc.Text()), "|")
		if len(parts) != 4 || (parts[1] != "1" && parts[1] != "28") {
			continue
		}
		a, err := netip.ParseAddr(parts[2])
		if err != nil || (parts[1] == "1") != a.Is4() {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(parts[0], "."))
		if !validDNSName(name) {
			continue
		}
		ttl, err := strconv.Atoi(parts[3])
		if err != nil || ttl < 0 {
			ttl = -1
		}
		out = append(out, CacheRecord{Name: name, Address: a, TTL: ttl})
	}
	return out
}

func validDNSName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

func emitCache(emit Emit, provider string, records []CacheRecord, truncated bool) error {
	for _, r := range records {
		details := map[string]any{"provider": provider, "freshness": "unknown"}
		if r.TTL >= 0 {
			details["ttl_remaining_s"] = r.TTL
			details["freshness"] = "ttl_remaining"
		}
		// Cache observation time is unknown; it is not stamped as "now".
		if err := emit(model.Event{Type: "observation", Source: "dns_cache", Name: r.Name, Address: r.Address.String(), InterfaceID: r.Interface, ActivityBasis: "cache", Reachability: "unknown", Details: details}); err != nil {
			return err
		}
	}
	outcome := "complete"
	var err error
	if truncated || len(records) >= maxCacheEntries {
		outcome = "partial"
		err = errors.New("cache output exceeded collection limit")
	}
	return status(emit, "dns_cache", outcome, err)
}

// ResolvConf holds nameservers and search domains from a resolv.conf file.
type ResolvConf struct {
	Nameservers []netip.Addr
	Search      []string
}

func ParseResolvConf(r io.Reader) ResolvConf {
	var c ResolvConf
	sc := bufio.NewScanner(io.LimitReader(r, 1<<20))
	sc.Buffer(make([]byte, 4096), 64<<10)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			if a, err := netip.ParseAddr(fields[1]); err == nil && len(c.Nameservers) < 16 {
				c.Nameservers = append(c.Nameservers, a.Unmap())
			}
		case "search", "domain":
			c.Search = nil
			for _, d := range fields[1:] {
				d = strings.ToLower(strings.TrimSuffix(d, "."))
				if validDNSName(d) && len(c.Search) < 16 {
					c.Search = append(c.Search, d)
				}
			}
		}
	}
	return c
}
