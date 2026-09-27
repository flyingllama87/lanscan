package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"lanscan/internal/discover"
	"lanscan/internal/model"
)

// maxRows bounds each summary table; the full data is in jsonl and csv.
const maxRows = 50

// summary accumulates a run's events and renders a short human report at
// run_finished (or Close). It keeps only what the report shows: subnets,
// hosts, resolvers, default routes, traces and problems. Evidence it hides
// (loopback, multicast, link-local, the host's own routes) stays in jsonl.
type summary struct {
	w       io.Writer
	printed bool
	any     bool

	version  string
	cfg      runConfig
	subnets  map[netip.Prefix]*subnet
	own      map[netip.Addr]string // this host's addresses and interfaces
	hosts    map[netip.Addr]*host
	dns      []netip.Addr
	defaults []string
	traces   map[string][]hop
	named    map[netip.Addr][]string // hosts-file names, applied to found hosts
	notes    []string
	noted    map[string]bool
	plan     map[string]any
	finished map[string]any
	outcome  string
}

type runConfig struct {
	Intensity int   `json:"intensity"`
	Plan      bool  `json:"plan"`
	Listen    int64 `json:"listen"`
	Tuning    struct {
		Port          int     `json:"tcp_port"`
		Rate          float64 `json:"rate"`
		MaxOperations int     `json:"max_operations"`
	} `json:"tuning"`
}

type subnet struct {
	iface   string
	gateway string
	from    map[string]bool
}

type host struct {
	names     map[string]bool
	mac       string
	from      map[string]bool
	responded string // how it answered, e.g. "icmp 1.2ms"
	probed    bool
	router    bool // answered a trace from the middle of a path
}

type hop struct {
	limit   int
	address string
}

func newSummary(w io.Writer) *summary {
	return &summary{w: w, subnets: map[netip.Prefix]*subnet{}, own: map[netip.Addr]string{}, hosts: map[netip.Addr]*host{}, traces: map[string][]hop{}, named: map[netip.Addr][]string{}, noted: map[string]bool{}}
}

// decode reads v (typed during a run, generic after a journal replay) into dst.
func decode(v any, dst any) {
	if b, err := json.Marshal(v); err == nil {
		_ = json.Unmarshal(b, dst)
	}
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return clean(fmt.Sprint(v))
}

// clean escapes anything that is not printable text, so names and messages
// from the network cannot drive the terminal.
func clean(s string) string {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			q := strconv.QuoteToASCII(s)
			return q[1 : len(q)-1]
		}
	}
	return s
}

// interesting reports whether a is worth showing as another host.
func interesting(a netip.Addr) bool {
	return a.IsValid() && !a.IsLoopback() && !a.IsMulticast() && !a.IsUnspecified() && !a.IsLinkLocalUnicast() && !a.IsLinkLocalMulticast() && a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// subnetWorthy reports whether p is a subnet a person would want listed.
func subnetWorthy(p netip.Prefix) bool {
	a := p.Addr()
	return p.Bits() > 0 && p.Bits() < a.BitLen() && interesting(a)
}

func (s *summary) note(msg string) {
	if !s.noted[msg] {
		s.noted[msg] = true
		s.notes = append(s.notes, msg)
	}
}

func (s *summary) addSubnet(p netip.Prefix, iface, gateway, from string) {
	p = p.Masked()
	if !subnetWorthy(p) {
		return
	}
	n := s.subnets[p]
	if n == nil {
		n = &subnet{from: map[string]bool{}}
		s.subnets[p] = n
	}
	if n.iface == "" {
		n.iface = clean(iface)
	}
	if n.gateway == "" && gateway != "" {
		n.gateway = gateway
	}
	n.from[from] = true
}

func (s *summary) addHost(addr, from string) *host {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return nil
	}
	a = a.Unmap().WithZone("")
	if !interesting(a) {
		return nil
	}
	h := s.hosts[a]
	if h == nil {
		h = &host{names: map[string]bool{}, from: map[string]bool{}}
		s.hosts[a] = h
	}
	if from != "" {
		h.from[from] = true
	}
	return h
}

func (s *summary) observe(e model.Event) {
	s.any = true
	switch e.Type {
	case "run_started":
		s.version = str(e.Details["version"])
		decode(e.Details["config"], &s.cfg)
	case "plan":
		decode(e.Details, &s.plan)
	case "run_finished":
		decode(e.Details, &s.finished)
		s.outcome = e.Outcome
	case "collector_status":
		switch e.Outcome {
		case "complete", "available":
		default:
			outcome := map[string]string{"denied": "not readable without more permission", "failed": "failed", "timed_out": "timed out", "unsupported": "not supported on this system", "partial": "partly read"}[e.Outcome]
			if outcome == "" {
				outcome = strings.ReplaceAll(e.Outcome, "_", " ")
			}
			msg := collectorName(clean(e.Source)) + ": " + outcome
			if err := str(e.Details["error"]); err != "" && e.Outcome != "denied" {
				msg += " (" + shorten(err) + ")"
			}
			s.note(msg)
		}
	case "capability":
		switch {
		case e.Outcome == "unavailable" && (e.Source == "icmp4" || e.Source == "icmp6"):
			msg := fmt.Sprintf("%s echo unavailable (%s); used only a TCP connect to port %d", strings.ToUpper(e.Source[:4])+"v"+e.Source[4:], shorten(str(e.Details["error"])), s.cfg.Tuning.Port)
			if runtime.GOOS == "linux" {
				msg += `. To enable ICMP, run as root or once: sudo setcap cap_net_raw+ep "$(command -v lanscan)"`
			}
			s.note(msg)
		case e.Outcome == "unavailable":
			s.note(fmt.Sprintf("%s unavailable (%s)", clean(e.Source), shorten(str(e.Details["error"]))))
		}
	case "trace_finished":
		s.traces[clean(e.Address)] = append(s.traces[clean(e.Address)], hop{limit: -1, address: clean(e.Outcome)})
	case "observation":
		s.observation(e)
	}
}

func (s *summary) observation(e model.Event) {
	switch e.Source {
	case "interfaces":
		if e.Prefix != nil && e.Address != "" {
			if a, err := netip.ParseAddr(e.Address); err == nil {
				s.own[a.WithZone("")] = clean(e.InterfaceID)
			}
			s.addSubnet(*e.Prefix, e.InterfaceID, "", "interface")
		}
	case "routes":
		if e.Prefix == nil || str(e.Details["route_type"]) != "unicast" {
			return
		}
		gw := str(e.Details["gateway"])
		if e.Prefix.Bits() == 0 {
			if gw != "" {
				s.defaults = append(s.defaults, fmt.Sprintf("%s on %s", gw, clean(e.InterfaceID)))
			}
			return
		}
		s.addSubnet(*e.Prefix, e.InterfaceID, gw, "route")
	case "hosts":
		// The hosts file names addresses; it is not evidence that they exist.
		if a, err := netip.ParseAddr(e.Address); err == nil && e.Name != "" {
			s.named[a.Unmap().WithZone("")] = append(s.named[a.Unmap().WithZone("")], clean(e.Name))
		}
	case "route_gateway":
		s.addHost(e.Address, "gateway")
	case "neighbors":
		if st := str(e.Details["state_name"]); st == "failed" || st == "incomplete" || st == "noarp" {
			return
		}
		if h := s.addHost(e.Address, "neighbour cache"); h != nil && h.mac == "" {
			h.mac = str(e.Details["mac"])
		}
	case "resolver_config":
		if a, err := netip.ParseAddr(e.Address); err == nil {
			for _, d := range s.dns {
				if d == a {
					return
				}
			}
			s.dns = append(s.dns, a)
		}
	case "dns_cache", "dns_forward", "dns_reverse":
		if h := s.addHost(e.Address, map[string]string{"dns_cache": "DNS cache", "dns_forward": "DNS", "dns_reverse": "DNS"}[e.Source]); h != nil && e.Name != "" {
			h.names[clean(strings.TrimSuffix(e.Name, "."))] = true
		}
	case "probe":
		h := s.addHost(e.Address, "")
		if h == nil {
			return
		}
		h.probed = true
		if e.Reachability == "endpoint_response" && h.responded == "" {
			h.responded = e.Protocol
			if e.Protocol == "tcp" && e.Port != 0 {
				h.responded = fmt.Sprintf("tcp/%d %s", e.Port, e.Outcome)
			}
			var d struct {
				RTT int64 `json:"rtt_ns"`
			}
			decode(e.Details, &d)
			if d.RTT > 0 {
				h.responded += " " + time.Duration(d.RTT).Round(100*time.Microsecond).String()
			}
		}
	case "trace":
		var d struct {
			Target string `json:"trace_target"`
			Hop    int    `json:"hop_limit"`
		}
		decode(e.Details, &d)
		s.traces[clean(d.Target)] = append(s.traces[clean(d.Target)], hop{limit: d.Hop, address: clean(e.Address)})
		if h := s.addHost(e.Address, "trace"); h != nil {
			if e.Address == d.Target && e.Outcome == "echo_reply" {
				if h.responded == "" {
					h.responded = "icmp (trace)"
				}
			} else {
				h.router = true
			}
		}
	case "listen":
		from := "heard " + clean(e.Protocol)
		if e.Prefix != nil {
			s.addSubnet(*e.Prefix, e.InterfaceID, "", from)
		}
		if e.Address != "" {
			h := s.addHost(e.Address, from)
			if h != nil && h.mac == "" {
				h.mac = str(e.Details["mac"])
			}
			if h != nil {
				if n := str(e.Details["system_name"]); n != "" {
					h.names[n] = true
				}
				if n := str(e.Details["device_id"]); n != "" {
					h.names[n] = true
				}
			}
		}
	default:
		// Inventory rows and seeds are tagged with their own file or source.
		switch {
		case e.Prefix != nil && e.PrefixBasis == "inventory":
			s.addSubnet(*e.Prefix, e.InterfaceID, "", "inventory")
		case e.Prefix == nil && e.Address != "":
			s.addHost(e.Address, "seed")
		}
	}
}

func collectorName(source string) string {
	switch source {
	case "dns_cache":
		return "DNS cache"
	case "neighbors":
		return "neighbour cache"
	}
	return strings.ReplaceAll(source, "_", " ")
}

func shorten(s string) string {
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s) > 60 {
		s = s[i+2:]
	}
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return strings.ToLower(s[:min(1, len(s))]) + s[min(1, len(s)):]
}

// subnetOf returns the most specific listed subnet containing a.
func (s *summary) subnetOf(a netip.Addr) (netip.Prefix, bool) {
	var best netip.Prefix
	for p := range s.subnets {
		if p.Contains(a) && (!best.IsValid() || p.Bits() > best.Bits()) {
			best = p
		}
	}
	return best, best.IsValid()
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// prepare finishes the host list: hosts-file names, and neither this
// host's addresses nor subnet broadcasts count as hosts.
func (s *summary) prepare() bool {
	if s.printed || !s.any {
		return false
	}
	s.printed = true
	for a, names := range s.named {
		if h := s.hosts[a]; h != nil {
			for _, n := range names {
				h.names[n] = true
			}
		}
	}
	for a := range s.hosts {
		if _, mine := s.own[a]; mine {
			delete(s.hosts, a)
			continue
		}
		for p, n := range s.subnets {
			if n.from["interface"] && discover.IsBroadcast(a, p) {
				delete(s.hosts, a)
			}
		}
	}
	return true
}

func (s *summary) print() error {
	if !s.prepare() {
		return nil
	}
	b := &strings.Builder{}
	s.header(b)
	s.subnetTable(b)
	s.hostTable(b)
	s.planTable(b)
	s.traceLines(b)
	s.contextLines(b)
	s.footer(b)
	_, err := io.WriteString(s.w, b.String())
	return err
}

// csvHeader is the table form of the summary: one row per subnet, then one
// per host.
var csvHeader = []string{"kind", "subnet", "address", "name", "mac", "interface", "this_host", "gateway", "hosts", "responded", "known_from", "status"}

func (s *summary) printCSV(raw bool) error {
	if !s.prepare() {
		return nil
	}
	w := csv.NewWriter(s.w)
	rows := [][]string{csvHeader}
	for _, r := range s.subnetRows() {
		rows = append(rows, []string{"subnet", r.prefix.String(), "", "", "", r.iface, r.this, r.gateway, strconv.Itoa(r.hosts), strconv.Itoa(r.responded), r.from, ""})
	}
	for _, r := range s.hostRows() {
		rows = append(rows, []string{"host", r.subnet, r.addr.String(), r.names, r.mac, r.iface, "", "", "", "", r.from, r.status})
	}
	for _, row := range rows {
		if !raw {
			for i := range row {
				row[i] = safe(row[i])
			}
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

func (s *summary) header(b *strings.Builder) {
	parts := []string{"lanscan"}
	if s.version != "" {
		parts[0] += " " + s.version
	}
	switch {
	case s.cfg.Plan:
		parts = append(parts, fmt.Sprintf("intensity %d plan (nothing sent)", s.cfg.Intensity))
	case s.cfg.Intensity == 0:
		parts = append(parts, "passive (nothing sent)")
	default:
		parts = append(parts, fmt.Sprintf("intensity %d", s.cfg.Intensity))
	}
	if s.cfg.Listen > 0 {
		parts = append(parts, "listened "+time.Duration(s.cfg.Listen).String())
	}
	var f struct {
		Elapsed int64 `json:"elapsed_ms"`
	}
	decode(s.finished, &f)
	if s.finished != nil {
		parts = append(parts, (time.Duration(f.Elapsed) * time.Millisecond).String())
	}
	fmt.Fprintln(b, strings.Join(parts, " · "))
}

type subnetRow struct {
	prefix                     netip.Prefix
	iface, this, gateway, from string
	hosts, responded           int
}

// subnetRows orders subnets: this host's first, then routed, then others.
func (s *summary) subnetRows() []subnetRow {
	prefixes := make([]netip.Prefix, 0, len(s.subnets))
	for p := range s.subnets {
		prefixes = append(prefixes, p)
	}
	rank := func(p netip.Prefix) int {
		n := s.subnets[p]
		switch {
		case n.from["interface"]:
			return 0
		case n.from["route"]:
			return 1
		}
		return 2
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if ri, rj := rank(prefixes[i]), rank(prefixes[j]); ri != rj {
			return ri < rj
		}
		if prefixes[i].Addr().Is4() != prefixes[j].Addr().Is4() {
			return prefixes[i].Addr().Is4()
		}
		return prefixes[i].Addr().Less(prefixes[j].Addr())
	})
	counts := map[netip.Prefix][2]int{}
	for a, h := range s.hosts {
		if p, ok := s.subnetOf(a); ok {
			c := counts[p]
			c[0]++
			if h.responded != "" {
				c[1]++
			}
			counts[p] = c
		}
	}
	rows := make([]subnetRow, 0, len(prefixes))
	for _, p := range prefixes {
		n := s.subnets[p]
		var mine []string
		for a := range s.own {
			if p.Contains(a) {
				mine = append(mine, a.String())
			}
		}
		sort.Strings(mine)
		gw := n.gateway
		if gw == "" {
			// A default gateway inside a connected subnet is its gateway.
			for _, d := range s.defaults {
				g, _, _ := strings.Cut(d, " ")
				if a, err := netip.ParseAddr(g); err == nil && p.Contains(a) {
					gw = g
				}
			}
		}
		c := counts[p]
		rows = append(rows, subnetRow{prefix: p, iface: n.iface, this: strings.Join(mine, ","), gateway: gw, from: strings.Join(sortedKeys(n.from), ", "), hosts: c[0], responded: c[1]})
	}
	return rows
}

func (s *summary) probing() bool { return s.cfg.Intensity > 0 && !s.cfg.Plan }

func (s *summary) subnetTable(b *strings.Builder) {
	rows := s.subnetRows()
	fmt.Fprintf(b, "\nSUBNETS (%d)\n", len(rows))
	if len(rows) == 0 {
		fmt.Fprintln(b, "  none found")
		return
	}
	t := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
	hosts := "HOSTS"
	if s.probing() {
		hosts = "HOSTS (RESPONDED)"
	}
	fmt.Fprintf(t, "  SUBNET\tINTERFACE\tTHIS HOST\tGATEWAY\t%s\tKNOWN FROM\n", hosts)
	for i, r := range rows {
		if i == maxRows {
			fmt.Fprintf(t, "  … %d more (see -f csv)\n", len(rows)-maxRows)
			break
		}
		count := fmt.Sprint(r.hosts)
		if s.probing() {
			count = fmt.Sprintf("%d (%d)", r.hosts, r.responded)
		}
		fmt.Fprintf(t, "  %s\t%s\t%s\t%s\t%s\t%s\n", r.prefix, dash(r.iface), dash(r.this), dash(r.gateway), count, r.from)
	}
	t.Flush()
}

type hostRow struct {
	addr                                    netip.Addr
	subnet, iface, names, mac, from, status string
}

func (s *summary) hostRows() []hostRow {
	addrs := make([]netip.Addr, 0, len(s.hosts))
	for a := range s.hosts {
		addrs = append(addrs, a)
	}
	sort.Slice(addrs, func(i, j int) bool {
		if addrs[i].Is4() != addrs[j].Is4() {
			return addrs[i].Is4()
		}
		return addrs[i].Less(addrs[j])
	})
	rows := make([]hostRow, 0, len(addrs))
	for _, a := range addrs {
		h := s.hosts[a]
		r := hostRow{addr: a, names: strings.Join(sortedKeys(h.names), ","), mac: h.mac, from: strings.Join(sortedKeys(h.from), ", ")}
		if p, ok := s.subnetOf(a); ok {
			r.subnet, r.iface = p.String(), s.subnets[p].iface
		}
		if s.probing() {
			switch {
			case h.responded != "":
				r.status = "responded " + h.responded
			case h.probed:
				r.status = "silent"
			case h.router:
				r.status = "router on a traced path"
			default:
				r.status = "not probed"
			}
		}
		rows = append(rows, r)
	}
	return rows
}

func (s *summary) hostTable(b *strings.Builder) {
	rows := s.hostRows()
	fmt.Fprintf(b, "\nHOSTS (%d)\n", len(rows))
	if len(rows) == 0 {
		fmt.Fprintln(b, "  none found")
		return
	}
	t := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
	status := ""
	if s.probing() {
		status = "\tSTATUS"
	}
	fmt.Fprintf(t, "  ADDRESS\tNAME\tMAC\tKNOWN FROM%s\n", status)
	for i, r := range rows {
		if i == maxRows {
			fmt.Fprintf(t, "  … %d more (see -f csv)\n", len(rows)-maxRows)
			break
		}
		row := fmt.Sprintf("  %s\t%s\t%s\t%s", r.addr, dash(r.names), dash(r.mac), r.from)
		if s.probing() {
			row += "\t" + r.status
		}
		fmt.Fprintln(t, row)
	}
	t.Flush()
}

func (s *summary) planTable(b *strings.Builder) {
	if !s.cfg.Plan || s.plan == nil {
		return
	}
	var p struct {
		Candidates int `json:"candidates"`
		Targets    []struct {
			Address string `json:"address"`
			Kind    string `json:"kind"`
		} `json:"targets"`
	}
	decode(s.plan, &p)
	fmt.Fprintf(b, "\nWOULD PROBE (%d)\n", p.Candidates)
	if p.Candidates == 0 {
		fmt.Fprintln(b, "  nothing at this intensity")
		return
	}
	t := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(t, "  ADDRESS\tWHY")
	for i, target := range p.Targets {
		if i == maxRows {
			break
		}
		fmt.Fprintf(t, "  %s\t%s\n", clean(target.Address), clean(target.Kind))
	}
	if p.Candidates > min(len(p.Targets), maxRows) {
		fmt.Fprintf(t, "  … %d more (see -f jsonl)\n", p.Candidates-min(len(p.Targets), maxRows))
	}
	t.Flush()
}

func (s *summary) traceLines(b *strings.Builder) {
	if len(s.traces) == 0 {
		return
	}
	targets := make([]string, 0, len(s.traces))
	for t := range s.traces {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	fmt.Fprintf(b, "\nPATHS (%d)\n", len(targets))
	for _, target := range targets {
		hops := s.traces[target]
		sort.SliceStable(hops, func(i, j int) bool { return hops[i].limit >= 0 && (hops[j].limit < 0 || hops[i].limit < hops[j].limit) })
		var path []string
		stop := ""
		for _, h := range hops {
			switch {
			case h.limit < 0:
				stop = h.address
			case h.address == "":
				path = append(path, "*")
			default:
				path = append(path, h.address)
			}
		}
		line := fmt.Sprintf("  %s: %s", target, strings.Join(path, " → "))
		if stop != "" && stop != "destination_reached" {
			line += "  (" + strings.ReplaceAll(stop, "_", " ") + ")"
		}
		fmt.Fprintln(b, line)
	}
}

func (s *summary) contextLines(b *strings.Builder) {
	fmt.Fprintln(b)
	if len(s.defaults) > 0 {
		fmt.Fprintf(b, "Default route: %s\n", strings.Join(s.defaults, "; "))
	}
	if len(s.dns) > 0 {
		var names []string
		for _, a := range s.dns {
			n := a.String()
			if a.IsLoopback() {
				n += " (local resolver)"
			}
			names = append(names, n)
		}
		fmt.Fprintf(b, "DNS servers: %s\n", strings.Join(names, ", "))
	}
	if len(s.notes) > 0 {
		fmt.Fprintln(b, "\nNotes:")
		for _, n := range s.notes {
			fmt.Fprintln(b, "  "+n)
		}
	}
}

var stopReasons = map[string]string{
	"operation_budget_exhausted":      "stopped early: the operation budget ran out (raise --max-operations)",
	"duration_exhausted":              "stopped early: --duration ran out (raise it or lower --intensity)",
	"capacity_exceeded":               "some evidence was dropped: raise --candidate-limit",
	"required_capability_unavailable": "a --require-capability was not met",
	"interrupted":                     "interrupted; results are partial",
}

func (s *summary) footer(b *strings.Builder) {
	fmt.Fprintln(b)
	if msg, ok := stopReasons[s.outcome]; ok {
		fmt.Fprintln(b, "Result: "+msg+".")
	}
	var f struct {
		Operations int `json:"operations"`
	}
	decode(s.finished, &f)
	switch {
	case s.cfg.Plan:
		var p struct {
			Candidates int `json:"candidates"`
			Synthetic  int `json:"synthetic_samples"`
			Neighbours int `json:"neighbour_guesses"`
			Traces     int `json:"trace_destinations"`
			DNSBudget  int `json:"dns_budget"`
			MaxOps     int `json:"max_operations"`
		}
		decode(s.plan, &p)
		known := p.Candidates - p.Synthetic
		fmt.Fprintf(b, "Plan: would probe %d addresses (%d known, %d guessed in known subnets, %d in neighbouring subnets)", p.Candidates, known, p.Synthetic-p.Neighbours, p.Neighbours)
		if p.Traces > 0 {
			fmt.Fprintf(b, ", trace up to %d paths", p.Traces)
		}
		fmt.Fprintf(b, ", using at most %d operations. Nothing was sent.\n", p.MaxOps)
		fmt.Fprintf(b, "Run it: drop --plan.\n")
	case s.cfg.Intensity == 0:
		fmt.Fprintln(b, "Nothing was sent. Next: lanscan -i 1 checks these hosts (add --plan to preview).")
	default:
		responded := 0
		for _, h := range s.hosts {
			if h.responded != "" {
				responded++
			}
		}
		fmt.Fprintf(b, "%d network operations; %d hosts responded. Silence is not absence: a host may block probes.\n", f.Operations, responded)
		if s.cfg.Intensity < 3 {
			fmt.Fprintf(b, "For more coverage: lanscan -i %d (add --plan to preview).\n", s.cfg.Intensity+1)
		}
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
