// Package listen derives address and prefix evidence from broadcast and
// multicast traffic heard on local links. It never transmits.
package listen

import (
	"encoding/binary"
	"net/netip"
)

// EtherType values, as reported for a received frame.
const (
	ProtoIPv4 = 0x0800
	ProtoARP  = 0x0806
	ProtoIPv6 = 0x86dd
	ProtoLLDP = 0x88cc
	// Proto8022 is how Linux reports 802.3 frames with an LLC header, such as CDP.
	Proto8022 = 0x0004
)

// Sighting is one piece of evidence from a frame. Address, Prefix, or both
// may be set; a sighting with neither carries only Details (for example an
// LLDP neighbour without a management address).
type Sighting struct {
	// Protocol names what was heard: arp, ndp, dhcp, lldp, cdp, ospf, vrrp,
	// hsrp, rip, mdns, ssdp, llmnr, netbios, igmp, mld, ipv4 or ipv6.
	Protocol string
	Address  netip.Addr
	// Role says what the frame claims about Address: sender, gateway,
	// dns_server, dhcp_server, dhcp_relay, dhcp_client, virtual_router,
	// management or ndp_target.
	Role        string
	Prefix      netip.Prefix
	PrefixBasis string
	Details     map[string]any
}

// Parse extracts sightings from a network-layer payload whose link-layer
// protocol is proto. It ignores anything it does not understand, and IPv6
// entirely when noIPv6 is set.
func Parse(proto uint16, b []byte, noIPv6 bool) []Sighting {
	var out []Sighting
	switch proto {
	case ProtoARP:
		out = parseARP(b)
	case ProtoIPv4:
		out = parseIPv4(b)
	case ProtoIPv6:
		if !noIPv6 {
			out = parseIPv6(b)
		}
	case ProtoLLDP:
		out = parseLLDP(b)
	case Proto8022:
		out = parseCDP(b)
	}
	if noIPv6 {
		kept := out[:0]
		for _, s := range out {
			if !s.Address.Is6() && !s.Prefix.Addr().Is6() {
				kept = append(kept, s)
			}
		}
		out = kept
	}
	return out
}

// usable reports whether a is worth recording as a host address.
func usable(a netip.Addr) bool {
	return a.IsValid() && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() && a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func addr4(b []byte) netip.Addr { return netip.AddrFrom4([4]byte(b[:4])) }

// maskPrefix returns a's prefix under a contiguous IPv4 mask, or an invalid
// prefix for a non-contiguous, zero or host mask.
func maskPrefix(a netip.Addr, mask []byte) netip.Prefix {
	m := binary.BigEndian.Uint32(mask)
	bits := 0
	for m&0x80000000 != 0 {
		bits++
		m <<= 1
	}
	if m != 0 || bits == 0 || bits == 32 {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(a, bits).Masked()
}

func parseARP(b []byte) []Sighting {
	// Ethernet/IPv4 ARP only: htype 1, ptype 0x0800, hlen 6, plen 4.
	if len(b) < 28 || binary.BigEndian.Uint16(b[0:]) != 1 || binary.BigEndian.Uint16(b[2:]) != ProtoIPv4 || b[4] != 6 || b[5] != 4 {
		return nil
	}
	sender := addr4(b[14:])
	if !usable(sender) {
		return nil // ARP probes (RFC 5227) have no sender address yet
	}
	mac := hwaddr(b[8:14])
	return []Sighting{{Protocol: "arp", Address: sender, Role: "sender", Details: map[string]any{"mac": mac, "operation": int(binary.BigEndian.Uint16(b[6:]))}}}
}

func hwaddr(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(b)*3)
	for i, v := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hex[v>>4], hex[v&0xf])
	}
	return string(out)
}

// udpProtocols names well-known broadcast and multicast services by port.
var udpProtocols = map[uint16]string{67: "dhcp", 68: "dhcp", 137: "netbios", 138: "netbios", 520: "rip", 1900: "ssdp", 1985: "hsrp", 5353: "mdns", 5355: "llmnr"}

func parseIPv4(b []byte) []Sighting {
	if len(b) < 20 || b[0]>>4 != 4 {
		return nil
	}
	ihl := int(b[0]&0xf) * 4
	total := int(binary.BigEndian.Uint16(b[2:]))
	if ihl < 20 || total < ihl || total > len(b) {
		return nil
	}
	fragment := binary.BigEndian.Uint16(b[6:]) & 0x1fff
	proto, src := b[9], addr4(b[12:])
	payload := b[ihl:total]
	name := "ipv4"
	var out []Sighting
	switch {
	case fragment != 0:
	case proto == 2:
		name = "igmp"
	case proto == 89:
		name = "ospf"
		out = parseOSPF(src, payload)
	case proto == 112:
		name = "vrrp"
		out = parseVRRP(payload, 4)
	case proto == 17 && len(payload) >= 8:
		sport, dport := binary.BigEndian.Uint16(payload), binary.BigEndian.Uint16(payload[2:])
		data := payload[8:]
		if p, ok := udpProtocols[dport]; ok {
			name = p
		} else if p, ok := udpProtocols[sport]; ok {
			name = p
		}
		switch name {
		case "dhcp":
			out = parseDHCP(data)
		case "rip":
			out = parseRIP(data)
		case "hsrp":
			out = parseHSRP(data)
		}
	}
	if usable(src) {
		out = append([]Sighting{{Protocol: name, Address: src, Role: "sender"}}, out...)
	}
	return out
}

func parseOSPF(src netip.Addr, b []byte) []Sighting {
	// OSPFv2 header (24 bytes), then a Hello body starting with the network mask.
	if len(b) < 28 || b[0] != 2 || b[1] != 1 || !usable(src) {
		return nil
	}
	p := maskPrefix(src, b[24:28])
	if !p.IsValid() {
		return nil
	}
	return []Sighting{{Protocol: "ospf", Prefix: p, PrefixBasis: "ospf_hello", Details: map[string]any{"router_id": addr4(b[4:]).String(), "area": addr4(b[8:]).String(), "router": src.String()}}}
}

// parseVRRP reads VRRPv2 and v3 advertisements; family is 4 or 6.
func parseVRRP(b []byte, family int) []Sighting {
	if len(b) < 8 || b[0]&0xf != 1 {
		return nil
	}
	version, vrid, priority, count := b[0]>>4, b[1], b[2], int(b[3])
	if version != 2 && version != 3 {
		return nil
	}
	size := 4
	if family == 6 {
		size = 16
	}
	var out []Sighting
	for i := 0; i < count && 8+(i+1)*size <= len(b); i++ {
		a, _ := netip.AddrFromSlice(b[8+i*size : 8+(i+1)*size])
		if usable(a) {
			out = append(out, Sighting{Protocol: "vrrp", Address: a, Role: "virtual_router", Details: map[string]any{"vrid": int(vrid), "priority": int(priority), "version": int(version)}})
		}
	}
	return out
}

func parseHSRP(b []byte) []Sighting {
	// HSRPv1: op code 0 (hello), virtual IP at offset 16.
	if len(b) < 20 || b[0] != 0 || b[1] != 0 {
		return nil
	}
	a := addr4(b[16:])
	if !usable(a) {
		return nil
	}
	return []Sighting{{Protocol: "hsrp", Address: a, Role: "virtual_router", Details: map[string]any{"group": int(b[6]), "priority": int(b[5])}}}
}

func parseRIP(b []byte) []Sighting {
	// RIPv2 responses carry masks; RIPv1 has none and adds only the sender.
	if len(b) < 4 || b[0] != 2 || b[1] != 2 {
		return nil
	}
	var out []Sighting
	for e := b[4:]; len(e) >= 20; e = e[20:] {
		if binary.BigEndian.Uint16(e) != 2 {
			continue // authentication or other families
		}
		metric := binary.BigEndian.Uint32(e[16:])
		p := maskPrefix(addr4(e[4:]), e[8:12])
		if !p.IsValid() || metric >= 16 {
			continue
		}
		d := map[string]any{"metric": int(metric)}
		if nh := addr4(e[12:]); usable(nh) {
			d["next_hop"] = nh.String()
		}
		out = append(out, Sighting{Protocol: "rip", Prefix: p, PrefixBasis: "rip", Details: d})
	}
	return out
}

var dhcpMessages = map[byte]string{1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack", 6: "nak", 7: "release", 8: "inform"}

func parseDHCP(b []byte) []Sighting {
	if len(b) < 240 || binary.BigEndian.Uint32(b[236:]) != 0x63825363 {
		return nil
	}
	ciaddr, yiaddr, giaddr := addr4(b[12:]), addr4(b[16:]), addr4(b[24:])
	opts := map[byte][]byte{}
	for o := b[240:]; len(o) > 0; {
		code := o[0]
		if code == 255 {
			break
		}
		if code == 0 {
			o = o[1:]
			continue
		}
		if len(o) < 2 || len(o) < 2+int(o[1]) {
			break
		}
		if _, dup := opts[code]; !dup {
			opts[code] = o[2 : 2+int(o[1])]
		}
		o = o[2+int(o[1]):]
	}
	d := map[string]any{}
	if t, ok := opts[53]; ok && len(t) == 1 {
		d["message"] = dhcpMessages[t[0]]
	}
	var out []Sighting
	add := func(a netip.Addr, role string) {
		if usable(a) {
			out = append(out, Sighting{Protocol: "dhcp", Address: a, Role: role, Details: d})
		}
	}
	add(ciaddr, "dhcp_client")
	add(yiaddr, "dhcp_client")
	add(giaddr, "dhcp_relay")
	if v, ok := opts[50]; ok && len(v) == 4 {
		add(addr4(v), "dhcp_client")
	}
	if v, ok := opts[54]; ok && len(v) == 4 {
		add(addr4(v), "dhcp_server")
	}
	for _, o := range []struct {
		code byte
		role string
	}{{3, "gateway"}, {6, "dns_server"}} {
		for v := opts[o.code]; len(v) >= 4; v = v[4:] {
			add(addr4(v), o.role)
		}
	}
	if m, ok := opts[1]; ok && len(m) == 4 && usable(yiaddr) {
		if p := maskPrefix(yiaddr, m); p.IsValid() {
			out = append(out, Sighting{Protocol: "dhcp", Prefix: p, PrefixBasis: "dhcp", Details: d})
		}
	}
	// Classless static routes (RFC 3442): width, significant octets, router.
	for v := opts[121]; len(v) > 0; {
		width := int(v[0])
		n := (width + 7) / 8
		if width > 32 || len(v) < 1+n+4 {
			break
		}
		var dst [4]byte
		copy(dst[:], v[1:1+n])
		if width > 0 && width < 32 {
			p := netip.PrefixFrom(netip.AddrFrom4(dst), width).Masked()
			out = append(out, Sighting{Protocol: "dhcp", Prefix: p, PrefixBasis: "dhcp_route", Details: map[string]any{"router": addr4(v[1+n:]).String()}})
		}
		v = v[1+n+4:]
	}
	return out
}

func parseIPv6(b []byte) []Sighting {
	if len(b) < 40 || b[0]>>4 != 6 {
		return nil
	}
	src := netip.AddrFrom16([16]byte(b[8:24]))
	next, payload := b[6], b[40:]
	if n := 40 + int(binary.BigEndian.Uint16(b[4:])); n <= len(b) {
		payload = b[40:n]
	}
	// MLD reports follow a hop-by-hop options header.
	if next == 0 && len(payload) >= 8 && len(payload) >= 8+int(payload[1])*8 {
		next, payload = payload[0], payload[8+int(payload[1])*8:]
	}
	name := "ipv6"
	var out []Sighting
	switch {
	case next == 58 && len(payload) >= 4:
		switch t := payload[0]; {
		case t >= 133 && t <= 137:
			name = "ndp"
			out = parseNDP(src, payload)
		case t == 130 || t == 131 || t == 143:
			name = "mld"
		}
	case next == 112:
		name = "vrrp"
		out = parseVRRP(payload, 6)
	case next == 17 && len(payload) >= 8:
		if p, ok := udpProtocols[binary.BigEndian.Uint16(payload[2:])]; ok {
			name = p
		}
	}
	if usable(src) {
		out = append([]Sighting{{Protocol: name, Address: src, Role: "sender"}}, out...)
	}
	return out
}

func parseNDP(src netip.Addr, b []byte) []Sighting {
	var out []Sighting
	switch b[0] {
	case 135, 136: // neighbour solicitation/advertisement: target at 8
		if len(b) >= 24 {
			if t := netip.AddrFrom16([16]byte(b[8:24])); usable(t) {
				out = append(out, Sighting{Protocol: "ndp", Address: t, Role: "ndp_target"})
			}
		}
	case 134: // router advertisement: options after 16 bytes
		if !usable(src) {
			return nil
		}
		for o := b[min(16, len(b)):]; len(o) >= 8; {
			n := int(o[1]) * 8
			if n == 0 || n > len(o) {
				break
			}
			switch opt := o[:n]; o[0] {
			case 3: // prefix information
				if n == 32 {
					p := netip.PrefixFrom(netip.AddrFrom16([16]byte(opt[16:32])), int(opt[2]))
					if opt[2] > 0 && opt[2] <= 128 && !p.Addr().IsLinkLocalUnicast() {
						out = append(out, Sighting{Protocol: "ndp", Prefix: p.Masked(), PrefixBasis: "router_advertisement", Details: map[string]any{"router": src.String(), "on_link": opt[3]&0x80 != 0, "autonomous": opt[3]&0x40 != 0}})
					}
				}
			case 24: // route information
				if bits := int(opt[2]); n >= 8 && bits > 0 && bits <= 128 && (bits+63)/64*8 <= n-8 {
					var a [16]byte
					copy(a[:], opt[8:n])
					out = append(out, Sighting{Protocol: "ndp", Prefix: netip.PrefixFrom(netip.AddrFrom16(a), bits).Masked(), PrefixBasis: "router_advertisement_route", Details: map[string]any{"router": src.String()}})
				}
			case 25: // recursive DNS servers
				for s := opt[8:]; len(s) >= 16; s = s[16:] {
					if a := netip.AddrFrom16([16]byte(s[:16])); usable(a) {
						out = append(out, Sighting{Protocol: "ndp", Address: a, Role: "dns_server"})
					}
				}
			}
			o = o[n:]
		}
		out = append(out, Sighting{Protocol: "ndp", Address: src, Role: "gateway"})
	}
	return out
}

func parseLLDP(b []byte) []Sighting {
	d := map[string]any{}
	var addrs []netip.Addr
	for len(b) >= 2 {
		t, n := b[0]>>1, int(binary.BigEndian.Uint16(b)&0x1ff)
		if t == 0 || len(b) < 2+n {
			break
		}
		v := b[2 : 2+n]
		switch t {
		case 1:
			if n > 1 {
				d["chassis_id"] = printable(v[1:], v[0] == 4)
			}
		case 2:
			if n > 1 {
				d["port_id"] = printable(v[1:], v[0] == 3)
			}
		case 4:
			d["port_description"] = printable(v, false)
		case 5:
			d["system_name"] = printable(v, false)
		case 8: // management address: length, subtype, address
			if n >= 2 && int(v[0]) >= 1 && int(v[0]) <= n-1 {
				if a, ok := netip.AddrFromSlice(v[2 : 1+int(v[0])]); ok && (v[1] == 1 || v[1] == 2) && usable(a) {
					addrs = append(addrs, a)
				}
			}
		case 127: // IEEE 802.1 port VLAN ID
			if n >= 6 && v[0] == 0x00 && v[1] == 0x80 && v[2] == 0xc2 && v[3] == 1 {
				d["vlan"] = int(binary.BigEndian.Uint16(v[4:]))
			}
		}
		b = b[2+n:]
	}
	if len(d) == 0 && len(addrs) == 0 {
		return nil
	}
	if len(addrs) == 0 {
		return []Sighting{{Protocol: "lldp", Details: d}}
	}
	out := make([]Sighting, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, Sighting{Protocol: "lldp", Address: a, Role: "management", Details: d})
	}
	return out
}

func parseCDP(b []byte) []Sighting {
	// LLC/SNAP header: AA AA 03, Cisco OUI 00000c, protocol 0x2000.
	if len(b) < 12 || b[0] != 0xaa || b[1] != 0xaa || b[2] != 3 || b[3] != 0 || b[4] != 0 || b[5] != 0x0c || binary.BigEndian.Uint16(b[6:]) != 0x2000 {
		return nil
	}
	d := map[string]any{}
	var addrs []netip.Addr
	for t := b[12:]; len(t) >= 4; {
		typ, n := binary.BigEndian.Uint16(t), int(binary.BigEndian.Uint16(t[2:]))
		if n < 4 || n > len(t) {
			break
		}
		v := t[4:n]
		switch typ {
		case 0x01:
			d["device_id"] = printable(v, false)
		case 0x03:
			d["port_id"] = printable(v, false)
		case 0x0a:
			if len(v) == 2 {
				d["vlan"] = int(binary.BigEndian.Uint16(v))
			}
		case 0x02, 0x16:
			addrs = append(addrs, cdpAddresses(v)...)
		}
		t = t[n:]
	}
	if len(d) == 0 && len(addrs) == 0 {
		return nil
	}
	if len(addrs) == 0 {
		return []Sighting{{Protocol: "cdp", Details: d}}
	}
	out := make([]Sighting, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, Sighting{Protocol: "cdp", Address: a, Role: "management", Details: d})
	}
	return out
}

func cdpAddresses(v []byte) []netip.Addr {
	if len(v) < 4 {
		return nil
	}
	count := int(binary.BigEndian.Uint32(v))
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for v = v[4:]; count > 0 && len(v) >= 2; count-- {
		plen := int(v[1])
		if len(v) < 2+plen+2 {
			break
		}
		alen := int(binary.BigEndian.Uint16(v[2+plen:]))
		if len(v) < 4+plen+alen {
			break
		}
		if a, ok := netip.AddrFromSlice(v[4+plen : 4+plen+alen]); ok && usable(a) && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
		v = v[4+plen+alen:]
	}
	return out
}

// printable returns v as text, or as a MAC-style string when mac is set or v
// is not printable ASCII. Values are bounded to 128 bytes.
func printable(v []byte, mac bool) string {
	if len(v) > 128 {
		v = v[:128]
	}
	if !mac {
		ok := true
		for _, c := range v {
			if c < 0x20 || c > 0x7e {
				ok = false
				break
			}
		}
		if ok {
			return string(v)
		}
	}
	return hwaddr(v)
}
