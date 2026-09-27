package listen

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
)

func ip4(s string) []byte { a := netip.MustParseAddr(s).As4(); return a[:] }
func ip6(s string) []byte { a := netip.MustParseAddr(s).As16(); return a[:] }

func be16(v int) []byte { return binary.BigEndian.AppendUint16(nil, uint16(v)) }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ipv4 wraps payload in a minimal IPv4 header.
func ipv4(proto byte, src, dst string, payload []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(payload)))
	h[8], h[9] = 1, proto
	copy(h[12:], ip4(src))
	copy(h[16:], ip4(dst))
	return append(h, payload...)
}

func udp(sport, dport int, data []byte) []byte {
	return cat(be16(sport), be16(dport), be16(8+len(data)), be16(0), data)
}

func ipv6(next byte, src, dst string, payload []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(payload)))
	h[6], h[7] = next, 255
	copy(h[8:], ip6(src))
	copy(h[24:], ip6(dst))
	return append(h, payload...)
}

// summary renders sightings compactly for comparison.
func summary(s []Sighting) []string {
	var out []string
	for _, x := range s {
		v := x.Protocol + ":" + x.Role
		if x.Address.IsValid() {
			v += " " + x.Address.String()
		}
		if x.Prefix.IsValid() {
			v += " " + x.Prefix.String() + "/" + x.PrefixBasis
		}
		out = append(out, v)
	}
	return out
}

func check(t *testing.T, name string, got []Sighting, want ...string) {
	t.Helper()
	if g := summary(got); !reflect.DeepEqual(g, want) {
		t.Errorf("%s:\n got %q\nwant %q", name, g, want)
	}
}

func TestParseARP(t *testing.T) {
	mac := []byte{0, 1, 2, 3, 4, 5}
	req := cat(be16(1), be16(0x0800), []byte{6, 4}, be16(1), mac, ip4("10.9.8.7"), make([]byte, 6), ip4("10.9.8.1"))
	got := Parse(ProtoARP, req, false)
	check(t, "request", got, "arp:sender 10.9.8.7")
	if got[0].Details["mac"] != "00:01:02:03:04:05" {
		t.Fatal(got[0].Details)
	}
	probe := cat(be16(1), be16(0x0800), []byte{6, 4}, be16(1), mac, ip4("0.0.0.0"), make([]byte, 6), ip4("10.9.8.9"))
	check(t, "RFC 5227 probe", Parse(ProtoARP, probe, false))
	check(t, "truncated", Parse(ProtoARP, req[:27], false))
}

func dhcp(msg byte, yiaddr, giaddr string, options ...[]byte) []byte {
	b := make([]byte, 240)
	b[0] = 2
	copy(b[16:], ip4(yiaddr))
	copy(b[24:], ip4(giaddr))
	binary.BigEndian.PutUint32(b[236:], 0x63825363)
	b = append(b, 53, 1, msg)
	for _, o := range options {
		b = append(b, o...)
	}
	return append(b, 255)
}

func TestParseDHCP(t *testing.T) {
	ack := dhcp(5, "10.20.30.40", "10.20.30.1",
		cat([]byte{1, 4}, ip4("255.255.255.0")),
		cat([]byte{3, 8}, ip4("10.20.30.1"), ip4("10.20.30.2")),
		cat([]byte{6, 4}, ip4("10.0.0.53")),
		cat([]byte{54, 4}, ip4("10.0.0.67")),
		// 10.50.0.0/16 via 10.20.30.1, then a malformed /40.
		cat([]byte{121, 12, 16, 10, 50}, ip4("10.20.30.1"), []byte{40, 1, 2, 3, 4}),
	)
	got := Parse(ProtoIPv4, ipv4(17, "10.0.0.67", "255.255.255.255", udp(67, 68, ack)), false)
	check(t, "ack", got,
		"dhcp:sender 10.0.0.67",
		"dhcp:dhcp_client 10.20.30.40",
		"dhcp:dhcp_relay 10.20.30.1",
		"dhcp:dhcp_server 10.0.0.67",
		"dhcp:gateway 10.20.30.1",
		"dhcp:gateway 10.20.30.2",
		"dhcp:dns_server 10.0.0.53",
		"dhcp: 10.20.30.0/24/dhcp",
		"dhcp: 10.50.0.0/16/dhcp_route",
	)
	if got[1].Details["message"] != "ack" {
		t.Fatal(got[1].Details)
	}
	bad := dhcp(5, "10.20.30.40", "0.0.0.0", cat([]byte{1, 4}, ip4("255.0.255.0")))
	check(t, "non-contiguous mask", Parse(ProtoIPv4, ipv4(17, "0.0.0.0", "255.255.255.255", udp(67, 68, bad)), false), "dhcp:dhcp_client 10.20.30.40")
}

func TestParseRoutingProtocols(t *testing.T) {
	hello := make([]byte, 44)
	hello[0], hello[1] = 2, 1
	copy(hello[4:], ip4("1.1.1.1"))
	copy(hello[24:], ip4("255.255.255.252"))
	check(t, "ospf", Parse(ProtoIPv4, ipv4(89, "10.1.1.2", "224.0.0.5", hello), false),
		"ospf:sender 10.1.1.2", "ospf: 10.1.1.0/30/ospf_hello")

	vrrp := cat([]byte{0x31, 7, 200, 2}, make([]byte, 4), ip4("10.1.2.1"), ip4("10.1.3.1"))
	check(t, "vrrp", Parse(ProtoIPv4, ipv4(112, "10.1.2.2", "224.0.0.18", vrrp), false),
		"vrrp:sender 10.1.2.2", "vrrp:virtual_router 10.1.2.1", "vrrp:virtual_router 10.1.3.1")

	hsrp := make([]byte, 20)
	copy(hsrp[16:], ip4("10.1.4.1"))
	check(t, "hsrp", Parse(ProtoIPv4, ipv4(17, "10.1.4.2", "224.0.0.2", udp(1985, 1985, hsrp)), false),
		"hsrp:sender 10.1.4.2", "hsrp:virtual_router 10.1.4.1")

	entry := func(prefix, mask string, metric int) []byte {
		return cat(be16(2), be16(0), ip4(prefix), ip4(mask), ip4("0.0.0.0"), binary.BigEndian.AppendUint32(nil, uint32(metric)))
	}
	rip := cat([]byte{2, 2, 0, 0}, entry("10.7.0.0", "255.255.0.0", 2), entry("10.8.0.0", "255.255.0.0", 16))
	check(t, "rip", Parse(ProtoIPv4, ipv4(17, "10.1.5.1", "224.0.0.9", udp(520, 520, rip)), false),
		"rip:sender 10.1.5.1", "rip: 10.7.0.0/16/rip")
}

func TestParseServiceDiscoveryAndFragments(t *testing.T) {
	check(t, "mdns", Parse(ProtoIPv4, ipv4(17, "192.168.1.20", "224.0.0.251", udp(5353, 5353, nil)), false), "mdns:sender 192.168.1.20")
	check(t, "ssdp", Parse(ProtoIPv4, ipv4(17, "192.168.1.21", "239.255.255.250", udp(40000, 1900, nil)), false), "ssdp:sender 192.168.1.21")
	frag := ipv4(89, "10.1.1.2", "224.0.0.5", make([]byte, 44))
	frag[7] = 1 // nonzero fragment offset: no transport header
	check(t, "fragment", Parse(ProtoIPv4, frag, false), "ipv4:sender 10.1.1.2")
	check(t, "bad length", Parse(ProtoIPv4, ipv4(17, "10.1.1.2", "224.0.0.5", nil)[:19], false))
}

func TestParseRouterAdvertisement(t *testing.T) {
	pio := func(prefix string, bits byte) []byte {
		return cat([]byte{3, 4, bits, 0xc0}, make([]byte, 12), ip6(prefix))
	}
	route := cat([]byte{24, 2, 48, 0}, make([]byte, 4), ip6("fd00:99::")[:8])
	rdnss := cat([]byte{25, 3, 0, 0}, make([]byte, 4), ip6("fd00:1::53"))
	ra := cat([]byte{134, 0, 0, 0}, make([]byte, 12), pio("fd00:1::", 64), pio("fe80::", 64), route, rdnss)
	got := Parse(ProtoIPv6, ipv6(58, "fe80::1", "ff02::1", ra), false)
	check(t, "ra", got,
		"ndp:sender fe80::1",
		"ndp: fd00:1::/64/router_advertisement",
		"ndp: fd00:99::/48/router_advertisement_route",
		"ndp:dns_server fd00:1::53",
		"ndp:gateway fe80::1",
	)
	if got[1].Details["on_link"] != true {
		t.Fatal(got[1].Details)
	}
	check(t, "no-ipv6", Parse(ProtoIPv6, ipv6(58, "fe80::1", "ff02::1", ra), true))

	dad := cat([]byte{135, 0, 0, 0}, make([]byte, 4), ip6("fd00:1::abcd"))
	check(t, "dad", Parse(ProtoIPv6, ipv6(58, "::", "ff02::1:ffab:cd", dad), false), "ndp:ndp_target fd00:1::abcd")

	// An MLD report behind a hop-by-hop header.
	mld := cat([]byte{58, 0, 5, 2, 0, 0, 1, 0}, []byte{143, 0, 0, 0}, make([]byte, 4))
	check(t, "mld", Parse(ProtoIPv6, ipv6(0, "fe80::2", "ff02::16", mld), false), "mld:sender fe80::2")
}

func tlv(t int, v []byte) []byte { return cat(be16(t<<9|len(v)), v) }

func TestParseLLDP(t *testing.T) {
	frame := cat(
		tlv(1, cat([]byte{4}, []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55})),
		tlv(2, cat([]byte{5}, []byte("Gi1/0/1"))),
		tlv(3, be16(120)),
		tlv(5, []byte("core-sw1")),
		tlv(8, cat([]byte{5, 1}, ip4("10.0.0.2"), []byte{2, 0, 0, 0, 1, 0})),
		tlv(127, cat([]byte{0, 0x80, 0xc2, 1}, be16(30))),
		tlv(0, nil),
	)
	got := Parse(ProtoLLDP, frame, false)
	check(t, "lldp", got, "lldp:management 10.0.0.2")
	d := got[0].Details
	if d["system_name"] != "core-sw1" || d["vlan"] != 30 || d["chassis_id"] != "00:11:22:33:44:55" || d["port_id"] != "Gi1/0/1" {
		t.Fatal(d)
	}
	noAddr := cat(tlv(5, []byte("edge")), tlv(0, nil))
	check(t, "lldp without address", Parse(ProtoLLDP, noAddr, false), "lldp:")
}

func TestParseCDP(t *testing.T) {
	cdpTLV := func(typ int, v []byte) []byte { return cat(be16(typ), be16(4+len(v)), v) }
	addrs := cat(binary.BigEndian.AppendUint32(nil, 2),
		[]byte{1, 1, 0xcc}, be16(4), ip4("10.0.0.3"),
		[]byte{2, 8, 0xaa, 0xaa, 3, 0, 0, 0, 0x86, 0xdd}, be16(16), ip6("fd00::3"))
	frame := cat([]byte{0xaa, 0xaa, 3, 0, 0, 0x0c, 0x20, 0x00}, []byte{2, 180, 0, 0},
		cdpTLV(1, []byte("dist-sw2")), cdpTLV(2, addrs), cdpTLV(0x0a, be16(10)))
	got := Parse(Proto8022, frame, false)
	check(t, "cdp", got, "cdp:management 10.0.0.3", "cdp:management fd00::3")
	if got[0].Details["device_id"] != "dist-sw2" || got[0].Details["vlan"] != 10 {
		t.Fatal(got[0].Details)
	}
	check(t, "cdp no-ipv6", Parse(Proto8022, frame, true), "cdp:management 10.0.0.3")
	check(t, "stp", Parse(Proto8022, []byte{0x42, 0x42, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false))
}

func FuzzParse(f *testing.F) {
	for _, p := range []uint16{ProtoARP, ProtoIPv4, ProtoIPv6, ProtoLLDP, Proto8022} {
		f.Add(p, []byte{})
	}
	f.Add(uint16(ProtoIPv4), ipv4(17, "10.0.0.67", "255.255.255.255", udp(67, 68, dhcp(5, "10.1.1.1", "0.0.0.0", cat([]byte{121, 5, 8, 10}, ip4("10.0.0.1"))))))
	f.Add(uint16(ProtoIPv6), ipv6(58, "fe80::1", "ff02::1", cat([]byte{134, 0, 0, 0}, make([]byte, 12), []byte{24, 1, 128, 0})))
	f.Add(uint16(ProtoLLDP), tlv(8, []byte{9, 1, 1, 2}))
	f.Fuzz(func(t *testing.T, proto uint16, b []byte) {
		for _, noIPv6 := range []bool{false, true} {
			for _, s := range Parse(proto, b, noIPv6) {
				if s.Prefix.IsValid() && s.Prefix != s.Prefix.Masked() {
					t.Fatalf("noncanonical prefix %s", s.Prefix)
				}
				if noIPv6 && (s.Address.Is6() || s.Prefix.Addr().Is6()) {
					t.Fatalf("IPv6 sighting with noIPv6: %v", s)
				}
				if s.Address.IsValid() && !usable(s.Address) {
					t.Fatal(fmt.Sprint("unusable address ", s.Address))
				}
			}
		}
	})
}
