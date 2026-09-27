package probe

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// TestFlowHoldsChecksumConstant checks the Paris invariant: every probe of a
// trace carries the same identifier and checksum while sequence numbers and
// payloads differ, for IPv4 and for IPv6 (whose checksum covers a pseudo-header).
func TestFlowHoldsChecksumConstant(t *testing.T) {
	psh := icmp.IPv6PseudoHeader(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"))
	for trial := range 50 {
		flow, err := NewFlow()
		if err != nil {
			t.Fatal(err)
		}
		if trial == 0 {
			flow.SeqBase = 0xfff0 // sequence numbers wrap within the trace
		}
		for _, family := range []struct {
			typ icmp.Type
			psh []byte
		}{{ipv4.ICMPTypeEcho, nil}, {ipv6.ICMPTypeEchoRequest, psh}} {
			checksums, seqs := map[uint16]bool{}, map[uint16]bool{}
			for hop := 1; hop <= 64; hop++ {
				seq := flow.seq(hop)
				m := icmp.Message{Type: family.typ, Body: &icmp.Echo{ID: int(flow.ID), Seq: int(seq), Data: flow.payload(seq)}}
				b, err := m.Marshal(family.psh)
				if err != nil {
					t.Fatal(err)
				}
				if binary.BigEndian.Uint16(b[4:6]) != flow.ID {
					t.Fatal("identifier changed")
				}
				checksums[binary.BigEndian.Uint16(b[2:4])] = true
				seqs[binary.BigEndian.Uint16(b[6:8])] = true
			}
			if len(checksums) != 1 || len(seqs) != 64 {
				t.Fatalf("%v: %d checksums, %d sequence numbers", family.typ, len(checksums), len(seqs))
			}
		}
	}
}
