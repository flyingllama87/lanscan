package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lanscan/internal/journal"
	"lanscan/internal/listen"
	"lanscan/internal/model"
)

type fakeCapture struct{ frames []listen.Frame }

func (f *fakeCapture) Run(ctx context.Context, _ time.Time, fn func(listen.Frame) error) error {
	for _, fr := range f.frames {
		if err := fn(fr); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeCapture) Close() error { return nil }

func fakeListen(t *testing.T, frames []listen.Frame, err error) {
	saved := listenCapture
	t.Cleanup(func() { listenCapture = saved })
	listenCapture = func(string) (capture, error) {
		if err != nil {
			return nil, err
		}
		return &fakeCapture{frames: frames}, nil
	}
}

// arpFrame is an ARP request from sender.
func arpFrame(sender [4]byte) listen.Frame {
	b := []byte{0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 1}
	b = append(b, sender[:]...)
	b = append(b, make([]byte, 10)...)
	return listen.Frame{Proto: listen.ProtoARP, Interface: "eth0", Data: b}
}

// ripFrame advertises 10.77.0.0/16 from 10.1.5.1.
func ripFrame() listen.Frame {
	rip := []byte{2, 2, 0, 0, 0, 2, 0, 0, 10, 77, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	udp := append([]byte{2, 8, 2, 8, 0, byte(8 + len(rip)), 0, 0}, rip...)
	ip := []byte{0x45, 0, 0, byte(20 + len(udp)), 0, 0, 0, 0, 1, 17, 0, 0, 10, 1, 5, 1, 224, 0, 0, 9}
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
	return listen.Frame{Proto: listen.ProtoIPv4, Interface: "eth0", Data: append(ip, udp...)}
}

func TestListenEvidenceFeedsPlanning(t *testing.T) {
	frames := []listen.Frame{arpFrame([4]byte{10, 66, 0, 9}), arpFrame([4]byte{10, 66, 0, 9}), ripFrame()}
	fakeListen(t, frames, nil)
	var out, stderr bytes.Buffer
	code := Run(context.Background(), []string{"discover", "--format", "jsonl", "--realm", "lab", "--listen", "1s", "--intensity", "2", "--plan", "--include", "10.77.0.0/16"}, &out, &stderr)
	if code != 0 {
		t.Fatalf("%d %s", code, stderr.String())
	}
	var sightings, prefixFindings, arpFindings int
	var status, plan model.Event
	_, err := journal.Replay(bytes.NewReader(out.Bytes()), func(e model.Event) error {
		switch {
		case e.Type == "observation" && e.Source == "listen":
			sightings++
			if e.ActivityBasis != "passive_capture" || e.InterfaceID != "eth0" {
				t.Errorf("%+v", e)
			}
		case e.Type == "finding_upsert" && e.Source == "listen" && e.Prefix != nil && e.Prefix.String() == "10.77.0.0/16" && e.PrefixBasis == "rip":
			prefixFindings++
		case e.Type == "finding_upsert" && e.Source == "listen" && e.Address == "10.66.0.9":
			arpFindings++
		case e.Type == "collector_status" && e.Source == "listen":
			status = e
		case e.Type == "plan":
			plan = e
		case e.Type == "operation_reserved":
			t.Errorf("listen or plan sent traffic: %+v", e)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The repeated ARP is recorded once; RIP gives its sender and one prefix.
	if sightings != 3 || prefixFindings != 1 || arpFindings != 1 || status.Outcome != "complete" {
		t.Fatalf("sightings=%d prefix=%d arp=%d status=%+v", sightings, prefixFindings, arpFindings, status)
	}
	// Intensity 2 samples the heard prefix, which has no host evidence.
	if n, _ := plan.Details["synthetic_samples"].(interface{ String() string }); n == nil || n.String() != "2" {
		t.Fatalf("heard prefix not sampled: %+v", plan.Details)
	}
}

func TestListenUnavailableFailsBeforeCreatingFiles(t *testing.T) {
	fakeListen(t, nil, errors.New("packet capture needs CAP_NET_RAW"))
	dir := t.TempDir()
	path := filepath.Join(dir, "run.jsonl")
	var out, stderr bytes.Buffer
	code := Run(context.Background(), []string{"discover", "--journal", path, "--listen", "1s"}, &out, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "CAP_NET_RAW") {
		t.Fatalf("%d %s", code, stderr.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("journal created: %v", err)
	}
}
