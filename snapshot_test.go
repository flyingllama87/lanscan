package lanscan

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"lanscan/internal/app"
	"lanscan/internal/model"
)

// jsonSnapshot is the reference behaviour snapshot must reproduce.
func jsonSnapshot(e model.Event) (Event, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return Event{}, err
	}
	var out Event
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	err = decoder.Decode(&out)
	return out, err
}

type ptrMarshaler struct{ V int }

func (p *ptrMarshaler) MarshalJSON() ([]byte, error) { return []byte(`"custom"`), nil }

type label string

type tagged struct {
	Name    string        `json:"name"`
	Skip    string        `json:"-"`
	Empty   string        `json:"empty,omitempty"`
	Addr    netip.Addr    `json:"addr"`
	Elapsed time.Duration `json:"elapsed"`
	hidden  int
}

func sampleEvents(t testing.TB) []model.Event {
	t.Helper()
	observed := time.Date(2026, 9, 27, 10, 11, 12, 123456789, time.FixedZone("x", 3600))
	prefix := netip.MustParsePrefix("10.20.0.0/16")
	crafted := model.Event{
		SchemaVersion: 1, EventID: "r:1", RunID: "r", Seq: 1, Type: "observation", RealmID: "realm", VantageID: "v",
		RecordedAt: time.Now().UTC(), ObservedAt: &observed, Prefix: &prefix, EvidenceIDs: []string{},
		Details: map[string]any{
			"int": 7, "int64": int64(-3), "uint32": uint32(9), "uint64": uint64(1 << 63), "float": 0.1, "big": 1e21, "f32": float32(1.1),
			"string": "s", "label": label("l"), "bool": true, "nil": nil, "number": json.Number("4"),
			"strings": []string{"a"}, "nil_strings": []string(nil), "empty_any": []any{},
			"counts": map[string]int{"a": 1}, "int_keys": map[int]string{2: "b"}, "nil_map": map[string]any(nil),
			"bytes": []byte("hi"), "array": [2]uint8{1, 2}, "ints": [3]int{1, 2, 3},
			"struct":     tagged{Name: "n", Skip: "x", Addr: netip.MustParseAddr("fe80::1%eth0"), Elapsed: time.Second, hidden: 1},
			"struct_ptr": &tagged{}, "nil_ptr": (*tagged)(nil), "addr": netip.MustParseAddr("10.0.0.1"), "prefix": prefix,
			"time": observed, "duration": 5 * time.Millisecond,
			"ptr_marshaler_value": ptrMarshaler{1}, "ptr_marshaler": &ptrMarshaler{2}, "ptr_marshaler_slice": []ptrMarshaler{{3}},
			"nested": map[string]any{"list": []any{1, "two", map[string]any{"three": 3.5}}},
		},
	}
	events := []model.Event{crafted, {SchemaVersion: 1, EventID: "r:2", RunID: "r", Seq: 2, Type: "x", RealmID: "realm", VantageID: "v", RecordedAt: time.Now().UTC(), Details: map[string]any{}}}
	cfg := app.DefaultConfig()
	cfg.NoJournal = true
	cfg.Include = []string{"10.0.0.0/8"}
	if _, err := app.Discover(context.Background(), cfg, func(e model.Event) error {
		events = append(events, e)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return events
}

func TestSnapshotMatchesJSONRoundTrip(t *testing.T) {
	for _, e := range sampleEvents(t) {
		want, err := jsonSnapshot(e)
		if err != nil {
			t.Fatal(err)
		}
		got, err := snapshot(e)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			for k := range want.Details {
				if !reflect.DeepEqual(got.Details[k], want.Details[k]) {
					t.Errorf("%s detail %q: got %#v, want %#v", e.Type, k, got.Details[k], want.Details[k])
				}
			}
			got.Details, want.Details = nil, nil
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s: got %#v, want %#v", e.Type, got, want)
			}
		}
	}
}

func TestSnapshotIsIndependent(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	inner := map[string]any{"k": "v"}
	e := model.Event{Prefix: &prefix, EvidenceIDs: []string{"a"}, Details: map[string]any{"inner": inner, "list": []any{"x"}}}
	s, err := snapshot(e)
	if err != nil {
		t.Fatal(err)
	}
	*s.Prefix = netip.MustParsePrefix("192.168.0.0/16")
	s.EvidenceIDs[0] = "changed"
	s.Details["inner"].(map[string]any)["k"] = "changed"
	s.Details["list"].([]any)[0] = "changed"
	if *e.Prefix != prefix || e.EvidenceIDs[0] != "a" || inner["k"] != "v" || e.Details["list"].([]any)[0] != "x" {
		t.Fatal("snapshot shares memory with the engine event")
	}
}

func BenchmarkSnapshot(b *testing.B) {
	events := sampleEvents(b)[2:]
	b.Run("typed", func(b *testing.B) {
		for b.Loop() {
			for _, e := range events {
				if _, err := snapshot(e); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("json", func(b *testing.B) {
		for b.Loop() {
			for _, e := range events {
				if _, err := jsonSnapshot(e); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
}
