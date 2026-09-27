package lanscan

import (
	"bytes"
	"encoding"
	"encoding/json"
	"reflect"
	"strconv"
	"time"

	"lanscan/internal/model"
)

// snapshot returns an independent copy of e with the shape a JSON round trip
// would produce: Details holds only map[string]any, []any, string, bool,
// json.Number and nil. Common values are converted directly; values with
// custom JSON behaviour or struct layout fall back to encoding/json.
func snapshot(e model.Event) (Event, error) {
	out := e
	var err error
	if out.RecordedAt, err = roundTripTime(e.RecordedAt); err != nil {
		return out, err
	}
	if e.ObservedAt != nil {
		t, err := roundTripTime(*e.ObservedAt)
		if err != nil {
			return out, err
		}
		out.ObservedAt = &t
	}
	if e.Prefix != nil {
		p := *e.Prefix
		out.Prefix = &p
	}
	out.EvidenceIDs = nil
	if len(e.EvidenceIDs) > 0 {
		out.EvidenceIDs = append([]string(nil), e.EvidenceIDs...)
	}
	out.Details = nil
	if len(e.Details) > 0 {
		out.Details = make(map[string]any, len(e.Details))
		for k, v := range e.Details {
			if out.Details[k], err = normalize(v); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

func roundTripTime(t time.Time) (time.Time, error) {
	b, err := t.MarshalText()
	if err != nil {
		return t, err
	}
	var u time.Time
	err = u.UnmarshalText(b)
	return u, err
}

var (
	jsonMarshaler = reflect.TypeFor[json.Marshaler]()
	textMarshaler = reflect.TypeFor[encoding.TextMarshaler]()
)

func normalize(v any) (any, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case string, bool, json.Number:
		return x, nil
	case int:
		return json.Number(strconv.FormatInt(int64(x), 10)), nil
	case int64:
		return json.Number(strconv.FormatInt(x, 10)), nil
	case uint64:
		return json.Number(strconv.FormatUint(x, 10)), nil
	case map[string]any:
		if x == nil {
			return nil, nil
		}
		m := make(map[string]any, len(x))
		for k, item := range x {
			n, err := normalize(item)
			if err != nil {
				return nil, err
			}
			m[k] = n
		}
		return m, nil
	case []any:
		if x == nil {
			return nil, nil
		}
		s := make([]any, len(x))
		for i, item := range x {
			n, err := normalize(item)
			if err != nil {
				return nil, err
			}
			s[i] = n
		}
		return s, nil
	case []string:
		if x == nil {
			return nil, nil
		}
		s := make([]any, len(x))
		for i, item := range x {
			s[i] = item
		}
		return s, nil
	}
	return normalizeValue(reflect.ValueOf(v))
}

func normalizeValue(rv reflect.Value) (any, error) {
	t := rv.Type()
	if t.Implements(jsonMarshaler) || t.Implements(textMarshaler) {
		return viaJSON(rv.Interface())
	}
	// encoding/json uses pointer-receiver marshalers only on addressable values.
	if pt := reflect.PointerTo(t); rv.CanAddr() && (pt.Implements(jsonMarshaler) || pt.Implements(textMarshaler)) {
		return viaJSON(rv.Addr().Interface())
	}
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil, nil
		}
		return normalizeValue(rv.Elem())
	case reflect.String:
		return rv.String(), nil
	case reflect.Bool:
		return rv.Bool(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return json.Number(strconv.FormatInt(rv.Int(), 10)), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return json.Number(strconv.FormatUint(rv.Uint(), 10)), nil
	case reflect.Map:
		if t.Key().Kind() != reflect.String || t.Key().Implements(textMarshaler) {
			break
		}
		if rv.IsNil() {
			return nil, nil
		}
		m := make(map[string]any, rv.Len())
		for it := rv.MapRange(); it.Next(); {
			n, err := normalizeValue(it.Value())
			if err != nil {
				return nil, err
			}
			m[it.Key().String()] = n
		}
		return m, nil
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			break // base64
		}
		if rv.IsNil() {
			return nil, nil
		}
		fallthrough
	case reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			break
		}
		s := make([]any, rv.Len())
		for i := range s {
			n, err := normalizeValue(rv.Index(i))
			if err != nil {
				return nil, err
			}
			s[i] = n
		}
		return s, nil
	}
	// Floats (JSON-specific formatting), structs (tags) and anything unusual.
	return viaJSON(rv.Interface())
}

func viaJSON(v any) (any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	err = decoder.Decode(&out)
	return out, err
}
