package platform

import (
	"reflect"
	"testing"
)

func TestParseResolvectlLinks(t *testing.T) {
	got := parseResolvectlLinks([]byte("Global: 10.0.0.1\nLink 2 (eth0): 10.1.0.53 fd00::53\nLink 3 (wg0):\nnoise\n"))
	want := map[string][]string{"global": {"10.0.0.1"}, "eth0": {"10.1.0.53", "fd00::53"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}
