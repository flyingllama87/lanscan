package version

import (
	"regexp"
	"runtime/debug"
	"testing"
)

func TestBaseIsSemver(t *testing.T) {
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(Base) {
		t.Fatalf("Base %q is not MAJOR.MINOR.PATCH", Base)
	}
}

func TestFromSettings(t *testing.T) {
	for _, test := range []struct {
		settings []debug.BuildSetting
		want     string
	}{
		{nil, Base + "-dev"},
		{[]debug.BuildSetting{{Key: "vcs.revision", Value: "b9b168a0123456789"}, {Key: "vcs.modified", Value: "false"}}, Base + "-dev+b9b168a01234"},
		{[]debug.BuildSetting{{Key: "vcs.revision", Value: "abc"}, {Key: "vcs.modified", Value: "true"}}, Base + "-dev+abc.dirty"},
	} {
		if got := fromSettings(test.settings); got != test.want {
			t.Errorf("got %q want %q", got, test.want)
		}
	}
}

func TestInjectedWins(t *testing.T) {
	saved := injected
	t.Cleanup(func() { injected = saved })
	injected = "9.9.9"
	if String() != "9.9.9" {
		t.Fatal(String())
	}
}
