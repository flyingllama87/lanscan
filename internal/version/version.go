// Package version identifies this build of lanscan.
package version

import (
	"runtime/debug"
	"strings"
)

// Base is the release this source tree becomes. Bump it with each release,
// before tagging v<Base>.
const Base = "0.2.1"

// injected is set by release builds with
// -ldflags '-X lanscan/internal/version.injected=VERSION'.
var injected string

// String returns the injected version, the module version of a tagged
// `go install`, or Base-dev plus the revision Go embedded at build time, such
// as 0.1.0-dev+b9b168ad113b.dirty.
func String() string {
	if injected != "" {
		return injected
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return Base + "-dev"
	}
	// Only a clean release tag counts; untagged builds get pseudo-versions.
	if v := info.Main.Version; strings.HasPrefix(v, "v") && !strings.ContainsAny(v, "-+") {
		return v[1:]
	}
	return fromSettings(info.Settings)
}

func fromSettings(settings []debug.BuildSetting) string {
	var revision string
	var modified bool
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	v := Base + "-dev"
	if revision != "" {
		v += "+" + revision[:min(12, len(revision))]
		if modified {
			v += ".dirty"
		}
	}
	return v
}
