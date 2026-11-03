package instance

import (
	"testing"

	"golang.org/x/mod/semver"
)

func TestIsUnsupportedVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "empty is supported", version: "", want: false},
		{name: "invalid is supported", version: "not-a-version", want: false},
		{name: "previous major", version: "2.19.2", want: false},
		{name: "minimum", version: "v3.0.0", want: false},
		{name: "just below cutoff", version: "3.99.99", want: false},
		{name: "prerelease below cutoff", version: "v3.99.0-beta.1", want: false},
		{name: "exact cutoff", version: "4.0.0", want: true},
		{name: "exact cutoff with v prefix", version: "v4.0.0", want: true},
		{name: "prerelease of cutoff minor", version: "v4.0.0-beta.1", want: true},
		{name: "next build of cutoff", version: "v4.0.0-next", want: true},
		{name: "patch above cutoff", version: "4.0.4", want: true},
		{name: "minor above cutoff", version: "4.1.0", want: true},
		{name: "far above cutoff", version: "v5.2.1", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isUnsupportedVersion(tt.version); got != tt.want {
				t.Errorf("isUnsupportedVersion(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestIsBelowMinimumVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "empty is supported", version: "", want: false},
		{name: "invalid is supported", version: "not-a-version", want: false},
		{name: "well below minimum", version: "2.8.0", want: true},
		{name: "previous major", version: "v2.19.2", want: true},
		{name: "prerelease below minimum", version: "v2.19.0-beta.1", want: true},
		{name: "next build reporting the previous major", version: "v2.19.2-next", want: false},
		{name: "next build without v prefix", version: "2.19.2-next", want: false},
		{name: "exact minimum", version: "3.0.0", want: false},
		{name: "exact minimum with v prefix", version: "v3.0.0", want: false},
		{name: "prerelease of minimum minor", version: "v3.0.0-beta.1", want: false},
		{name: "patch above minimum", version: "3.0.3", want: false},
		{name: "minor above minimum", version: "v3.1.0", want: false},
		{name: "next major", version: "4.0.0", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBelowMinimumVersion(tt.version); got != tt.want {
				t.Errorf("isBelowMinimumVersion(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

// The two gates must not both fire on the same version, and must leave a non-empty
// supported range between them.
func TestVersionBoundsAreConsistent(t *testing.T) {
	for _, version := range []string{"2.19.2", "3.0.0", "3.99.99", "4.0.0", "5.0.0"} {
		if isBelowMinimumVersion(version) && isUnsupportedVersion(version) {
			t.Errorf("version %q is both below the minimum and unsupported", version)
		}
	}

	if semver.Compare(minimumSupportedPocketIDVersion, firstUnsupportedPocketIDVersion) >= 0 {
		t.Errorf("minimum %q is not below first unsupported %q",
			minimumSupportedPocketIDVersion, firstUnsupportedPocketIDVersion)
	}

	if semver.Compare(latestTestedPocketIDVersion, minimumSupportedPocketIDVersion) < 0 {
		t.Errorf("latest tested %q is below the minimum supported %q",
			latestTestedPocketIDVersion, minimumSupportedPocketIDVersion)
	}
}
