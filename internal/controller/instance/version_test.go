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
		{name: "well below cutoff", version: "2.8.0", want: false},
		{name: "with v prefix below cutoff", version: "v2.10.0", want: false},
		{name: "previously blocked minor is supported again", version: "2.14.0", want: false},
		{name: "just below cutoff", version: "2.99.99", want: false},
		{name: "prerelease below cutoff", version: "v2.99.0-beta.1", want: false},
		{name: "exact cutoff", version: "3.0.0", want: true},
		{name: "exact cutoff with v prefix", version: "v3.0.0", want: true},
		{name: "prerelease of cutoff minor", version: "v3.0.0-beta.1", want: true},
		{name: "patch above cutoff", version: "3.0.4", want: true},
		{name: "minor above cutoff", version: "3.1.0", want: true},
		{name: "far above cutoff", version: "v4.2.1", want: true},
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
		{name: "with v prefix below minimum", version: "v2.10.0", want: true},
		{name: "just below minimum", version: "2.13.0", want: true},
		{name: "patch below minimum", version: "v2.13.7", want: true},
		{name: "prerelease below minimum", version: "v2.13.0-beta.1", want: true},
		{name: "exact minimum", version: "2.14.0", want: false},
		{name: "exact minimum with v prefix", version: "v2.14.0", want: false},
		{name: "prerelease of minimum minor", version: "v2.14.0-beta.1", want: false},
		{name: "patch above minimum", version: "2.14.3", want: false},
		{name: "minor above minimum", version: "v2.15.0", want: false},
		{name: "next major", version: "3.0.0", want: false},
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
	for _, version := range []string{"2.13.0", "2.14.0", "2.99.99", "3.0.0", "4.0.0"} {
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
