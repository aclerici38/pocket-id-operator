package instance

import "testing"

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
		{name: "just below cutoff", version: "2.99.99", want: false},
		{name: "exact cutoff", version: "3.0.0", want: true},
		{name: "exact cutoff with v prefix", version: "v3.0.0", want: true},
		{name: "above cutoff", version: "3.1.0", want: true},
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
