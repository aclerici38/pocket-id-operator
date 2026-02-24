/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package instance

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/mod/semver"
)

// minorBump returns a version string with the minor component incremented by delta.
// e.g. minorBump("v2.2.0", 1) -> "v2.3.0", minorBump("v2.2.0", -1) -> "v2.1.0"
func minorBump(v string, delta int) string {
	parts := strings.Split(strings.TrimPrefix(semver.Canonical(v), "v"), ".")
	minor, _ := strconv.Atoi(parts[1])
	return fmt.Sprintf("v%s.%d.0", parts[0], minor+delta)
}

func TestPocketIDVersionStatus(t *testing.T) {
	current := latestTestedPocketIDVersion
	older := minorBump(current, -1)
	newer := minorBump(current, 1)

	tests := []struct {
		name        string
		image       string
		wantVersion string
		wantNewer   bool
	}{
		{
			name:        "current tested version with distroless suffix",
			image:       "ghcr.io/pocket-id/pocket-id:" + current + "-distroless@sha256:abc123",
			wantVersion: current,
			wantNewer:   false,
		},
		{
			name:        "current tested version plain",
			image:       "ghcr.io/pocket-id/pocket-id:" + current,
			wantVersion: current,
			wantNewer:   false,
		},
		{
			name:        "older version",
			image:       "ghcr.io/pocket-id/pocket-id:" + older + "-distroless",
			wantVersion: older,
			wantNewer:   false,
		},
		{
			name:        "newer version triggers warning",
			image:       "ghcr.io/pocket-id/pocket-id:" + newer + "-distroless",
			wantVersion: newer,
			wantNewer:   true,
		},
		{
			name:        "latest tag is unparseable",
			image:       "ghcr.io/pocket-id/pocket-id:latest",
			wantVersion: "",
			wantNewer:   false,
		},
		{
			name:        "arbitrary tag is unparseable",
			image:       "ghcr.io/pocket-id/pocket-id:main",
			wantVersion: "",
			wantNewer:   false,
		},
		{
			name:        "no tag is unparseable",
			image:       "ghcr.io/pocket-id/pocket-id",
			wantVersion: "",
			wantNewer:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVersion, gotNewer := pocketIDVersionStatus(tt.image)
			if gotVersion != tt.wantVersion {
				t.Errorf("version: got %q, want %q", gotVersion, tt.wantVersion)
			}
			if gotNewer != tt.wantNewer {
				t.Errorf("newer: got %v, want %v", gotNewer, tt.wantNewer)
			}
		})
	}
}
