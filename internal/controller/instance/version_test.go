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

import "testing"

func TestPocketIDVersionStatus(t *testing.T) {
	tests := []struct {
		name        string
		image       string
		wantVersion string
		wantNewer   bool
	}{
		{
			name:        "current tested version with distroless suffix",
			image:       "ghcr.io/pocket-id/pocket-id:v2.2.0-distroless@sha256:ad2d21a7b31d6b4f1d999caec794a5b5edeb97fc40801947158d62befd4203e3",
			wantVersion: "v2.2.0",
			wantNewer:   false,
		},
		{
			name:        "current tested version plain",
			image:       "ghcr.io/pocket-id/pocket-id:v2.2.0",
			wantVersion: "v2.2.0",
			wantNewer:   false,
		},
		{
			name:        "older version",
			image:       "ghcr.io/pocket-id/pocket-id:v2.1.0-distroless",
			wantVersion: "v2.1.0",
			wantNewer:   false,
		},
		{
			name:        "newer version triggers warning",
			image:       "ghcr.io/pocket-id/pocket-id:v2.3.0-distroless",
			wantVersion: "v2.3.0",
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
