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
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

const (
	// latestTestedPocketIDVersion is the most recent pocket-id upstream version tested.
	// renovate: datasource=docker depName=ghcr.io/pocket-id/pocket-id
	latestTestedPocketIDVersion = "v2.3.0"
)

var semverTagRe = regexp.MustCompile(`^v\d+\.\d+\.\d+`)

// pocketIDVersionStatus extracts the semver tag from an image string and reports
// whether it is newer than latestTestedPocketIDVersion.
// Returns the extracted version string (empty if unparseable) and whether it is newer.
func pocketIDVersionStatus(image string) (vStr string, newer bool) {
	tag := image
	if i := strings.Index(tag, "@"); i != -1 {
		tag = tag[:i]
	}
	if i := strings.LastIndex(tag, ":"); i != -1 {
		tag = tag[i+1:]
	} else {
		return "", false
	}

	vStr = semverTagRe.FindString(tag)
	if vStr == "" || !semver.IsValid(vStr) {
		return "", false
	}

	return vStr, semver.Compare(vStr, latestTestedPocketIDVersion) > 0
}
