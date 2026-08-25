package instance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/semver"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

// imageVersion extracts the tag from a pinned image reference, dropping any digest.
func imageVersion(t *testing.T, image string) string {
	t.Helper()
	ref, _, _ := strings.Cut(image, "@")
	idx := strings.LastIndex(ref, ":")
	if idx < 0 {
		t.Fatalf("image %q carries no tag", image)
	}
	return ref[idx+1:]
}

// An instance that never set spec.image runs whatever this operator release ships.
// This is the whole point of resolving the default in the controller: it is re-evaluated
// on every reconcile, so upgrading the operator moves an unpinned instance forward.
func TestResolveImage_DefaultsWhenUnset(t *testing.T) {
	inst := minimalInstance()

	if got := resolveImage(inst); got != DefaultPocketIDImage {
		t.Errorf("resolveImage on an unpinned instance = %q, want %q", got, DefaultPocketIDImage)
	}
}

// An explicit pin is still honoured verbatim; the fallback must never override it.
func TestResolveImage_ExplicitPinWins(t *testing.T) {
	const pinned = "ghcr.io/pocket-id/pocket-id:v2.14.0-distroless"

	inst := minimalInstance()
	inst.Spec.Image = pinned

	if got := resolveImage(inst); got != pinned {
		t.Errorf("resolveImage on a pinned instance = %q, want %q", got, pinned)
	}
}

// The default has to reach the container, not just resolveImage.
func TestBuildPodTemplate_DefaultsImageWhenUnset(t *testing.T) {
	inst := minimalInstance()

	pt := (&Reconciler{}).buildPodTemplate(inst, "")

	if got := pt.Spec.Containers[0].Image; got != DefaultPocketIDImage {
		t.Errorf("container image = %q, want the operator default %q", got, DefaultPocketIDImage)
	}
}

// DefaultPocketIDImage and latestTestedPocketIDVersion are bumped by two different
// Renovate managers (the image regex and the `// renovate:` comment). Nothing else
// forces them to move together, so an upgrade PR that lands only one would silently
// ship a default the operator has not been tested against.
func TestDefaultPocketIDImage_TracksLatestTestedVersion(t *testing.T) {
	tag := imageVersion(t, DefaultPocketIDImage)

	if tag != latestTestedPocketIDVersion && !strings.HasPrefix(tag, latestTestedPocketIDVersion+"-") {
		t.Errorf("default image tag %q does not match latestTestedPocketIDVersion %q; bump both together",
			tag, latestTestedPocketIDVersion)
	}
}

// A default outside the supported range would halt the operator on the first reconcile
// of any instance that did not pin an image, which is exactly the failure this default
// exists to prevent.
func TestDefaultPocketIDImage_WithinSupportedRange(t *testing.T) {
	tag := imageVersion(t, DefaultPocketIDImage)

	if !semver.IsValid(tag) {
		t.Fatalf("default image tag %q is not a valid semver version", tag)
	}
	if isBelowMinimumVersion(tag) {
		t.Errorf("default image %q is below minimumSupportedPocketIDVersion %q; unpinned instances would crash loop",
			DefaultPocketIDImage, minimumSupportedPocketIDVersion)
	}
	if isUnsupportedVersion(tag) {
		t.Errorf("default image %q is at or above firstUnsupportedPocketIDVersion %q; unpinned instances would crash loop",
			DefaultPocketIDImage, firstUnsupportedPocketIDVersion)
	}
}

// The regression guard for the bug this default replaced. A `+kubebuilder:default` on
// spec.image makes the API server stamp the value into the stored object on first write
// and never revisit it, so instances stay on the image of whichever operator created
// them — invisibly, until a later operator's version floor halts on them. The property
// that matters is in the generated CRD, not in the Go marker, so assert on the CRD.
func TestCRD_DoesNotDefaultImage(t *testing.T) {
	path := filepath.Join("..", "..", "..", "config", "crd", "bases", "pocketid.internal_pocketidinstances.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read CRD: %v", err)
	}

	var crd struct {
		Spec struct {
			Versions []struct {
				Name   string `json:"name"`
				Schema struct {
					OpenAPIV3Schema struct {
						Properties struct {
							Spec struct {
								Properties map[string]map[string]any `json:"properties"`
							} `json:"spec"`
						} `json:"properties"`
					} `json:"openAPIV3Schema"`
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}
	if err := k8syaml.Unmarshal(data, &crd); err != nil {
		t.Fatalf("parse CRD: %v", err)
	}
	if len(crd.Spec.Versions) == 0 {
		t.Fatal("CRD declares no versions; the parse above is wrong")
	}

	for _, version := range crd.Spec.Versions {
		image, ok := version.Schema.OpenAPIV3Schema.Properties.Spec.Properties["image"]
		if !ok {
			t.Fatalf("version %s: spec.image is missing from the CRD schema", version.Name)
		}
		if def, ok := image["default"]; ok {
			t.Errorf("version %s: spec.image declares a schema default (%v); the API server would stamp it into every instance and never re-evaluate it. Resolve the default in the controller instead (see DefaultPocketIDImage).",
				version.Name, def)
		}
	}
}
