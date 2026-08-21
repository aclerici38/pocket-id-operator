//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"os"
	"sort"
	"testing"

	"sigs.k8s.io/yaml"

	pocketidv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

const instanceCRDPath = "../../config/crd/bases/pocketid.internal_pocketidinstances.yaml"

// TestMaximalInstanceYAMLMatchesCRDSchema guards the maximal instance manifest
// against silent drift. A CRD structural schema prunes unknown fields rather
// than rejecting them, so a stray or misspelled key applies cleanly, leaves that
// section unset, and lets the maximal spec pass while covering nothing.
//
// Two checks are needed because neither catches the other's failure mode:
// decoding into the Go type finds keys that no field claims, but encoding/json
// matches names case-insensitively, so it accepts "bindDn" for "bindDN" — which
// the API server would prune. Walking the generated OpenAPI schema is
// case-sensitive and catches exactly that.
func TestMaximalInstanceYAMLMatchesCRDSchema(t *testing.T) {
	manifest := []byte(maximalInstanceYAML("maximal-env-instance", instanceNS))

	var instance pocketidv1alpha1.PocketIDInstance
	if err := yaml.UnmarshalStrict(manifest, &instance); err != nil {
		t.Fatalf("maximal instance manifest does not decode into PocketIDInstance: %v", err)
	}

	var doc map[string]any
	if err := yaml.Unmarshal(manifest, &doc); err != nil {
		t.Fatalf("maximal instance manifest is not valid YAML: %v", err)
	}
	for _, unknown := range unknownSchemaPaths(t, doc["spec"], loadInstanceSpecSchema(t), "spec") {
		t.Errorf("%s is not in the CRD schema and would be pruned on apply", unknown)
	}

	// Spot-check the sections that exist purely to produce environment
	// variables, so a wholesale deletion cannot go unnoticed.
	for name, set := range map[string]bool{
		"ui":                 instance.Spec.UI != nil,
		"userManagement":     instance.Spec.UserManagement != nil,
		"webauthn":           instance.Spec.WebAuthn != nil,
		"smtp":               instance.Spec.SMTP != nil,
		"emailNotifications": instance.Spec.EmailNotifications != nil,
		"ldap":               instance.Spec.LDAP != nil,
		"ldap.attributeMapping": instance.Spec.LDAP != nil &&
			instance.Spec.LDAP.AttributeMapping != nil,
		"logging": instance.Spec.Logging != nil,
		"tracing": instance.Spec.Tracing != nil,
		"geoip":   instance.Spec.GeoIP != nil,
		"metrics": instance.Spec.Metrics != nil,
	} {
		if !set {
			t.Errorf("maximal instance manifest leaves spec.%s unset", name)
		}
	}
}

// loadInstanceSpecSchema returns the OpenAPI schema controller-gen generated for
// PocketIDInstance's spec, so the check runs against the same definition the API
// server enforces.
func loadInstanceSpecSchema(t *testing.T) map[string]any {
	t.Helper()

	raw, err := os.ReadFile(instanceCRDPath)
	if err != nil {
		t.Fatalf("failed to read the PocketIDInstance CRD: %v", err)
	}

	var crd struct {
		Spec struct {
			Versions []struct {
				Name   string `json:"name"`
				Schema struct {
					OpenAPIV3Schema struct {
						Properties struct {
							Spec map[string]any `json:"spec"`
						} `json:"properties"`
					} `json:"openAPIV3Schema"`
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal(raw, &crd); err != nil {
		t.Fatalf("failed to parse the PocketIDInstance CRD: %v", err)
	}

	for _, version := range crd.Spec.Versions {
		if version.Name == pocketidv1alpha1.GroupVersion.Version {
			return version.Schema.OpenAPIV3Schema.Properties.Spec
		}
	}
	t.Fatalf("the PocketIDInstance CRD has no %s version", pocketidv1alpha1.GroupVersion.Version)
	return nil
}

// unknownSchemaPaths reports every path in value that the schema does not
// declare, matching field names case-sensitively the way the API server does.
// Subtrees the schema leaves open (x-kubernetes-preserve-unknown-fields, or a
// free-form object with no properties) are accepted as-is.
func unknownSchemaPaths(t *testing.T, value any, schema map[string]any, path string) []string {
	t.Helper()

	if schema == nil {
		return nil
	}
	if open, ok := schema["x-kubernetes-preserve-unknown-fields"].(bool); ok && open {
		return nil
	}

	switch typed := value.(type) {
	case map[string]any:
		properties, ok := schema["properties"].(map[string]any)
		if !ok {
			// A free-form object, e.g. a map with additionalProperties.
			return nil
		}
		var unknown []string
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child, declared := properties[key].(map[string]any)
			if !declared {
				unknown = append(unknown, fmt.Sprintf("%s.%s", path, key))
				continue
			}
			unknown = append(unknown, unknownSchemaPaths(t, typed[key], child, path+"."+key)...)
		}
		return unknown
	case []any:
		items, ok := schema["items"].(map[string]any)
		if !ok {
			return nil
		}
		var unknown []string
		for i, element := range typed {
			unknown = append(unknown, unknownSchemaPaths(t, element, items, fmt.Sprintf("%s[%d]", path, i))...)
		}
		return unknown
	default:
		return nil
	}
}
