//go:build e2e
// +build e2e

package e2e

import (
	"encoding/json"
	"testing"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TestFieldString pins the jsonpath subset the wait helpers rely on. Every shape here is
// one a spec actually passes; a regression would otherwise surface as a two-minute
// Eventually timeout with no indication of why.
func TestFieldString(t *testing.T) {
	// fieldString fails loudly on an unsupported path, which needs a Gomega handler.
	RegisterTestingT(t)
	const doc = `{
	  "metadata": {
	    "generation": 3,
	    "annotations": {"pocketid.internal/hash": "abc"}
	  },
	  "spec": {"containers": [{"image": "img:1"}]},
	  "status": {
	    "userID": "abc-123",
	    "isAdmin": true,
	    "totalUserCount": 5,
	    "allowedUserGroupIDs": ["g1", "g2"],
	    "managedUserIDs": ["u1", "u2"],
	    "empty": [],
	    "emptyList": [],
	    "callbackUrls": ["https://a/cb", "https://b/cb"],
	    "permissions": [
	      {"key": "read:orders",  "id": "perm-r"},
	      {"key": "write:orders", "id": "perm-w"}
	    ],
	    "conditions": [{"type": "Ready", "status": "True", "observedGeneration": 3}]
	  }
	}`
	var raw map[string]any
	if err := json.Unmarshal([]byte(doc), &raw); err != nil {
		t.Fatal(err)
	}
	obj := &unstructured.Unstructured{Object: raw}

	for _, tc := range []struct{ path, want string }{
		{".status.managedUserIDs[*]", "u1 u2"},
		{".status.empty[*]", ""},
		{".status.emptyList", ""},
		{".status.callbackUrls", `["https://a/cb","https://b/cb"]`},
		{`.metadata.annotations.pocketid\.internal/hash`, "abc"},
		{".spec.containers[0].image", "img:1"},
		{".status.userID", "abc-123"},
		{".status.isAdmin", "true"},
		{".status.totalUserCount", "5"},
		{".metadata.generation", "3"},
		{".status.allowedUserGroupIDs[0]", "g1"},
		{".status.allowedUserGroupIDs[1]", "g2"},
		{".status.permissions[?(@.key=='read:orders')].id", "perm-r"},
		{".status.permissions[?(@.key=='write:orders')].id", "perm-w"},
		{".status.permissions[?(@.key=='nope')].id", ""},
		{".status.allowedUserGroupIDs[9]", ""},
		{".status.missing", ""},
		{".status.missing.deeper", ""},
	} {
		if got := fieldString(obj, tc.path); got != tc.want {
			t.Errorf("fieldString(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestConditionField(t *testing.T) {
	RegisterTestingT(t)
	obj := &unstructured.Unstructured{Object: map[string]any{
		"status": map[string]any{"conditions": []any{
			map[string]any{"type": "Ready", "status": "True", "observedGeneration": int64(3)},
		}},
	}}
	for _, tc := range []struct{ condType, field, want string }{
		{"Ready", "status", "True"},
		{"Ready", "observedGeneration", "3"},
		{"Ready", "reason", ""},
		{"Missing", "status", ""},
	} {
		if got := conditionField(obj, tc.condType, tc.field); got != tc.want {
			t.Errorf("conditionField(%q,%q) = %q, want %q", tc.condType, tc.field, got, tc.want)
		}
	}
}
