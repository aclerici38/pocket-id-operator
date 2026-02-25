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

package v1alpha1

import (
	"encoding/json"
	"testing"
)

func TestSensitiveValue_UnmarshalJSON_InlineString(t *testing.T) {
	var sv SensitiveValue
	if err := json.Unmarshal([]byte(`"us-east-1"`), &sv); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sv.Value != "us-east-1" {
		t.Errorf("Value: got %q, want %q", sv.Value, "us-east-1")
	}
	if sv.ValueFrom != nil {
		t.Error("expected ValueFrom to be nil for inline string")
	}
}

func TestSensitiveValue_UnmarshalJSON_ObjectValue(t *testing.T) {
	var sv SensitiveValue
	if err := json.Unmarshal([]byte(`{"value":"us-east-1"}`), &sv); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sv.Value != "us-east-1" {
		t.Errorf("Value: got %q, want %q", sv.Value, "us-east-1")
	}
	if sv.ValueFrom != nil {
		t.Error("expected ValueFrom to be nil for object with value")
	}
}

func TestSensitiveValue_UnmarshalJSON_ObjectValueFrom(t *testing.T) {
	data := `{"valueFrom":{"secretKeyRef":{"name":"my-secret","key":"region"}}}`
	var sv SensitiveValue
	if err := json.Unmarshal([]byte(data), &sv); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sv.Value != "" {
		t.Errorf("expected empty Value, got %q", sv.Value)
	}
	if sv.ValueFrom == nil || sv.ValueFrom.SecretKeyRef == nil {
		t.Fatal("expected secretKeyRef to be set")
	}
	if sv.ValueFrom.SecretKeyRef.Name != "my-secret" {
		t.Errorf("secret name: got %q, want %q", sv.ValueFrom.SecretKeyRef.Name, "my-secret")
	}
	if sv.ValueFrom.SecretKeyRef.Key != "region" {
		t.Errorf("secret key: got %q, want %q", sv.ValueFrom.SecretKeyRef.Key, "region")
	}
}

func TestSensitiveValue_UnmarshalJSON_EmptyString(t *testing.T) {
	var sv SensitiveValue
	if err := json.Unmarshal([]byte(`""`), &sv); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sv.Value != "" {
		t.Errorf("Value: got %q, want empty", sv.Value)
	}
}

func TestSensitiveValue_MarshalJSON_RoundTrip(t *testing.T) {
	original := SensitiveValue{Value: "test-value"}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var restored SensitiveValue
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if restored.Value != original.Value {
		t.Errorf("round-trip: got %q, want %q", restored.Value, original.Value)
	}
}
