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

import "encoding/json"

// UnmarshalJSON implements custom unmarshaling for SensitiveValue.
// It accepts either a plain JSON string (interpreted as the Value field)
// or a JSON object with "value" and/or "valueFrom" fields.
func (sv *SensitiveValue) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as a plain string first
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		sv.Value = s
		sv.ValueFrom = nil
		return nil
	}

	// Otherwise unmarshal as the struct (use an alias to avoid infinite recursion)
	type sensitiveValueAlias SensitiveValue
	var alias sensitiveValueAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*sv = SensitiveValue(alias)
	return nil
}
