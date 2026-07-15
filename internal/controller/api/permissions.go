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

package api

import (
	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// buildPermissionInputs converts the CR spec permissions into API permission inputs.
func buildPermissionInputs(permissions []pocketidinternalv1alpha1.APIPermission) []pocketid.APIPermissionInput {
	inputs := make([]pocketid.APIPermissionInput, 0, len(permissions))
	for _, p := range permissions {
		inputs = append(inputs, pocketid.APIPermissionInput{
			Key:         p.Key,
			Name:        p.Name,
			Description: p.Description,
		})
	}
	return inputs
}

// permissionsEqual reports whether the desired inputs match the current permissions,
// comparing key, name, and description regardless of order.
func permissionsEqual(desired []pocketid.APIPermissionInput, current []pocketid.APIPermission) bool {
	if len(desired) != len(current) {
		return false
	}
	currentByKey := make(map[string]pocketid.APIPermission, len(current))
	for _, p := range current {
		currentByKey[p.Key] = p
	}
	for _, want := range desired {
		got, ok := currentByKey[want.Key]
		if !ok || got.Name != want.Name || got.Description != want.Description {
			return false
		}
	}
	return true
}

// observedPermissions converts Pocket-ID permissions into the CR status representation.
func observedPermissions(permissions []pocketid.APIPermission) []pocketidinternalv1alpha1.ObservedAPIPermission {
	if len(permissions) == 0 {
		return nil
	}
	observed := make([]pocketidinternalv1alpha1.ObservedAPIPermission, 0, len(permissions))
	for _, p := range permissions {
		observed = append(observed, pocketidinternalv1alpha1.ObservedAPIPermission{
			ID:   p.ID,
			Key:  p.Key,
			Name: p.Name,
		})
	}
	return observed
}
