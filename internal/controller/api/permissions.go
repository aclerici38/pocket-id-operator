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
	"cmp"
	"slices"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// buildPermissionInputs converts the CR spec permissions into the full set Pocket-ID replaces
// the API's permissions with. It is never nil, so an empty spec clears them.
func buildPermissionInputs(permissions []pocketidinternalv1alpha1.APIPermission) []pid.APIPermissionInputDto {
	inputs := make([]pid.APIPermissionInputDto, 0, len(permissions))
	for _, p := range permissions {
		inputs = append(inputs, pid.APIPermissionInputDto{
			Key:         p.Key,
			Name:        p.Name,
			Description: pocketid.NullIfEmpty(p.Description),
		})
	}
	return inputs
}

// observedPermissions converts Pocket-ID permissions into the CR status representation, sorted
// by key since Pocket-ID returns them unordered.
func observedPermissions(permissions []pid.APIPermissionResponseDto) []pocketidinternalv1alpha1.ObservedAPIPermission {
	if len(permissions) == 0 {
		return nil
	}
	observed := make([]pocketidinternalv1alpha1.ObservedAPIPermission, 0, len(permissions))
	for _, p := range permissions {
		observed = append(observed, pocketidinternalv1alpha1.ObservedAPIPermission{
			ID:         p.ID,
			Key:        p.Key,
			Name:       p.Name,
			CIMDAccess: p.AllowedForCIMDClients,
		})
	}
	slices.SortFunc(observed, func(a, b pocketidinternalv1alpha1.ObservedAPIPermission) int { return cmp.Compare(a.Key, b.Key) })
	return observed
}

// cimdAccess resolves the API's CIMD access from spec: whether it is enabled and the IDs of the
// permissions it covers. Access defaults to on when any permission is marked, so the API-level
// field is only needed to grant access with no permissions or to revoke it. Keys resolve
// against the API's live permissions, since a permission created in the same edit has no ID
// until then. The IDs are sent even while access is off, so turning it back on needs only spec.
func cimdAccess(api *pocketidinternalv1alpha1.PocketIDAPI, current pid.APIResponseDto) (enabled bool, permissionIDs []string) {
	wanted := make(map[string]bool, len(api.Spec.Permissions))
	for _, p := range api.Spec.Permissions {
		if p.CIMDAccess {
			wanted[p.Key] = true
		}
	}

	enabled = len(wanted) > 0
	if api.Spec.CIMDAccess != nil {
		enabled = *api.Spec.CIMDAccess
	}

	permissionIDs = []string{}
	for _, p := range current.Permissions {
		if wanted[p.Key] {
			permissionIDs = append(permissionIDs, p.ID)
		}
	}
	return enabled, permissionIDs
}
