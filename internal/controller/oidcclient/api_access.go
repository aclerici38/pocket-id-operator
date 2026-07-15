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

package oidcclient

import (
	"context"
	"fmt"
	"sort"

	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/helpers"
	"github.com/aclerici38/pocket-id-operator/internal/metrics"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// ReconcileAPIAccess ensures this client's API access in Pocket-ID matches spec.apiAccess.
// The client is the sole owner of its API access: when spec.apiAccess is set the operator
// keeps it in sync and clears it once emptied. When it was never set, existing access
// configured out-of-band is left untouched.
func (r *Reconciler) ReconcileAPIAccess(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, apiClient *pocketid.Client) error {
	log := logf.FromContext(ctx)

	hasSpec := len(oidcClient.Spec.APIAccess) > 0
	hasManaged := len(oidcClient.Status.ManagedAPIPermissionIDs) > 0
	if !hasSpec && !hasManaged {
		return nil
	}

	desired, err := r.resolveAPIAccess(ctx, oidcClient)
	if err != nil {
		return err
	}

	current, err := apiClient.GetClientAPIAccess(ctx, oidcClient.Status.ClientID)
	if err != nil {
		return fmt.Errorf("get client API access: %w", err)
	}

	if !pocketid.SortedEqual(desired.ClientPermissionIDs, current.ClientPermissionIDs) ||
		!pocketid.SortedEqual(desired.UserDelegatedPermissionIDs, current.UserDelegatedPermissionIDs) {
		log.Info("Updating client API access", "name", oidcClient.Name)
		if _, err := apiClient.UpdateClientAPIAccess(ctx, oidcClient.Status.ClientID, desired); err != nil {
			return fmt.Errorf("update client API access: %w", err)
		}
		metrics.ResourceOperations.WithLabelValues("PocketIDOIDCClient", "updated").Inc()
	}

	// Persist the managed permission IDs so the access can be cleared if spec.apiAccess is emptied.
	managed := mergeSorted(desired.ClientPermissionIDs, desired.UserDelegatedPermissionIDs)
	if !pocketid.SortedEqual(managed, oidcClient.Status.ManagedAPIPermissionIDs) {
		base := oidcClient.DeepCopy()
		oidcClient.Status.ManagedAPIPermissionIDs = managed
		if err := r.Status().Patch(ctx, oidcClient, client.MergeFrom(base)); err != nil {
			return fmt.Errorf("update managed API permission IDs status: %w", err)
		}
	}

	return nil
}

// resolveAPIAccess resolves spec.apiAccess into the desired permission IDs by looking up
// each referenced PocketIDAPI and mapping permission keys to their Pocket-ID IDs.
func (r *Reconciler) resolveAPIAccess(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) (pocketid.ClientAPIAccess, error) {
	clientIDs := make(map[string]struct{})
	delegatedIDs := make(map[string]struct{})

	for _, grant := range oidcClient.Spec.APIAccess {
		if grant.APIRef.Name == "" {
			return pocketid.ClientAPIAccess{}, fmt.Errorf("apiAccess entry has an empty apiRef.name")
		}
		namespace := grant.APIRef.Namespace
		if namespace == "" {
			namespace = oidcClient.Namespace
		}

		api := &pocketidinternalv1alpha1.PocketIDAPI{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: grant.APIRef.Name}, api); err != nil {
			return pocketid.ClientAPIAccess{}, fmt.Errorf("get API %s: %w", grant.APIRef.Name, err)
		}
		if !helpers.IsResourceReady(api.Status.Conditions) {
			return pocketid.ClientAPIAccess{}, fmt.Errorf("API %s is not ready (Ready condition not True)", grant.APIRef.Name)
		}

		keyToID := make(map[string]string, len(api.Status.Permissions))
		for _, p := range api.Status.Permissions {
			keyToID[p.Key] = p.ID
		}

		if err := collectPermissionIDs(grant.DelegatedPermissions, keyToID, grant.APIRef.Name, delegatedIDs); err != nil {
			return pocketid.ClientAPIAccess{}, err
		}
		if err := collectPermissionIDs(grant.ClientPermissions, keyToID, grant.APIRef.Name, clientIDs); err != nil {
			return pocketid.ClientAPIAccess{}, err
		}
	}

	return pocketid.ClientAPIAccess{
		ClientPermissionIDs:        sortedKeys(clientIDs),
		UserDelegatedPermissionIDs: sortedKeys(delegatedIDs),
	}, nil
}

// collectPermissionIDs resolves permission keys to IDs via keyToID and adds them to dst.
func collectPermissionIDs(keys []string, keyToID map[string]string, apiName string, dst map[string]struct{}) error {
	for _, key := range keys {
		id, ok := keyToID[key]
		if !ok {
			return fmt.Errorf("permission %q not found on API %s", key, apiName)
		}
		dst[id] = struct{}{}
	}
	return nil
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// mergeSorted returns the sorted union of the given string slices.
func mergeSorted(slices ...[]string) []string {
	set := make(map[string]struct{})
	for _, s := range slices {
		for _, v := range s {
			set[v] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return sortedKeys(set)
}
