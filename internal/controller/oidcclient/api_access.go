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

	// A cimd client is fetched even when nothing is managed, so status keeps reporting the
	// access its APIs grant it. Only a cimd client can hold that access.
	// ManagedAPIPermissionIDs is still consulted so a client reconciled by an older operator
	// version, which recorded no ManagedAPIs, stays under management across the upgrade.
	manage := len(oidcClient.Spec.APIAccess) > 0 ||
		len(oidcClient.Status.ManagedAPIs) > 0 ||
		len(oidcClient.Status.ManagedAPIPermissionIDs) > 0
	isCIMD := oidcClient.Status.ClientType == pocketid.ClientTypeCIMD
	if !manage && !isCIMD {
		return nil
	}

	desired, err := r.resolveAPIAccess(ctx, oidcClient)
	if err != nil {
		return err
	}

	all, err := apiClient.ListAPIClientGrants(ctx, oidcClient.Status.ClientID)
	if err != nil {
		return fmt.Errorf("list API client grants: %w", err)
	}

	// An entry with no grant of its own is reachable only through the API's CIMD setting,
	// which the API owns: reconciling it from here would revoke it on every pass.
	var current []pocketid.APIClientGrant
	var cimdGranted []string
	for _, grant := range all {
		if !grant.IsEmpty() {
			current = append(current, grant)
		}
		if grant.CIMDGranted {
			cimdGranted = append(cimdGranted, grant.Resource)
		}
	}
	sort.Strings(cimdGranted)

	currentByAPI := make(map[string]pocketid.APIClientGrant, len(current))
	for _, grant := range current {
		currentByAPI[grant.APIID] = grant
	}

	changed := false
	if !manage {
		return r.patchAPIAccessStatus(ctx, oidcClient, oidcClient.Status.ManagedAPIPermissionIDs,
			oidcClient.Status.ManagedAPIs, cimdGranted)
	}

	for _, apiID := range sortedKeysOfGrants(desired) {
		if grantsEqual(currentByAPI[apiID], desired[apiID]) {
			continue
		}
		log.Info("Updating client API access", "name", oidcClient.Name, "apiID", apiID)
		if _, err := apiClient.SetAPIClientGrant(ctx, apiID, oidcClient.Status.ClientID, desired[apiID]); err != nil {
			return fmt.Errorf("set API client grant: %w", err)
		}
		changed = true
	}
	for _, grant := range current {
		if _, ok := desired[grant.APIID]; ok {
			continue
		}
		log.Info("Revoking client API access", "name", oidcClient.Name, "apiID", grant.APIID)
		if err := apiClient.RemoveAPIClientGrant(ctx, grant.APIID, oidcClient.Status.ClientID); err != nil {
			return fmt.Errorf("remove API client grant: %w", err)
		}
		changed = true
	}
	if changed {
		metrics.ResourceOperations.WithLabelValues("PocketIDOIDCClient", "updated").Inc()
	}

	// Persist what was granted so the access can be revoked if spec.apiAccess is emptied.
	return r.patchAPIAccessStatus(ctx, oidcClient, managedPermissionIDs(desired),
		sortedKeysOfGrants(desired), cimdGranted)
}

// patchAPIAccessStatus records what the operator manages and what the client reaches through
// its APIs' CIMD setting, in one patch.
func (r *Reconciler) patchAPIAccessStatus(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, managed, managedAPIs, cimdGranted []string) error {
	if pocketid.SortedEqual(managed, oidcClient.Status.ManagedAPIPermissionIDs) &&
		pocketid.SortedEqual(managedAPIs, oidcClient.Status.ManagedAPIs) &&
		pocketid.SortedEqual(cimdGranted, oidcClient.Status.CIMDGrantedAPIs) {
		return nil
	}
	base := oidcClient.DeepCopy()
	oidcClient.Status.ManagedAPIPermissionIDs = managed
	oidcClient.Status.ManagedAPIs = managedAPIs
	oidcClient.Status.CIMDGrantedAPIs = cimdGranted
	if err := r.Status().Patch(ctx, oidcClient, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("update API access status: %w", err)
	}
	return nil
}

// resolveAPIAccess resolves spec.apiAccess into the desired grant per Pocket-ID API ID by
// looking up each referenced PocketIDAPI and mapping permission keys to their Pocket-ID IDs.
// Entries that grant nothing are omitted: Pocket-ID stores no row for them, so keeping them
// would leave the reconcile permanently drifted. A flow granted with no permissions is still
// a grant, and is kept.
func (r *Reconciler) resolveAPIAccess(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) (map[string]pocketid.APIClientGrant, error) {
	delegatedIDs := make(map[string]map[string]struct{})
	clientIDs := make(map[string]map[string]struct{})
	delegatedAccess := make(map[string]bool)
	clientAccess := make(map[string]bool)

	for _, grant := range oidcClient.Spec.APIAccess {
		if grant.APIRef.Name == "" {
			return nil, fmt.Errorf("apiAccess entry has an empty apiRef.name")
		}
		namespace := grant.APIRef.Namespace
		if namespace == "" {
			namespace = oidcClient.Namespace
		}

		api := &pocketidinternalv1alpha1.PocketIDAPI{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: grant.APIRef.Name}, api); err != nil {
			return nil, fmt.Errorf("get API %s: %w", grant.APIRef.Name, err)
		}
		if !helpers.IsResourceReady(api.Status.Conditions) {
			return nil, fmt.Errorf("API %s is not ready (Ready condition not True)", grant.APIRef.Name)
		}
		if api.Status.APIID == "" {
			return nil, fmt.Errorf("API %s has no Pocket-ID ID in status", grant.APIRef.Name)
		}

		keyToID := make(map[string]string, len(api.Status.Permissions))
		for _, p := range api.Status.Permissions {
			keyToID[p.Key] = p.ID
		}

		if _, ok := delegatedIDs[api.Status.APIID]; !ok {
			delegatedIDs[api.Status.APIID] = make(map[string]struct{})
			clientIDs[api.Status.APIID] = make(map[string]struct{})
		}
		delegatedAccess[api.Status.APIID] = delegatedAccess[api.Status.APIID] ||
			accessRequested(grant.DelegatedAccess, grant.DelegatedPermissions)
		clientAccess[api.Status.APIID] = clientAccess[api.Status.APIID] ||
			accessRequested(grant.ClientAccess, grant.ClientPermissions)
		if err := collectPermissionIDs(grant.DelegatedPermissions, keyToID, grant.APIRef.Name, delegatedIDs[api.Status.APIID]); err != nil {
			return nil, err
		}
		if err := collectPermissionIDs(grant.ClientPermissions, keyToID, grant.APIRef.Name, clientIDs[api.Status.APIID]); err != nil {
			return nil, err
		}
	}

	desired := make(map[string]pocketid.APIClientGrant, len(delegatedIDs))
	for apiID := range delegatedIDs {
		delegated := sortedKeys(delegatedIDs[apiID])
		clientPerms := sortedKeys(clientIDs[apiID])
		grant := pocketid.APIClientGrant{
			APIID:                      apiID,
			ClientAccess:               clientAccess[apiID],
			UserDelegatedAccess:        delegatedAccess[apiID],
			ClientPermissionIDs:        clientPerms,
			UserDelegatedPermissionIDs: delegated,
		}
		if grant.IsEmpty() {
			continue
		}
		desired[apiID] = grant
	}
	return desired, nil
}

// accessRequested reports whether a flow is granted: the explicit flag when set, otherwise
// whether any permission was selected for it.
func accessRequested(explicit *bool, permissions []string) bool {
	if explicit != nil {
		return *explicit
	}
	return len(permissions) > 0
}

// grantsEqual reports whether two grants convey the same access.
func grantsEqual(a, b pocketid.APIClientGrant) bool {
	return a.ClientAccess == b.ClientAccess &&
		a.UserDelegatedAccess == b.UserDelegatedAccess &&
		pocketid.SortedEqual(a.ClientPermissionIDs, b.ClientPermissionIDs) &&
		pocketid.SortedEqual(a.UserDelegatedPermissionIDs, b.UserDelegatedPermissionIDs)
}

// managedPermissionIDs returns the sorted union of every permission ID across the grants.
func managedPermissionIDs(grants map[string]pocketid.APIClientGrant) []string {
	all := make([][]string, 0, 2*len(grants))
	for _, grant := range grants {
		all = append(all, grant.ClientPermissionIDs, grant.UserDelegatedPermissionIDs)
	}
	return mergeSorted(all...)
}

// sortedKeysOfGrants returns the API IDs of the grants, sorted.
func sortedKeysOfGrants(grants map[string]pocketid.APIClientGrant) []string {
	keys := make([]string, 0, len(grants))
	for k := range grants {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
