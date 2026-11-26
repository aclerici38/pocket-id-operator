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
	"maps"
	"slices"
	"sort"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"
	"github.com/oapi-codegen/nullable"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
	"github.com/aclerici38/pocket-id-operator/internal/controller/helpers"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// ReconcileAPIAccess makes this client's API access in Pocket-ID exactly spec.apiAccess. The
// operator owns every grant the client holds except on the built-in API, so other access granted
// outside the operator is revoked.
func (r *Reconciler) ReconcileAPIAccess(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, apiClient *pocketid.Client) error {
	log := logf.FromContext(ctx)

	desired, err := r.resolveAPIAccess(ctx, oidcClient)
	if err != nil {
		return err
	}

	id := pid.OIDCClientID(oidcClient.Status.ClientID)
	current, err := pid.Decode[[]pid.ClientAPIGrantDto](apiClient.ListAPIsClientMayAccess(ctx, id))
	if err != nil {
		return fmt.Errorf("list API client grants: %w", err)
	}

	for _, apiID := range slices.Sorted(maps.Keys(desired)) {
		if err := pid.Check(apiClient.UpdateClientAccessToAPI(ctx, apiID, id, desired[apiID])); err != nil {
			return fmt.Errorf("set API client grant: %w", err)
		}
	}

	var cimdGranted []string
	for _, grant := range current {
		if grant.CIMDGrantedAccess || len(grant.CIMDGrantedPermissionIDs) > 0 {
			cimdGranted = append(cimdGranted, grant.API.Resource)
		}
		// An entry with no grant of its own is reachable only through the API's CIMD setting,
		// which the API owns.
		ownGrant := grant.ClientAccess || grant.UserDelegatedAccess ||
			len(grant.ClientPermissionIDs) > 0 || len(grant.UserDelegatedPermissionIDs) > 0
		if _, wanted := desired[grant.API.ID]; wanted || !ownGrant || grant.API.ID == pocketid.BuiltInAPIID {
			continue
		}
		log.Info("Revoking client API access", "name", oidcClient.Name, "apiID", grant.API.ID)
		if err := pid.Check(apiClient.RevokeClientAccessToAPI(ctx, grant.API.ID, id)); err != nil && !pocketid.IsNotFoundError(err) {
			return fmt.Errorf("remove API client grant: %w", err)
		}
	}

	slices.Sort(cimdGranted)
	base := oidcClient.DeepCopy()
	oidcClient.Status.CIMDGrantedAPIs = cimdGranted
	if err := common.PatchStatus(ctx, r.Client, oidcClient, base); err != nil {
		return fmt.Errorf("update API access status: %w", err)
	}
	return nil
}

// resolveAPIAccess resolves spec.apiAccess into the desired grant per Pocket-ID API ID by
// looking up each referenced PocketIDAPI and mapping permission keys to their Pocket-ID IDs.
// Entries that grant nothing are omitted: Pocket-ID stores no row for them. A flow granted with
// no permissions is still a grant, and is kept.
func (r *Reconciler) resolveAPIAccess(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) (map[string]pid.APIClientGrantUpdateDto, error) {
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

	desired := make(map[string]pid.APIClientGrantUpdateDto, len(delegatedIDs))
	for apiID := range delegatedIDs {
		delegated := sortedKeys(delegatedIDs[apiID])
		clientPerms := sortedKeys(clientIDs[apiID])
		if !clientAccess[apiID] && !delegatedAccess[apiID] && len(delegated) == 0 && len(clientPerms) == 0 {
			continue
		}
		desired[apiID] = pid.APIClientGrantUpdateDto{
			ClientAccess:               new(clientAccess[apiID]),
			UserDelegatedAccess:        new(delegatedAccess[apiID]),
			ClientPermissionIDs:        nullable.NewNullableWithValue(clientPerms),
			UserDelegatedPermissionIDs: nullable.NewNullableWithValue(delegated),
		}
	}
	return desired, nil
}

// addAPITokenParams writes what a token request needs: the audience to ask for and the scopes
// the client-credentials flow may request. Each API gets its own pair, keyed by the name it is
// referenced by, because a token is issued for one audience and scopes belong to one API.
// The unsuffixed pair is written as well while all the grants share an audience. Once they do
// not, it is dropped rather than made to pick one.
func (r *Reconciler) addAPITokenParams(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, keys pocketidinternalv1alpha1.OIDCClientSecretKeys, secretData map[string][]byte) error {
	params, err := r.resolveAPITokenParams(ctx, oidcClient)
	if err != nil {
		return err
	}

	resources := make(map[string]struct{}, len(params))
	allScopes := make(map[string]struct{})
	for _, p := range params {
		setTokenParams(secretData, keys.Resource+"_"+p.name, keys.Scopes+"_"+p.name, p.resource, sortedKeys(p.scopes))
		resources[p.resource] = struct{}{}
		for scope := range p.scopes {
			allScopes[scope] = struct{}{}
		}
	}
	if len(resources) == 1 {
		setTokenParams(secretData, keys.Resource, keys.Scopes, params[0].resource, sortedKeys(allScopes))
	}
	return nil
}

// setTokenParams writes one resource/scopes pair. A grant with no client permissions gets no
// scopes key: it is a request for the audience alone.
func setTokenParams(secretData map[string][]byte, resourceKey, scopesKey, resource string, scopes []string) {
	if resource == "" {
		return
	}
	secretData[resourceKey] = []byte(resource)
	if len(scopes) > 0 {
		secretData[scopesKey] = []byte(strings.Join(scopes, " "))
	}
}

// apiTokenParams is what one API contributes to the credentials Secret.
type apiTokenParams struct {
	// name is the apiRef.name, used as the Secret key suffix. Resources are usually URIs,
	// which are not legal Secret keys; a DNS-1123 name always is.
	name      string
	namespace string
	resource  string
	scopes    map[string]struct{}
}

// resolveAPITokenParams returns one entry per API in spec.apiAccess, sorted by name. Entries
// naming the same API are merged.
func (r *Reconciler) resolveAPITokenParams(ctx context.Context, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) ([]apiTokenParams, error) {
	byName := make(map[string]*apiTokenParams)

	for _, grant := range oidcClient.Spec.APIAccess {
		namespace := grant.APIRef.Namespace
		if namespace == "" {
			namespace = oidcClient.Namespace
		}

		entry, seen := byName[grant.APIRef.Name]
		if seen && entry.namespace != namespace {
			// Both would claim the same Secret key, so fail instead of letting one win.
			return nil, fmt.Errorf("apiAccess references two APIs named %q, in namespaces %s and %s, which collide on the same secret key",
				grant.APIRef.Name, entry.namespace, namespace)
		}
		if !seen {
			api := &pocketidinternalv1alpha1.PocketIDAPI{}
			if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: grant.APIRef.Name}, api); err != nil {
				return nil, fmt.Errorf("get API %s: %w", grant.APIRef.Name, err)
			}
			// Status is what Pocket-ID holds. Spec covers a status not written back yet.
			resource := api.Status.Resource
			if resource == "" {
				resource = api.Spec.Resource
			}
			entry = &apiTokenParams{
				name:      grant.APIRef.Name,
				namespace: namespace,
				resource:  resource,
				scopes:    make(map[string]struct{}),
			}
			byName[grant.APIRef.Name] = entry
		}
		for _, key := range grant.ClientPermissions {
			entry.scopes[key] = struct{}{}
		}
	}

	params := make([]apiTokenParams, 0, len(byName))
	for _, name := range sortedKeysOf(byName) {
		params = append(params, *byName[name])
	}
	return params, nil
}

// sortedKeysOf returns the map's keys, sorted.
func sortedKeysOf(entries map[string]*apiTokenParams) []string {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// accessRequested reports whether a flow is granted: the explicit flag when set, otherwise
// whether any permission was selected for it.
func accessRequested(explicit *bool, permissions []string) bool {
	if explicit != nil {
		return *explicit
	}
	return len(permissions) > 0
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
