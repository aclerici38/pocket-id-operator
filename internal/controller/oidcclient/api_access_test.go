package oidcclient

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

func apiAccessScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := pocketidinternalv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return s
}

func readyAPI(perms []pocketidinternalv1alpha1.ObservedAPIPermission) *pocketidinternalv1alpha1.PocketIDAPI {
	return &pocketidinternalv1alpha1.PocketIDAPI{
		ObjectMeta: metav1.ObjectMeta{Name: "orders", Namespace: "default"},
		Status: pocketidinternalv1alpha1.PocketIDAPIStatus{
			APIID:       "api-1",
			Permissions: perms,
			Conditions: []metav1.Condition{{
				Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled",
				LastTransitionTime: metav1.Now(),
			}},
		},
	}
}

func clientWithAccess(grants []pocketidinternalv1alpha1.OIDCClientAPIAccess) *pocketidinternalv1alpha1.PocketIDOIDCClient {
	return &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
		Spec:       pocketidinternalv1alpha1.PocketIDOIDCClientSpec{APIAccess: grants},
		Status:     pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "client-1"},
	}
}

func TestResolveAPIAccess_MapsKeysToIDs(t *testing.T) {
	s := apiAccessScheme(t)
	api := readyAPI([]pocketidinternalv1alpha1.ObservedAPIPermission{
		{ID: "p-read", Key: "read:orders"},
		{ID: "p-sync", Key: "sync:orders"},
	})
	oidcClient := clientWithAccess([]pocketidinternalv1alpha1.OIDCClientAPIAccess{{
		APIRef:               pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders"},
		DelegatedPermissions: []string{"read:orders"},
		ClientPermissions:    []string{"sync:orders"},
	}})

	r := &Reconciler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(api).Build()}

	got, err := r.resolveAPIAccess(context.Background(), oidcClient, nil)
	if err != nil {
		t.Fatalf("resolveAPIAccess: %v", err)
	}
	grant, ok := got["api-1"]
	if !ok {
		t.Fatalf("no grant for api-1: %+v", got)
	}
	if !reflect.DeepEqual(grant.UserDelegatedPermissionIDs.MustGet(), []string{"p-read"}) {
		t.Fatalf("delegated = %v", grant.UserDelegatedPermissionIDs)
	}
	if !reflect.DeepEqual(grant.ClientPermissionIDs.MustGet(), []string{"p-sync"}) {
		t.Fatalf("client = %v", grant.ClientPermissionIDs)
	}
	if !*grant.UserDelegatedAccess || !*grant.ClientAccess {
		t.Fatalf("expected both access flags set: %+v", grant)
	}
}

func TestResolveAPIAccess_ErrorsWhenAPINotReady(t *testing.T) {
	s := apiAccessScheme(t)
	api := readyAPI(nil)
	api.Status.Conditions = nil // not ready
	oidcClient := clientWithAccess([]pocketidinternalv1alpha1.OIDCClientAPIAccess{{
		APIRef: pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders"},
	}})

	r := &Reconciler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(api).Build()}
	if _, err := r.resolveAPIAccess(context.Background(), oidcClient, nil); err == nil {
		t.Fatal("expected error when API not ready")
	}
}

func TestResolveAPIAccess_ErrorsOnUnknownPermissionKey(t *testing.T) {
	s := apiAccessScheme(t)
	api := readyAPI([]pocketidinternalv1alpha1.ObservedAPIPermission{{ID: "p1", Key: "read:orders"}})
	oidcClient := clientWithAccess([]pocketidinternalv1alpha1.OIDCClientAPIAccess{{
		APIRef:            pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders"},
		ClientPermissions: []string{"missing:scope"},
	}})

	r := &Reconciler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(api).Build()}
	if _, err := r.resolveAPIAccess(context.Background(), oidcClient, nil); err == nil {
		t.Fatal("expected error for unknown permission key")
	}
}

func TestResolveAPIAccess_ExplicitAccessWithoutPermissions(t *testing.T) {
	s := apiAccessScheme(t)
	api := readyAPI(nil)
	yes := true
	oidcClient := clientWithAccess([]pocketidinternalv1alpha1.OIDCClientAPIAccess{{
		APIRef:          pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders"},
		DelegatedAccess: &yes,
	}})

	r := &Reconciler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(api).Build()}

	got, err := r.resolveAPIAccess(context.Background(), oidcClient, nil)
	if err != nil {
		t.Fatalf("resolveAPIAccess: %v", err)
	}
	grant, ok := got["api-1"]
	if !ok {
		t.Fatalf("a scopeless grant must still be a grant: %+v", got)
	}
	if !*grant.UserDelegatedAccess || len(grant.UserDelegatedPermissionIDs.MustGet()) != 0 {
		t.Fatalf("unexpected grant: %+v", grant)
	}
}

func TestResolveAPIAccess_OmitsEntryGrantingNothing(t *testing.T) {
	s := apiAccessScheme(t)
	api := readyAPI(nil)
	oidcClient := clientWithAccess([]pocketidinternalv1alpha1.OIDCClientAPIAccess{{
		APIRef: pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders"},
	}})

	r := &Reconciler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(api).Build()}

	got, err := r.resolveAPIAccess(context.Background(), oidcClient, nil)
	if err != nil {
		t.Fatalf("resolveAPIAccess: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no grants, got %+v", got)
	}
}

// The operator owns every grant the client holds: spec grants are written every reconcile,
// any other grant of the client's own is revoked, and access the client only reaches through
// an API's CIMD setting belongs to the API, so it is reported rather than revoked.
func TestReconcileAPIAccess(t *testing.T) {
	ownGrant := map[string]any{"api": map[string]any{"id": "api-ui"}, "userDelegatedAccess": true}
	scopelessGrant := map[string]any{"api": map[string]any{"id": "api-scopeless"}, "clientAccess": true}
	cimdOnly := map[string]any{
		"api":                      map[string]any{"id": "api-cimd", "resource": "https://cimd.example.com"},
		"cimdGrantedAccess":        true,
		"cimdGrantedPermissionIds": []string{"p-cimd"},
	}
	specced := map[string]any{"api": map[string]any{"id": "api-1"}, "userDelegatedAccess": true}
	readOrders := []pocketidinternalv1alpha1.OIDCClientAPIAccess{{
		APIRef:               pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders"},
		DelegatedPermissions: []string{"read:orders"},
	}}

	for _, tc := range []struct {
		name        string
		spec        []pocketidinternalv1alpha1.OIDCClientAPIAccess
		current     []map[string]any
		wantPuts    []string
		wantDeletes []string
		wantCIMD    []string
	}{
		{name: "nothing to do still lists"},
		{name: "writes spec grants", spec: readOrders, current: []map[string]any{specced}, wantPuts: []string{"api-1"}},
		{
			name:        "revokes grants made outside the operator",
			current:     []map[string]any{ownGrant, scopelessGrant},
			wantDeletes: []string{"api-ui", "api-scopeless"},
		},
		{
			name:     "keeps CIMD-only access and reports it",
			spec:     readOrders,
			current:  []map[string]any{cimdOnly},
			wantPuts: []string{"api-1"},
			wantCIMD: []string{"https://cimd.example.com"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := apiAccessScheme(t)
			api := readyAPI([]pocketidinternalv1alpha1.ObservedAPIPermission{{ID: "p-read", Key: "read:orders"}})
			oidcClient := clientWithAccess(tc.spec)
			oidcClient.Status.CIMDGrantedAPIs = []string{"stale"}

			var puts, deletes []string
			encoded := encodedID("client-1")
			apiClient := fakeAPI(t, map[string]http.HandlerFunc{
				"GET /api/admin/api-access/" + encoded + "/apis": func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(w, append([]map[string]any{}, tc.current...))
				},
				"PUT /api/admin/apis/{id}/clients/" + encoded: func(w http.ResponseWriter, r *http.Request) {
					var body map[string]any
					decodeBody(t, r, &body)
					if body["userDelegatedAccess"] != true || !reflect.DeepEqual(body["userDelegatedPermissionIds"], []any{"p-read"}) {
						t.Errorf("unexpected grant body %v", body)
					}
					puts = append(puts, r.PathValue("id"))
					writeJSON(w, body)
				},
				"DELETE /api/admin/apis/{id}/clients/" + encoded: func(w http.ResponseWriter, r *http.Request) {
					deletes = append(deletes, r.PathValue("id"))
					w.WriteHeader(http.StatusNoContent)
				},
			})
			r := &Reconciler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(api, oidcClient).WithStatusSubresource(oidcClient).Build()}

			if err := r.ReconcileAPIAccess(context.Background(), oidcClient, apiClient); err != nil {
				t.Fatalf("ReconcileAPIAccess: %v", err)
			}
			if !reflect.DeepEqual(puts, tc.wantPuts) {
				t.Errorf("PUTs = %v, want %v", puts, tc.wantPuts)
			}
			if !reflect.DeepEqual(deletes, tc.wantDeletes) {
				t.Errorf("DELETEs = %v, want %v", deletes, tc.wantDeletes)
			}
			if !reflect.DeepEqual(oidcClient.Status.CIMDGrantedAPIs, tc.wantCIMD) {
				t.Errorf("cimdGrantedAPIs = %v, want %v", oidcClient.Status.CIMDGrantedAPIs, tc.wantCIMD)
			}
		})
	}
}

func TestResolveAPITokenParams_MergesEntriesForOneAPI(t *testing.T) {
	s := apiAccessScheme(t)
	api := readyAPI(nil)
	api.Status.Resource = "https://orders.example.com"
	// Two entries for the same API: their client permissions merge.
	oidcClient := clientWithAccess([]pocketidinternalv1alpha1.OIDCClientAPIAccess{
		{
			APIRef:               pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders"},
			DelegatedPermissions: []string{"list:orders"},
			ClientPermissions:    []string{"sync:orders"},
		},
		{
			APIRef:            pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders", Namespace: "default"},
			ClientPermissions: []string{"read:orders", "sync:orders"},
		},
	})

	r := &Reconciler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(api).Build()}

	params, err := r.resolveAPITokenParams(context.Background(), oidcClient, "")
	if err != nil {
		t.Fatalf("resolveAPITokenParams: %v", err)
	}
	if len(params) != 1 {
		t.Fatalf("expected one entry, got %+v", params)
	}
	if params[0].name != "orders" || params[0].resource != "https://orders.example.com" {
		t.Fatalf("params = %+v", params[0])
	}
	// Delegated permissions are not client-credentials scopes.
	if !reflect.DeepEqual(sortedKeys(params[0].scopes), []string{"read:orders", "sync:orders"}) {
		t.Fatalf("scopes = %v", sortedKeys(params[0].scopes))
	}
}

func TestResolveAPITokenParams_SortsByReferencedName(t *testing.T) {
	s := apiAccessScheme(t)
	orders := readyAPI(nil)
	orders.Status.Resource = "https://orders.example.com"
	billing := readyAPI(nil)
	billing.Name = "billing"
	billing.Status.Resource = "https://billing.example.com"
	oidcClient := clientWithAccess([]pocketidinternalv1alpha1.OIDCClientAPIAccess{
		{BuiltIn: true},
		{APIRef: pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders"}},
		{APIRef: pocketidinternalv1alpha1.NamespacedAPIReference{Name: "billing"}},
	})

	r := &Reconciler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(orders, billing).Build()}

	params, err := r.resolveAPITokenParams(context.Background(), oidcClient, "https://id.example.com/api")
	if err != nil {
		t.Fatalf("resolveAPITokenParams: %v", err)
	}
	if len(params) != 3 || params[0].name != "billing" || params[1].name != "orders" || params[2].name != "pocket_id" {
		t.Fatalf("expected entries sorted by name, got %+v", params)
	}
	if params[2].resource != "https://id.example.com/api" {
		t.Fatalf("built-in resource = %q", params[2].resource)
	}
}

func TestResolveAPITokenParams_FallsBackToSpecResource(t *testing.T) {
	s := apiAccessScheme(t)
	api := readyAPI(nil)
	api.Spec.Resource = "https://orders.example.com"
	yes := true
	oidcClient := clientWithAccess([]pocketidinternalv1alpha1.OIDCClientAPIAccess{{
		APIRef:       pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders"},
		ClientAccess: &yes,
	}})

	r := &Reconciler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(api).Build()}

	params, err := r.resolveAPITokenParams(context.Background(), oidcClient, "")
	if err != nil {
		t.Fatalf("resolveAPITokenParams: %v", err)
	}
	if len(params) != 1 || params[0].resource != "https://orders.example.com" {
		t.Fatalf("params = %+v", params)
	}
	if len(params[0].scopes) != 0 {
		t.Fatalf("expected no scopes for a grant with no client permissions, got %v", params[0].scopes)
	}
}

func TestResolveAPITokenParams_ErrorsOnSameNameInTwoNamespaces(t *testing.T) {
	s := apiAccessScheme(t)
	local := readyAPI(nil)
	local.Status.Resource = "https://orders.example.com"
	shared := readyAPI(nil)
	shared.Namespace = "shared"
	shared.Status.Resource = "https://shared-orders.example.com"
	oidcClient := clientWithAccess([]pocketidinternalv1alpha1.OIDCClientAPIAccess{
		{APIRef: pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders"}},
		{APIRef: pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders", Namespace: "shared"}},
	})

	r := &Reconciler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(local, shared).Build()}
	// Both would claim resource_orders.
	if _, err := r.resolveAPITokenParams(context.Background(), oidcClient, ""); err == nil {
		t.Fatal("expected error when two APIs collide on the same secret key")
	}
}

func TestResolveAPITokenParams_ErrorsWhenAPIMissing(t *testing.T) {
	s := apiAccessScheme(t)
	oidcClient := clientWithAccess([]pocketidinternalv1alpha1.OIDCClientAPIAccess{{
		APIRef: pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders"},
	}})

	r := &Reconciler{Client: fake.NewClientBuilder().WithScheme(s).Build()}
	if _, err := r.resolveAPITokenParams(context.Background(), oidcClient, ""); err == nil {
		t.Fatal("expected error when the referenced API does not exist")
	}
}
