package oidcclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
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

	got, err := r.resolveAPIAccess(context.Background(), oidcClient)
	if err != nil {
		t.Fatalf("resolveAPIAccess: %v", err)
	}
	grant, ok := got["api-1"]
	if !ok {
		t.Fatalf("no grant for api-1: %+v", got)
	}
	if !reflect.DeepEqual(grant.UserDelegatedPermissionIDs, []string{"p-read"}) {
		t.Fatalf("delegated = %v", grant.UserDelegatedPermissionIDs)
	}
	if !reflect.DeepEqual(grant.ClientPermissionIDs, []string{"p-sync"}) {
		t.Fatalf("client = %v", grant.ClientPermissionIDs)
	}
	if !grant.UserDelegatedAccess || !grant.ClientAccess {
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
	if _, err := r.resolveAPIAccess(context.Background(), oidcClient); err == nil {
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
	if _, err := r.resolveAPIAccess(context.Background(), oidcClient); err == nil {
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

	got, err := r.resolveAPIAccess(context.Background(), oidcClient)
	if err != nil {
		t.Fatalf("resolveAPIAccess: %v", err)
	}
	grant, ok := got["api-1"]
	if !ok {
		t.Fatalf("a scopeless grant must still be a grant: %+v", got)
	}
	if !grant.UserDelegatedAccess || len(grant.UserDelegatedPermissionIDs) != 0 {
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

	got, err := r.resolveAPIAccess(context.Background(), oidcClient)
	if err != nil {
		t.Fatalf("resolveAPIAccess: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no grants, got %+v", got)
	}
}

func TestReconcileAPIAccess_NoSpecNoManaged_Skips(t *testing.T) {
	s := apiAccessScheme(t)
	oidcClient := clientWithAccess(nil)
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	r := &Reconciler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(oidcClient).WithStatusSubresource(oidcClient).Build()}
	apiClient := mustPocketClient(t, ts.URL)

	if err := r.ReconcileAPIAccess(context.Background(), oidcClient, apiClient); err != nil {
		t.Fatalf("ReconcileAPIAccess: %v", err)
	}
	if called {
		t.Fatal("should not call Pocket-ID when apiAccess unset and nothing managed")
	}
}

func TestReconcileAPIAccess_PushesOnDrift(t *testing.T) {
	s := apiAccessScheme(t)
	api := readyAPI([]pocketidinternalv1alpha1.ObservedAPIPermission{
		{ID: "p-read", Key: "read:orders"},
	})
	oidcClient := clientWithAccess([]pocketidinternalv1alpha1.OIDCClientAPIAccess{{
		APIRef:               pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders"},
		DelegatedPermissions: []string{"read:orders"},
	}})

	var putPath string
	var putBody grantBody
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet: // no current access
			writeJSON(w, []any{})
		case http.MethodPut:
			putPath = r.URL.Path
			_ = json.NewDecoder(r.Body).Decode(&putBody)
			writeJSON(w, putBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	r := &Reconciler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(api, oidcClient).WithStatusSubresource(oidcClient).Build()}
	apiClient := mustPocketClient(t, ts.URL)

	if err := r.ReconcileAPIAccess(context.Background(), oidcClient, apiClient); err != nil {
		t.Fatalf("ReconcileAPIAccess: %v", err)
	}
	if putPath != "/api/apis/api-1/clients/client-1" {
		t.Fatalf("unexpected PUT path %q", putPath)
	}
	if !putBody.UserDelegatedAccess || !reflect.DeepEqual(putBody.UserDelegatedPermissionIDs, []string{"p-read"}) {
		t.Fatalf("expected delegated push of p-read, got %+v", putBody)
	}
	if !reflect.DeepEqual(oidcClient.Status.ManagedAPIPermissionIDs, []string{"p-read"}) {
		t.Fatalf("expected managed status p-read, got %v", oidcClient.Status.ManagedAPIPermissionIDs)
	}
}

func TestReconcileAPIAccess_RevokesDroppedAPI(t *testing.T) {
	s := apiAccessScheme(t)
	oidcClient := clientWithAccess(nil)
	oidcClient.Status.ManagedAPIPermissionIDs = []string{"p-read"}

	deleted := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, []map[string]any{{
				"api":                        map[string]any{"id": "api-1"},
				"userDelegatedAccess":        true,
				"userDelegatedPermissionIds": []string{"p-read"},
			}})
		case http.MethodDelete:
			deleted = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	r := &Reconciler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(oidcClient).WithStatusSubresource(oidcClient).Build()}

	if err := r.ReconcileAPIAccess(context.Background(), oidcClient, mustPocketClient(t, ts.URL)); err != nil {
		t.Fatalf("ReconcileAPIAccess: %v", err)
	}
	if deleted != "/api/apis/api-1/clients/client-1" {
		t.Fatalf("expected the dropped API grant to be revoked, got %q", deleted)
	}
	if oidcClient.Status.ManagedAPIPermissionIDs != nil {
		t.Fatalf("expected managed IDs cleared, got %v", oidcClient.Status.ManagedAPIPermissionIDs)
	}
}

// A CIMD-granted API belongs to the API, not the client, so it must not be revoked.
func TestReconcileAPIAccess_LeavesCIMDGrantedAPIAlone(t *testing.T) {
	s := apiAccessScheme(t)
	oidcClient := clientWithAccess(nil)
	oidcClient.Status.ManagedAPIPermissionIDs = []string{"p-read"}

	deleted := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, []map[string]any{{
				"api":                      map[string]any{"id": "api-1"},
				"cimdGrantedAccess":        true,
				"cimdGrantedPermissionIds": []string{"p-read"},
			}})
		case http.MethodDelete:
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	r := &Reconciler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(oidcClient).WithStatusSubresource(oidcClient).Build()}

	if err := r.ReconcileAPIAccess(context.Background(), oidcClient, mustPocketClient(t, ts.URL)); err != nil {
		t.Fatalf("ReconcileAPIAccess: %v", err)
	}
	if deleted {
		t.Fatal("revoked an API the client only reaches through its CIMD setting")
	}
}

func TestMergeSorted(t *testing.T) {
	got := mergeSorted([]string{"b", "a"}, []string{"a", "c"})
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("mergeSorted = %v", got)
	}
	if mergeSorted(nil, nil) != nil {
		t.Fatal("mergeSorted of empties should be nil")
	}
}

func mustPocketClient(t *testing.T, url string) *pocketid.Client {
	t.Helper()
	c, err := pocketid.NewClient(url, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// grantBody mirrors the per-API grant DTO exchanged with Pocket-ID.
type grantBody struct {
	ClientAccess               bool     `json:"clientAccess"`
	UserDelegatedAccess        bool     `json:"userDelegatedAccess"`
	ClientPermissionIDs        []string `json:"clientPermissionIds"`
	UserDelegatedPermissionIDs []string `json:"userDelegatedPermissionIds"`
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
