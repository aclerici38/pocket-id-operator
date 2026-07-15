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
	if !reflect.DeepEqual(got.UserDelegatedPermissionIDs, []string{"p-read"}) {
		t.Fatalf("delegated = %v", got.UserDelegatedPermissionIDs)
	}
	if !reflect.DeepEqual(got.ClientPermissionIDs, []string{"p-sync"}) {
		t.Fatalf("client = %v", got.ClientPermissionIDs)
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

	var putBody map[string][]string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet: // no current access
			writeAccessJSON(w, nil, nil)
		case http.MethodPut:
			_ = json.NewDecoder(r.Body).Decode(&putBody)
			writeAccessJSON(w, putBody["clientPermissionIds"], putBody["userDelegatedPermissionIds"])
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
	if !reflect.DeepEqual(putBody["userDelegatedPermissionIds"], []string{"p-read"}) {
		t.Fatalf("expected delegated push of p-read, got %+v", putBody)
	}
	if !reflect.DeepEqual(oidcClient.Status.ManagedAPIPermissionIDs, []string{"p-read"}) {
		t.Fatalf("expected managed status p-read, got %v", oidcClient.Status.ManagedAPIPermissionIDs)
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

func writeAccessJSON(w http.ResponseWriter, clientIDs, delegatedIDs []string) {
	if clientIDs == nil {
		clientIDs = []string{}
	}
	if delegatedIDs == nil {
		delegatedIDs = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string][]string{
		"clientPermissionIds":        clientIDs,
		"userDelegatedPermissionIds": delegatedIDs,
	})
}
