package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

type apiJSON struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Resource    string          `json:"resource"`
	Permissions []permissionRow `json:"permissions"`
}

type permissionRow struct {
	ID          string `json:"id"`
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func apiScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := pocketidinternalv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return s
}

func newReconciler(t *testing.T, objs ...client.Object) *Reconciler {
	t.Helper()
	fc := fake.NewClientBuilder().
		WithScheme(apiScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(objs...).
		Build()
	r := &Reconciler{Client: fc}
	r.EnsureClient(fc)
	return r
}

func pocketClient(t *testing.T, url string) *pocketid.Client {
	t.Helper()
	c, err := pocketid.NewClient(url, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestCreateOrAdoptAPI_AdoptsByResource(t *testing.T) {
	api := &pocketidinternalv1alpha1.PocketIDAPI{
		ObjectMeta: metav1.ObjectMeta{Name: "orders", Namespace: "default"},
		Spec:       pocketidinternalv1alpha1.PocketIDAPISpec{Resource: "https://orders.example.com"},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/apis" {
			writeJSON(w, map[string]any{"data": []apiJSON{{ID: "existing-1", Name: "Orders", Resource: "https://orders.example.com"}}})
			return
		}
		http.Error(w, "unexpected create", http.StatusInternalServerError)
	}))
	defer ts.Close()

	r := newReconciler(t, api)
	requeue, err := r.createOrAdoptAPI(context.Background(), api, pocketClient(t, ts.URL))
	if err != nil {
		t.Fatalf("createOrAdoptAPI: %v", err)
	}
	if !requeue {
		t.Fatal("expected requeue after adoption")
	}

	updated := &pocketidinternalv1alpha1.PocketIDAPI{}
	_ = r.Get(context.Background(), client.ObjectKeyFromObject(api), updated)
	if updated.Status.APIID != "existing-1" {
		t.Fatalf("expected adopted APIID existing-1, got %q", updated.Status.APIID)
	}
}

func TestPushAPIState_CreatesDeclaredPermissions(t *testing.T) {
	api := &pocketidinternalv1alpha1.PocketIDAPI{
		ObjectMeta: metav1.ObjectMeta{Name: "orders", Namespace: "default"},
		Spec: pocketidinternalv1alpha1.PocketIDAPISpec{
			Name:     "Orders",
			Resource: "https://orders.example.com",
			Permissions: []pocketidinternalv1alpha1.APIPermission{
				{Key: "read:orders", Name: "Read"},
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDAPIStatus{APIID: "api-1"},
	}

	var sentPerms []map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/api/apis/api-1/permissions" {
			var body struct {
				Permissions []map[string]any `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			sentPerms = body.Permissions
			writeJSON(w, apiJSON{ID: "api-1", Name: "Orders", Resource: "https://orders.example.com"})
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	r := newReconciler(t, api)
	// current pocket-id state: name matches, no permissions yet
	current := &pocketid.API{ID: "api-1", Name: "Orders", Resource: "https://orders.example.com"}

	updated, err := r.pushAPIState(context.Background(), api, pocketClient(t, ts.URL), current)
	if err != nil {
		t.Fatalf("pushAPIState: %v", err)
	}
	if !updated {
		t.Fatal("expected an update")
	}
	if len(sentPerms) != 1 || sentPerms[0]["key"] != "read:orders" {
		t.Fatalf("unexpected permissions pushed: %+v", sentPerms)
	}
}

func TestPushAPIState_ReplacesExternalPermissions(t *testing.T) {
	api := &pocketidinternalv1alpha1.PocketIDAPI{
		ObjectMeta: metav1.ObjectMeta{Name: "orders", Namespace: "default"},
		Spec: pocketidinternalv1alpha1.PocketIDAPISpec{
			Name:        "Orders",
			Resource:    "https://orders.example.com",
			Permissions: []pocketidinternalv1alpha1.APIPermission{{Key: "read:orders", Name: "Read"}},
		},
		Status: pocketidinternalv1alpha1.PocketIDAPIStatus{APIID: "api-1"},
	}

	var sentKeys []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/api/apis/api-1/permissions" {
			var body struct {
				Permissions []map[string]any `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			for _, p := range body.Permissions {
				sentKeys = append(sentKeys, p["key"].(string))
			}
			writeJSON(w, apiJSON{ID: "api-1", Name: "Orders", Resource: "https://orders.example.com"})
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	r := newReconciler(t, api)
	// Pocket-ID has an extra externally-added permission; sole ownership drops it.
	current := &pocketid.API{
		ID: "api-1", Name: "Orders", Resource: "https://orders.example.com",
		Permissions: []pocketid.APIPermission{
			{ID: "p1", Key: "read:orders", Name: "Read"},
			{ID: "p2", Key: "external:scope", Name: "External"},
		},
	}

	if _, err := r.pushAPIState(context.Background(), api, pocketClient(t, ts.URL), current); err != nil {
		t.Fatalf("pushAPIState: %v", err)
	}
	if !reflect.DeepEqual(sentKeys, []string{"read:orders"}) {
		t.Fatalf("expected only spec permission pushed, got %v", sentKeys)
	}
}

func TestPushAPIState_InSyncNoUpdate(t *testing.T) {
	api := &pocketidinternalv1alpha1.PocketIDAPI{
		ObjectMeta: metav1.ObjectMeta{Name: "orders", Namespace: "default"},
		Spec: pocketidinternalv1alpha1.PocketIDAPISpec{
			Name:        "Orders",
			Resource:    "https://orders.example.com",
			Permissions: []pocketidinternalv1alpha1.APIPermission{{Key: "read:orders", Name: "Read"}},
		},
		Status: pocketidinternalv1alpha1.PocketIDAPIStatus{APIID: "api-1"},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer ts.Close()

	r := newReconciler(t, api)
	current := &pocketid.API{
		ID: "api-1", Name: "Orders", Resource: "https://orders.example.com",
		Permissions: []pocketid.APIPermission{{ID: "p1", Key: "read:orders", Name: "Read"}},
	}

	updated, err := r.pushAPIState(context.Background(), api, pocketClient(t, ts.URL), current)
	if err != nil {
		t.Fatalf("pushAPIState: %v", err)
	}
	if updated {
		t.Fatal("expected no update when in sync")
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
