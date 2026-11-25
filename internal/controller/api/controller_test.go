package api

import (
	"cmp"
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid/pocketidtest"
)

// apiServer is a fake Pocket-ID holding APIs by ID. It records every request, with its body,
// in the order they arrived.
type apiServer struct {
	apis     map[string]*pid.APIResponseDto
	requests []string
	bodies   map[string]string
}

func newAPIServer(t *testing.T, apis ...pid.APIResponseDto) (*apiServer, *pocketid.Client) {
	t.Helper()
	srv := &apiServer{apis: map[string]*pid.APIResponseDto{}, bodies: map[string]string{}}
	for _, api := range apis {
		srv.apis[api.ID] = &api
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/admin/apis", func(w http.ResponseWriter, r *http.Request) {
		var page pid.PaginatedAPIAPIResponseDto
		for _, api := range srv.apis {
			if strings.Contains(api.Resource, r.URL.Query().Get("search")) {
				page.Data = append(page.Data, *api)
			}
		}
		writeJSON(w, http.StatusOK, page)
	})
	mux.HandleFunc("POST /api/admin/apis", func(w http.ResponseWriter, r *http.Request) {
		var body pid.APICreateDto
		srv.decode(r, &body)
		api := &pid.APIResponseDto{ID: "api-new", Name: body.Name, Resource: body.Resource, CreatedAt: time.Now()}
		srv.apis[api.ID] = api
		writeJSON(w, http.StatusCreated, api)
	})
	mux.HandleFunc("PATCH /api/admin/apis/{id}", srv.withAPI(func(api *pid.APIResponseDto, r *http.Request) {
		var body pid.PatchAPIJSONRequestBody
		srv.decode(r, &body)
		if body.Name != nil {
			api.Name = *body.Name
		}
	}))
	// Pocket-ID matches permissions by key, so a kept permission keeps its ID.
	mux.HandleFunc("PUT /api/admin/apis/{id}/permissions", srv.withAPI(func(api *pid.APIResponseDto, r *http.Request) {
		var body struct {
			Permissions []pid.APIPermissionResponseDto
		}
		srv.decode(r, &body)
		ids := map[string]string{}
		for _, p := range api.Permissions {
			ids[p.Key] = p.ID
		}
		for i, p := range body.Permissions {
			body.Permissions[i].ID = cmp.Or(ids[p.Key], "p-"+p.Key)
		}
		api.Permissions = body.Permissions
	}))
	mux.HandleFunc("PUT /api/admin/apis/{id}/cimd-access", srv.withAPI(func(api *pid.APIResponseDto, r *http.Request) {
		var body struct {
			Enabled       bool
			PermissionIDs []string `json:"permissionIds"`
		}
		srv.decode(r, &body)
		api.AllowCIMDClients = body.Enabled
		for i, p := range api.Permissions {
			api.Permissions[i].AllowedForCIMDClients = slices.Contains(body.PermissionIDs, p.ID)
		}
	}))
	return srv, pocketidtest.NewClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.requests = append(srv.requests, r.Method+" "+r.URL.Path)
		mux.ServeHTTP(w, r)
	}))
}

// withAPI applies update to the API named in the path and answers with it, or 404s.
func (s *apiServer) withAPI(update func(*pid.APIResponseDto, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		api, ok := s.apis[r.PathValue("id")]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found"})
			return
		}
		update(api, r)
		writeJSON(w, http.StatusOK, api)
	}
}

func (s *apiServer) decode(r *http.Request, v any) {
	var raw json.RawMessage
	_ = json.NewDecoder(r.Body).Decode(&raw)
	s.bodies[r.Method+" "+r.URL.Path] = string(raw)
	_ = json.Unmarshal(raw, v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
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

func ordersAPI(status pocketidinternalv1alpha1.PocketIDAPIStatus, perms ...pocketidinternalv1alpha1.APIPermission) *pocketidinternalv1alpha1.PocketIDAPI {
	return &pocketidinternalv1alpha1.PocketIDAPI{
		ObjectMeta: metav1.ObjectMeta{Name: "orders", Namespace: "default"},
		Spec: pocketidinternalv1alpha1.PocketIDAPISpec{
			Name:        "Orders",
			Resource:    "https://orders.example.com",
			Permissions: perms,
		},
		Status: status,
	}
}

func TestCreateOrAdoptAPI(t *testing.T) {
	existing := pid.APIResponseDto{ID: "existing-1", Name: "Orders", Resource: "https://orders.example.com"}
	for name, tt := range map[string]struct {
		apis       []pid.APIResponseDto
		wantID     string
		wantCreate bool
	}{
		"adopts by resource": {apis: []pid.APIResponseDto{existing}, wantID: "existing-1"},
		"creates":            {wantID: "api-new", wantCreate: true},
	} {
		t.Run(name, func(t *testing.T) {
			api := ordersAPI(pocketidinternalv1alpha1.PocketIDAPIStatus{})
			srv, apiClient := newAPIServer(t, tt.apis...)
			r := newReconciler(t, api)

			requeue, err := r.createOrAdoptAPI(context.Background(), api, apiClient)
			if err != nil {
				t.Fatalf("createOrAdoptAPI: %v", err)
			}
			if !requeue {
				t.Fatal("expected requeue")
			}
			if created := slices.Contains(srv.requests, "POST /api/admin/apis"); created != tt.wantCreate {
				t.Errorf("created = %v, want %v", created, tt.wantCreate)
			}
			updated := &pocketidinternalv1alpha1.PocketIDAPI{}
			_ = r.Get(context.Background(), client.ObjectKeyFromObject(api), updated)
			if updated.Status.APIID != tt.wantID {
				t.Fatalf("APIID = %q, want %q", updated.Status.APIID, tt.wantID)
			}
		})
	}
}

// The spec is written every reconcile: the name, then the full permission set, then CIMD access
// resolved against the IDs the permission write assigned.
func TestPushAPIState_WritesSpec(t *testing.T) {
	createdAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	srv, apiClient := newAPIServer(t, pid.APIResponseDto{
		ID: "api-1", Name: "Old", Resource: "https://orders.example.com", CreatedAt: createdAt,
		Permissions: []pid.APIPermissionResponseDto{
			{ID: "p1", Key: "read", Name: "Read"},
			{ID: "p2", Key: "external", Name: "Added in the UI"},
		},
	})
	api := ordersAPI(pocketidinternalv1alpha1.PocketIDAPIStatus{APIID: "api-1"},
		pocketidinternalv1alpha1.APIPermission{Key: "write", Name: "Write", CIMDAccess: true},
		pocketidinternalv1alpha1.APIPermission{Key: "read", Name: "Read"},
	)
	r := newReconciler(t, api)

	current, err := r.pushAPIState(context.Background(), api, apiClient)
	if err != nil {
		t.Fatalf("pushAPIState: %v", err)
	}

	wantRequests := []string{
		"PATCH /api/admin/apis/api-1",
		"PUT /api/admin/apis/api-1/permissions",
		"PUT /api/admin/apis/api-1/cimd-access",
	}
	if !reflect.DeepEqual(srv.requests, wantRequests) {
		t.Fatalf("requests = %v, want %v", srv.requests, wantRequests)
	}
	// Name is the only field the operator manages; the resource is immutable.
	if got := srv.bodies["PATCH /api/admin/apis/api-1"]; got != `{"name":"Orders"}` {
		t.Errorf("PATCH body = %s", got)
	}
	// The permission created in this write is the one CIMD access is granted on.
	if got := srv.bodies["PUT /api/admin/apis/api-1/cimd-access"]; got != `{"enabled":true,"permissionIds":["p-write"]}` {
		t.Errorf("CIMD body = %s", got)
	}

	if err := r.updateAPIStatus(context.Background(), api, current); err != nil {
		t.Fatalf("updateAPIStatus: %v", err)
	}
	want := []pocketidinternalv1alpha1.ObservedAPIPermission{
		{ID: "p1", Key: "read", Name: "Read"},
		{ID: "p-write", Key: "write", Name: "Write", CIMDAccess: true},
	}
	if !reflect.DeepEqual(api.Status.Permissions, want) {
		t.Errorf("status permissions = %+v, want %+v", api.Status.Permissions, want)
	}
	if api.Status.Name != "Orders" || !api.Status.CIMDAccess || api.Status.CreatedAt != createdAt.Format(time.RFC3339) {
		t.Errorf("status = %+v", api.Status)
	}
}

func TestPushAPIState_EmptySpecClearsPermissions(t *testing.T) {
	srv, apiClient := newAPIServer(t, pid.APIResponseDto{ID: "api-1",
		Permissions: []pid.APIPermissionResponseDto{{ID: "p1", Key: "read"}}})
	api := ordersAPI(pocketidinternalv1alpha1.PocketIDAPIStatus{APIID: "api-1"})

	current, err := newReconciler(t, api).pushAPIState(context.Background(), api, apiClient)
	if err != nil {
		t.Fatalf("pushAPIState: %v", err)
	}
	if got := srv.bodies["PUT /api/admin/apis/api-1/permissions"]; got != `{"permissions":[]}` {
		t.Errorf("permissions body = %s", got)
	}
	if got := srv.bodies["PUT /api/admin/apis/api-1/cimd-access"]; got != `{"enabled":false,"permissionIds":[]}` {
		t.Errorf("CIMD body = %s", got)
	}
	if len(current.Permissions) != 0 {
		t.Errorf("permissions = %+v, want none", current.Permissions)
	}
}

// An API deleted outside the operator answers the first write with 404, which Reconcile reads
// as an external deletion.
func TestPushAPIState_DeletedExternally(t *testing.T) {
	srv, apiClient := newAPIServer(t)
	api := ordersAPI(pocketidinternalv1alpha1.PocketIDAPIStatus{APIID: "gone"})

	_, err := newReconciler(t, api).pushAPIState(context.Background(), api, apiClient)
	if !pocketid.IsNotFoundError(err) {
		t.Fatalf("err = %v, want not found", err)
	}
	if len(srv.requests) != 1 {
		t.Errorf("requests = %v, want only the PATCH", srv.requests)
	}
}

func TestRequestsForOIDCClient_EnqueuesReferencedAndFinalizerCarryingAPIs(t *testing.T) {
	// referenced is named in the client's current apiAccess (finalizer must be added).
	referenced := &pocketidinternalv1alpha1.PocketIDAPI{
		ObjectMeta: metav1.ObjectMeta{Name: "orders", Namespace: "default"},
		Spec:       pocketidinternalv1alpha1.PocketIDAPISpec{Resource: "https://orders.example.com"},
	}
	// dropped is no longer in the client's spec but still carries the reference finalizer:
	// the client just removed the grant, so it must be enqueued to drop the finalizer.
	dropped := &pocketidinternalv1alpha1.PocketIDAPI{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "billing",
			Namespace:  "default",
			Finalizers: []string{OIDCClientAPIFinalizer},
		},
		Spec: pocketidinternalv1alpha1.PocketIDAPISpec{Resource: "https://billing.example.com"},
	}
	// unrelated has no finalizer and is not referenced: it must not be enqueued.
	unrelated := &pocketidinternalv1alpha1.PocketIDAPI{
		ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "default"},
		Spec:       pocketidinternalv1alpha1.PocketIDAPISpec{Resource: "https://unrelated.example.com"},
	}

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			APIAccess: []pocketidinternalv1alpha1.OIDCClientAPIAccess{{
				APIRef: pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders"},
			}},
		},
	}

	r := newReconciler(t, referenced, dropped, unrelated, oidcClient)
	requests := r.requestsForOIDCClient(context.Background(), oidcClient)

	got := make(map[string]bool, len(requests))
	for _, req := range requests {
		got[req.Name] = true
	}
	if !got["orders"] {
		t.Errorf("expected referenced API 'orders' to be enqueued, got %v", got)
	}
	if !got["billing"] {
		t.Errorf("expected finalizer-carrying API 'billing' to be enqueued, got %v", got)
	}
	if got["unrelated"] {
		t.Errorf("did not expect unrelated API to be enqueued, got %v", got)
	}
}
