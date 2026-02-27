package usergroup

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// pocketIDUserGroupAPIResponse is the JSON shape returned by Pocket-ID user group endpoints.
type pocketIDUserGroupAPIResponse struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	FriendlyName       string `json:"friendlyName"`
	CreatedAt          string `json:"createdAt"`
	LdapID             string `json:"ldapId"`
	Users              []any  `json:"users"`
	CustomClaims       []any  `json:"customClaims"`
	AllowedOidcClients []any  `json:"allowedOidcClients"`
}

// okUserGroupResponse writes a minimal valid user group JSON response.
func okUserGroupResponse(w http.ResponseWriter, id, name string) {
	resp := pocketIDUserGroupAPIResponse{
		ID:                 id,
		Name:               name,
		Users:              []any{},
		CustomClaims:       []any{},
		AllowedOidcClients: []any{},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func newUserGroupPushReconciler(scheme *runtime.Scheme, objs ...client.Object) *Reconciler {
	fc := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(objs...).
		Build()
	r := &Reconciler{Client: fc, Scheme: scheme}
	r.EnsureClient(fc)
	return r
}

// --- buildUserGroupInput tests ---

func TestBuildUserGroupInput_UsesSpecName(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	fc := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &Reconciler{Client: fc, Scheme: scheme}

	ug := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "resource-name", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			Name:         "spec-name",
			FriendlyName: "Spec Friendly Name",
		},
	}

	dummyClient, _ := pocketid.NewClient("http://unused.local", "")
	input, err := r.buildUserGroupInput(ctx, ug, dummyClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if input.Name != "spec-name" {
		t.Errorf("Name: expected %q, got %q", "spec-name", input.Name)
	}
	if input.FriendlyName != "Spec Friendly Name" {
		t.Errorf("FriendlyName: expected %q, got %q", "Spec Friendly Name", input.FriendlyName)
	}
}

func TestBuildUserGroupInput_FallsBackToResourceName(t *testing.T) {
	// When spec.name is empty, the CR metadata.name is used as both name and friendlyName.
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	fc := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &Reconciler{Client: fc, Scheme: scheme}

	ug := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "resource-name", Namespace: testNamespace},
		Spec:       pocketidinternalv1alpha1.PocketIDUserGroupSpec{},
	}

	dummyClient, _ := pocketid.NewClient("http://unused.local", "")
	input, err := r.buildUserGroupInput(ctx, ug, dummyClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if input.Name != "resource-name" {
		t.Errorf("Name: expected fallback to %q, got %q", "resource-name", input.Name)
	}
	if input.FriendlyName != "resource-name" {
		t.Errorf("FriendlyName: expected fallback to %q, got %q", "resource-name", input.FriendlyName)
	}
}

// --- resolveUsers sort order ---

func TestResolveUsers_OutputIsSorted(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	fc := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &Reconciler{Client: fc, Scheme: scheme}

	ug := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "test-group", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			Users: &pocketidinternalv1alpha1.UserGroupUsers{
				UserIDs: []string{"uid-c", "uid-a", "uid-b"},
			},
		},
	}

	// No API calls are made when using direct UserIDs (no username lookups).
	dummyClient, _ := pocketid.NewClient("http://unused.local", "")
	ids, err := r.resolveUsers(ctx, ug, dummyClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{"uid-a", "uid-b", "uid-c"}
	if len(ids) != 3 || ids[0] != expected[0] || ids[1] != expected[1] || ids[2] != expected[2] {
		t.Errorf("expected sorted %v, got %v", expected, ids)
	}
}

func TestResolveUsers_DeduplicatesIDs(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	fc := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &Reconciler{Client: fc, Scheme: scheme}

	ug := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "test-group", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			Users: &pocketidinternalv1alpha1.UserGroupUsers{
				UserIDs: []string{"uid-a", "uid-b", "uid-a"}, // duplicate uid-a
			},
		},
	}

	dummyClient, _ := pocketid.NewClient("http://unused.local", "")
	ids, err := r.resolveUsers(ctx, ug, dummyClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 deduplicated IDs, got %v", ids)
	}
}

// --- pushUserGroupState tests ---

func TestPushUserGroupState_SkipsWhenInSync(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	ug := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "sync-group", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			Name:         "sync-group",
			FriendlyName: "Sync Group",
			CustomClaims: []pocketidinternalv1alpha1.CustomClaim{{Key: "env", Value: "prod"}},
			Users: &pocketidinternalv1alpha1.UserGroupUsers{
				UserIDs: []string{"uid-1"},
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{GroupID: "gid-sync"},
	}

	// current matches desired exactly
	current := &pocketid.UserGroup{
		ID:           "gid-sync",
		Name:         "sync-group",
		FriendlyName: "Sync Group",
		CustomClaims: []pocketid.CustomClaim{{Key: "env", Value: "prod"}},
		UserIDs:      []string{"uid-1"},
	}

	r := newUserGroupPushReconciler(scheme, ug)

	// Server that fails on any call — verifies no API calls are made.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("unexpected API call during in-sync pushUserGroupState")
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if err := r.pushUserGroupState(ctx, ug, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPushUserGroupState_UpdatesOnlyNameWhenNameChanged(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	ug := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "new-name-group", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			Name:         "new-name",
			FriendlyName: "New Friendly Name",
		},
		Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{GroupID: "gid-name"},
	}

	current := &pocketid.UserGroup{
		ID:           "gid-name",
		Name:         "old-name",
		FriendlyName: "Old Friendly Name",
	}

	r := newUserGroupPushReconciler(scheme, ug)

	nameUpdateCalled := false
	claimsUpdateCalled := false
	usersUpdateCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodPut && req.URL.Path == "/api/user-groups/gid-name":
			nameUpdateCalled = true
			okUserGroupResponse(w, "gid-name", "new-name")
		case req.Method == http.MethodPut && req.URL.Path == "/api/custom-claims/user-group/gid-name":
			claimsUpdateCalled = true
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]any{})
		case req.Method == http.MethodPut && req.URL.Path == "/api/user-groups/gid-name/users":
			usersUpdateCalled = true
			okUserGroupResponse(w, "gid-name", "new-name")
		default:
			http.NotFound(w, req)
		}
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if err := r.pushUserGroupState(ctx, ug, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !nameUpdateCalled {
		t.Error("expected UpdateUserGroup to be called when name changed")
	}
	if claimsUpdateCalled {
		t.Error("expected UpdateUserGroupCustomClaims NOT to be called when claims are unchanged (both nil)")
	}
	if usersUpdateCalled {
		t.Error("expected UpdateUserGroupUsers NOT to be called when users are unchanged (both nil)")
	}
}

func TestPushUserGroupState_ClearsClaimsWithEmptySlice(t *testing.T) {
	// When desired claims are nil (no spec.customClaims) but current has claims,
	// the update must send an empty slice (not nil) to clear them.
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	ug := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "clear-claims-group", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			Name: "clear-claims-group",
			// No spec.customClaims → desired claims = nil
		},
		Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{GroupID: "gid-clear-claims"},
	}

	// current has claims → claimsChanged = true
	current := &pocketid.UserGroup{
		ID:           "gid-clear-claims",
		Name:         "clear-claims-group",
		FriendlyName: "clear-claims-group",
		CustomClaims: []pocketid.CustomClaim{{Key: "existing", Value: "claim"}},
	}

	r := newUserGroupPushReconciler(scheme, ug)

	var receivedClaims []any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodPut && req.URL.Path == "/api/custom-claims/user-group/gid-clear-claims":
			_ = json.NewDecoder(req.Body).Decode(&receivedClaims)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]any{})
		case req.Method == http.MethodPut && req.URL.Path == "/api/user-groups/gid-clear-claims":
			okUserGroupResponse(w, "gid-clear-claims", "clear-claims-group")
		case req.Method == http.MethodPut && req.URL.Path == "/api/user-groups/gid-clear-claims/users":
			okUserGroupResponse(w, "gid-clear-claims", "clear-claims-group")
		default:
			http.NotFound(w, req)
		}
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if err := r.pushUserGroupState(ctx, ug, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The body should be an empty JSON array [], not null/missing.
	if receivedClaims == nil {
		t.Error("expected empty array [] to be sent to clear claims, got nil (null)")
	}
	if len(receivedClaims) != 0 {
		t.Errorf("expected empty claims array, got %v", receivedClaims)
	}
}

func TestPushUserGroupState_ClearsUsersWithEmptySlice(t *testing.T) {
	// When desired users are nil (no spec.users) but current has users,
	// the update must send an empty slice (not nil) to clear them.
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	ug := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "clear-users-group", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			Name: "clear-users-group",
			// No spec.users → desired userIDs = nil
		},
		Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{GroupID: "gid-clear-users"},
	}

	// current has users → usersChanged = true
	current := &pocketid.UserGroup{
		ID:           "gid-clear-users",
		Name:         "clear-users-group",
		FriendlyName: "clear-users-group",
		UserIDs:      []string{"existing-user"},
	}

	r := newUserGroupPushReconciler(scheme, ug)

	var receivedBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodPut && req.URL.Path == "/api/user-groups/gid-clear-users/users":
			_ = json.NewDecoder(req.Body).Decode(&receivedBody)
			okUserGroupResponse(w, "gid-clear-users", "clear-users-group")
		case req.Method == http.MethodPut && req.URL.Path == "/api/user-groups/gid-clear-users":
			okUserGroupResponse(w, "gid-clear-users", "clear-users-group")
		case req.Method == http.MethodPut && req.URL.Path == "/api/custom-claims/user-group/gid-clear-users":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]any{})
		default:
			http.NotFound(w, req)
		}
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if err := r.pushUserGroupState(ctx, ug, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedBody == nil {
		t.Fatal("expected UpdateUserGroupUsers to be called")
	}
	// The "userIds" field should be an empty array, not absent/null.
	userIds, ok := receivedBody["userIds"]
	if !ok {
		t.Error("expected userIds field in request body")
	} else {
		ids, ok := userIds.([]any)
		if !ok || len(ids) != 0 {
			t.Errorf("expected empty userIds array, got %v", userIds)
		}
	}
}
