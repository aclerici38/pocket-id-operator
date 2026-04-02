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
		Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{
			GroupID:        "gid-sync",
			ManagedUserIDs: []string{"uid-1"},
		},
	}

	// current matches desired exactly (only managed user present)
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

	if _, err := r.pushUserGroupState(ctx, ug, apiClient, current); err != nil {
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

	if _, err := r.pushUserGroupState(ctx, ug, apiClient, current); err != nil {
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

	if _, err := r.pushUserGroupState(ctx, ug, apiClient, current); err != nil {
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

func TestPushUserGroupState_RemovesManagedUsersWhenSpecCleared(t *testing.T) {
	// When spec.users is nil but status.managedUserIDs has previously managed users,
	// those managed users should be removed while externally-added users are preserved.
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	ug := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "clear-users-group", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			Name: "clear-users-group",
			// No spec.users → desired userIDs = nil
		},
		Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{
			GroupID:        "gid-clear-users",
			ManagedUserIDs: []string{"managed-user"},
		},
	}

	// current has both a managed user and an external user
	current := &pocketid.UserGroup{
		ID:           "gid-clear-users",
		Name:         "clear-users-group",
		FriendlyName: "clear-users-group",
		UserIDs:      []string{"managed-user", "external-user"},
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

	if _, err := r.pushUserGroupState(ctx, ug, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedBody == nil {
		t.Fatal("expected UpdateUserGroupUsers to be called")
	}
	// Should contain only the external user; the managed user should be removed.
	userIds, ok := receivedBody["userIds"]
	if !ok {
		t.Fatal("expected userIds field in request body")
	}
	ids, ok := userIds.([]any)
	if !ok {
		t.Fatalf("expected userIds to be an array, got %T", userIds)
	}
	if len(ids) != 1 || ids[0] != "external-user" {
		t.Errorf("expected [external-user], got %v", ids)
	}
}

func TestPushUserGroupState_FirstReconcileIsAdditive(t *testing.T) {
	// On first reconcile (no status.managedUserIDs), desired users are added
	// without removing any existing external users.
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	ug := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "first-reconcile-group", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			Name: "first-reconcile-group",
			Users: &pocketidinternalv1alpha1.UserGroupUsers{
				UserIDs: []string{"new-managed"},
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{
			GroupID: "gid-first",
			// No ManagedUserIDs — first reconcile
		},
	}

	// Group already has an external user from before adoption
	current := &pocketid.UserGroup{
		ID:           "gid-first",
		Name:         "first-reconcile-group",
		FriendlyName: "first-reconcile-group",
		UserIDs:      []string{"existing-external"},
	}

	r := newUserGroupPushReconciler(scheme, ug)

	var receivedBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodPut && req.URL.Path == "/api/user-groups/gid-first/users":
			_ = json.NewDecoder(req.Body).Decode(&receivedBody)
			okUserGroupResponse(w, "gid-first", "first-reconcile-group")
		default:
			http.NotFound(w, req)
		}
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if _, err := r.pushUserGroupState(ctx, ug, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedBody == nil {
		t.Fatal("expected UpdateUserGroupUsers to be called")
	}
	userIds := receivedBody["userIds"].([]any)
	if len(userIds) != 2 {
		t.Fatalf("expected 2 users, got %v", userIds)
	}
	// Both external and new managed user should be present (sorted)
	expected := []string{"existing-external", "new-managed"}
	for i, id := range userIds {
		if id != expected[i] {
			t.Errorf("expected %q at index %d, got %q", expected[i], i, id)
		}
	}
}

func TestPushUserGroupState_PreservesExternalUsers(t *testing.T) {
	// When CR users haven't changed but an external user was added via UI,
	// the external user should be preserved (no API call needed if managed set matches).
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	ug := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "preserve-group", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			Name: "preserve-group",
			Users: &pocketidinternalv1alpha1.UserGroupUsers{
				UserIDs: []string{"managed-1"},
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{
			GroupID:        "gid-preserve",
			ManagedUserIDs: []string{"managed-1"},
		},
	}

	// Pocket-ID has the managed user + an external user added via UI
	current := &pocketid.UserGroup{
		ID:           "gid-preserve",
		Name:         "preserve-group",
		FriendlyName: "preserve-group",
		UserIDs:      []string{"managed-1", "external-dave"},
	}

	r := newUserGroupPushReconciler(scheme, ug)

	// Server that fails on any call — no API update should happen
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("unexpected API call — external users should be preserved without update")
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if _, err := r.pushUserGroupState(ctx, ug, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPushUserGroupState_RemovesOnlyUnmanagedFromCR(t *testing.T) {
	// When a user is removed from the CR, only that user is removed from the group.
	// External users and remaining managed users are preserved.
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	ug := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "remove-one-group", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			Name: "remove-one-group",
			Users: &pocketidinternalv1alpha1.UserGroupUsers{
				UserIDs: []string{"bob"}, // Alice removed from CR
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{
			GroupID:        "gid-remove-one",
			ManagedUserIDs: []string{"alice", "bob"}, // Previously managed both
		},
	}

	// Pocket-ID has alice, bob, and external dave
	current := &pocketid.UserGroup{
		ID:           "gid-remove-one",
		Name:         "remove-one-group",
		FriendlyName: "remove-one-group",
		UserIDs:      []string{"alice", "bob", "dave"},
	}

	r := newUserGroupPushReconciler(scheme, ug)

	var receivedBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodPut && req.URL.Path == "/api/user-groups/gid-remove-one/users":
			_ = json.NewDecoder(req.Body).Decode(&receivedBody)
			okUserGroupResponse(w, "gid-remove-one", "remove-one-group")
		default:
			http.NotFound(w, req)
		}
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if _, err := r.pushUserGroupState(ctx, ug, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedBody == nil {
		t.Fatal("expected UpdateUserGroupUsers to be called")
	}
	userIds := receivedBody["userIds"].([]any)
	// Should have bob and dave (alice removed), sorted
	expected := []string{"bob", "dave"}
	if len(userIds) != len(expected) {
		t.Fatalf("expected %d users, got %v", len(expected), userIds)
	}
	for i, id := range userIds {
		if id != expected[i] {
			t.Errorf("expected %q at index %d, got %q", expected[i], i, id)
		}
	}
}

// --- computeMergedMembers unit tests ---

func TestComputeMergedMembers_AdoptionPreservesExisting(t *testing.T) {
	// First reconcile: previouslyManaged is empty, existing users preserved
	result := computeMergedMembers(
		[]string{"alice", "bob"},    // desired
		nil,                         // previously managed (first reconcile)
		[]string{"dave", "charlie"}, // current in Pocket-ID
	)
	expected := []string{"alice", "bob", "charlie", "dave"}
	if len(result) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, result)
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("index %d: expected %q, got %q", i, expected[i], result[i])
		}
	}
}

func TestComputeMergedMembers_RemovesOnlyDroppedManaged(t *testing.T) {
	result := computeMergedMembers(
		[]string{"bob"},                  // desired (alice removed)
		[]string{"alice", "bob"},         // previously managed
		[]string{"alice", "bob", "dave"}, // current
	)
	expected := []string{"bob", "dave"}
	if len(result) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, result)
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("index %d: expected %q, got %q", i, expected[i], result[i])
		}
	}
}

func TestComputeMergedMembers_ClearsAllManaged(t *testing.T) {
	result := computeMergedMembers(
		nil,                              // desired (spec.users cleared)
		[]string{"alice", "bob"},         // previously managed
		[]string{"alice", "bob", "dave"}, // current
	)
	expected := []string{"dave"}
	if len(result) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, result)
	}
	if result[0] != "dave" {
		t.Errorf("expected %q, got %q", "dave", result[0])
	}
}

func TestComputeMergedMembers_NoChangeWhenInSync(t *testing.T) {
	result := computeMergedMembers(
		[]string{"alice", "bob"},         // desired
		[]string{"alice", "bob"},         // previously managed (same)
		[]string{"alice", "bob", "dave"}, // current (includes external dave)
	)
	expected := []string{"alice", "bob", "dave"}
	if len(result) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, result)
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("index %d: expected %q, got %q", i, expected[i], result[i])
		}
	}
}
