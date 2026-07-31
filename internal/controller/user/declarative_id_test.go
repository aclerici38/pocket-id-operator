package user

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-openapi/runtime"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const declaredUserID = "18f3c2f6-2c4b-4f26-9d1c-4b7f6e0a1b2c"

func declarativeIDScheme(t *testing.T) *k8sruntime.Scheme {
	t.Helper()
	scheme := k8sruntime.NewScheme()
	if err := pocketidinternalv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add pocketid scheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add core scheme: %v", err)
	}
	return scheme
}

// --- FindExistingUser ID lookup ---

func TestFindExistingUser_LooksUpByIDWithoutListing(t *testing.T) {
	ctx := context.Background()
	reconciler := &Reconciler{}

	expected := &pocketid.User{ID: declaredUserID, Username: "alice", Email: "alice@example.com"}

	mockClient := &mockPocketIDClient{
		getUserFunc: func(_ context.Context, id string) (*pocketid.User, error) {
			if id != declaredUserID {
				t.Fatalf("expected GetUser for %q, got %q", declaredUserID, id)
			}
			return expected, nil
		},
		listUsersFunc: func(context.Context, string) ([]*pocketid.User, error) {
			t.Fatal("ListUsers should not be called when an ID is supplied")
			return nil, nil
		},
	}

	found, err := reconciler.FindExistingUser(ctx, mockClient, declaredUserID, "alice", "alice@example.com")
	if err != nil {
		t.Fatalf("FindExistingUser returned error: %v", err)
	}
	if found == nil {
		t.Fatal("expected to find the user by ID")
	}
	if found.ID != declaredUserID {
		t.Fatalf("expected user ID %q, got %q", declaredUserID, found.ID)
	}
}

// A declared ID that no longer exists must not silently fall back to a username
// match, which would adopt a user with a different ID than the one declared.
func TestFindExistingUser_IDNotFoundDoesNotFallBackToUsername(t *testing.T) {
	ctx := context.Background()
	reconciler := &Reconciler{}

	mockClient := &mockPocketIDClient{
		getUserFunc: func(context.Context, string) (*pocketid.User, error) {
			return nil, runtime.NewAPIError("GetAPIUsersID", nil, http.StatusNotFound)
		},
		listUsersFunc: func(context.Context, string) ([]*pocketid.User, error) {
			t.Fatal("ListUsers should not be called when an ID is supplied")
			return nil, nil
		},
	}

	found, err := reconciler.FindExistingUser(ctx, mockClient, declaredUserID, "alice", "alice@example.com")
	if err != nil {
		t.Fatalf("FindExistingUser returned error: %v", err)
	}
	if found != nil {
		t.Fatalf("expected no user for an unknown ID, got %+v", found)
	}
}

func TestFindExistingUser_IDLookupPropagatesNon404Errors(t *testing.T) {
	ctx := context.Background()
	reconciler := &Reconciler{}

	mockClient := &mockPocketIDClient{
		getUserFunc: func(context.Context, string) (*pocketid.User, error) {
			return nil, runtime.NewAPIError("GetAPIUsersID", nil, http.StatusInternalServerError)
		},
	}

	if _, err := reconciler.FindExistingUser(ctx, mockClient, declaredUserID, "alice", ""); err == nil {
		t.Fatal("expected a 500 from the ID lookup to be returned as an error")
	}
}

// --- buildUserInput ---

func TestBuildUserInput_PropagatesDeclaredID(t *testing.T) {
	scheme := declarativeIDScheme(t)

	for name, specID := range map[string]string{
		"declared": declaredUserID,
		"unset":    "",
	} {
		t.Run(name, func(t *testing.T) {
			user := &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{Name: "alice", Namespace: "default"},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					UserID:   specID,
					Username: pocketidinternalv1alpha1.StringValue{Value: "alice"},
				},
			}

			fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(user).Build()
			r := &Reconciler{Client: fc, APIReader: fc, Scheme: scheme}

			input, err := r.buildUserInput(context.Background(), user)
			if err != nil {
				t.Fatalf("buildUserInput returned error: %v", err)
			}
			if input.ID != specID {
				t.Fatalf("expected input ID %q, got %q", specID, input.ID)
			}
		})
	}
}

// --- createOrAdoptUser ---

// newDeclarativeIDReconciler returns a reconciler backed by a fake client holding user.
func newDeclarativeIDReconciler(t *testing.T, scheme *k8sruntime.Scheme, user *pocketidinternalv1alpha1.PocketIDUser) (*Reconciler, client.Client) {
	t.Helper()
	fc := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user).
		WithStatusSubresource(user).
		Build()
	r := &Reconciler{Client: fc, APIReader: fc, Scheme: scheme}
	r.EnsureClient(fc)
	return r, fc
}

func userWithDeclaredID(name, specID string) *pocketidinternalv1alpha1.PocketIDUser {
	return &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
			UserID:   specID,
			Username: pocketidinternalv1alpha1.StringValue{Value: name},
			Email:    pocketidinternalv1alpha1.StringValue{Value: name + "@example.com"},
		},
	}
}

func statusUserID(t *testing.T, c client.Client, user *pocketidinternalv1alpha1.PocketIDUser) string {
	t.Helper()
	latest := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(user), latest); err != nil {
		t.Fatalf("get user: %v", err)
	}
	return latest.Status.UserID
}

// A user that already carries the declared ID is adopted without issuing a create,
// which Pocket-ID would reject as a duplicate primary key.
func TestCreateOrAdoptUser_AdoptsExistingUserByDeclaredID(t *testing.T) {
	scheme := declarativeIDScheme(t)
	user := userWithDeclaredID("alice", declaredUserID)
	r, fc := newDeclarativeIDReconciler(t, scheme, user)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/api/users/"+declaredUserID:
			w.Header().Set("Content-Type", "application/json")
			// The username in Pocket-ID differs from the spec: adoption must still key off the ID.
			_ = json.NewEncoder(w).Encode(map[string]any{"id": declaredUserID, "username": "renamed-alice"})
		default:
			t.Errorf("unexpected %s %s during ID adoption", req.Method, req.URL.Path)
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	apiClient, err := pocketid.NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "instance", Namespace: "default"},
	}

	requeue, err := r.createOrAdoptUser(context.Background(), user, apiClient, instance)
	if err != nil {
		t.Fatalf("createOrAdoptUser returned error: %v", err)
	}
	if !requeue {
		t.Fatal("expected a requeue after adopting the user")
	}
	if got := statusUserID(t, fc, user); got != declaredUserID {
		t.Fatalf("expected status.userID %q, got %q", declaredUserID, got)
	}
}

// When the declared ID is not present in Pocket-ID, the user is created with it.
func TestCreateOrAdoptUser_CreatesWithDeclaredIDWhenAbsent(t *testing.T) {
	scheme := declarativeIDScheme(t)
	user := userWithDeclaredID("bob", declaredUserID)
	r, fc := newDeclarativeIDReconciler(t, scheme, user)

	var sentID any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/api/users/"+declaredUserID:
			http.Error(w, "not found", http.StatusNotFound)
		case req.Method == http.MethodPost && req.URL.Path == "/api/users":
			var body map[string]any
			_ = json.NewDecoder(req.Body).Decode(&body)
			sentID = body["id"]
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": declaredUserID, "username": "bob"})
		case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/one-time-access-token"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "one-time-token"})
		default:
			t.Errorf("unexpected %s %s during create", req.Method, req.URL.Path)
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	apiClient, err := pocketid.NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "instance", Namespace: "default"},
	}

	requeue, err := r.createOrAdoptUser(context.Background(), user, apiClient, instance)
	if err != nil {
		t.Fatalf("createOrAdoptUser returned error: %v", err)
	}
	if !requeue {
		t.Fatal("expected a requeue after creating the user")
	}
	if sentID != declaredUserID {
		t.Fatalf("expected the declared ID %q in the create body, got %v", declaredUserID, sentID)
	}
	if got := statusUserID(t, fc, user); got != declaredUserID {
		t.Fatalf("expected status.userID %q, got %q", declaredUserID, got)
	}
}

// Without a declared ID the controller must not attempt an ID lookup; it falls
// through to the create-then-adopt-by-username path.
func TestCreateOrAdoptUser_SkipsIDLookupWhenUnset(t *testing.T) {
	scheme := declarativeIDScheme(t)
	user := userWithDeclaredID("carol", "")
	r, fc := newDeclarativeIDReconciler(t, scheme, user)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodPost && req.URL.Path == "/api/users":
			var body map[string]any
			_ = json.NewDecoder(req.Body).Decode(&body)
			if _, present := body["id"]; present {
				t.Errorf("expected no id in the create body, got %v", body["id"])
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "generated-id", "username": "carol"})
		case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/one-time-access-token"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "one-time-token"})
		case req.Method == http.MethodGet:
			t.Errorf("unexpected GET %s: no ID lookup should happen without spec.userID", req.URL.Path)
			http.Error(w, "unexpected", http.StatusInternalServerError)
		default:
			t.Errorf("unexpected %s %s", req.Method, req.URL.Path)
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	apiClient, err := pocketid.NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "instance", Namespace: "default"},
	}

	if _, err := r.createOrAdoptUser(context.Background(), user, apiClient, instance); err != nil {
		t.Fatalf("createOrAdoptUser returned error: %v", err)
	}
	if got := statusUserID(t, fc, user); got != "generated-id" {
		t.Fatalf("expected status.userID %q, got %q", "generated-id", got)
	}
}

// --- pushUserState ---

// The ID is create-only, so a spec that declares it must not read as drift once
// Pocket-ID reports the same user back.
func TestPushUserState_DeclaredIDIsNotDrift(t *testing.T) {
	scheme := declarativeIDScheme(t)

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{Name: "alice", Namespace: "default"},
		Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
			UserID:      declaredUserID,
			Username:    pocketidinternalv1alpha1.StringValue{Value: "alice"},
			FirstName:   pocketidinternalv1alpha1.StringValue{Value: "Alice"},
			DisplayName: pocketidinternalv1alpha1.StringValue{Value: "Alice"},
			Email:       pocketidinternalv1alpha1.StringValue{Value: "alice@example.com"},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{UserID: declaredUserID},
	}

	current := &pocketid.User{
		ID:          declaredUserID,
		Username:    "alice",
		FirstName:   "Alice",
		DisplayName: "Alice",
		Email:       "alice@example.com",
	}

	r := newUserPushReconciler(scheme)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("unexpected API call: a declared ID matching Pocket-ID is not drift")
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	updated, err := r.pushUserState(context.Background(), user, apiClient, current)
	if err != nil {
		t.Fatalf("pushUserState returned error: %v", err)
	}
	if updated {
		t.Fatal("expected no update when only the ID is involved")
	}
}

// Without spec.userID the desired input carries no ID while Pocket-ID always
// reports one. That asymmetry must not push an update on every reconcile.
func TestPushUserState_AutogeneratedIDIsNotDrift(t *testing.T) {
	scheme := declarativeIDScheme(t)

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{Name: "dave", Namespace: "default"},
		Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
			Username:    pocketidinternalv1alpha1.StringValue{Value: "dave"},
			FirstName:   pocketidinternalv1alpha1.StringValue{Value: "Dave"},
			DisplayName: pocketidinternalv1alpha1.StringValue{Value: "Dave"},
			Email:       pocketidinternalv1alpha1.StringValue{Value: "dave@example.com"},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{UserID: "generated-id"},
	}

	current := &pocketid.User{
		ID:          "generated-id",
		Username:    "dave",
		FirstName:   "Dave",
		DisplayName: "Dave",
		Email:       "dave@example.com",
	}

	r := newUserPushReconciler(scheme)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("unexpected API call: an autogenerated ID is not drift")
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	updated, err := r.pushUserState(context.Background(), user, apiClient, current)
	if err != nil {
		t.Fatalf("pushUserState returned error: %v", err)
	}
	if updated {
		t.Fatal("expected no update when the only difference is the autogenerated ID")
	}
}

// Real drift must still be pushed when a declared ID is in play.
func TestPushUserState_UpdatesDespiteDeclaredID(t *testing.T) {
	scheme := declarativeIDScheme(t)

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{Name: "erin", Namespace: "default"},
		Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
			UserID:      declaredUserID,
			Username:    pocketidinternalv1alpha1.StringValue{Value: "erin"},
			FirstName:   pocketidinternalv1alpha1.StringValue{Value: "Erin"},
			DisplayName: pocketidinternalv1alpha1.StringValue{Value: "Erin"},
			Email:       pocketidinternalv1alpha1.StringValue{Value: "erin-new@example.com"},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{UserID: declaredUserID},
	}

	current := &pocketid.User{
		ID:          declaredUserID,
		Username:    "erin",
		FirstName:   "Erin",
		DisplayName: "Erin",
		Email:       "erin-old@example.com",
	}

	r := newUserPushReconciler(scheme)

	updateCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPut && req.URL.Path == "/api/users/"+declaredUserID {
			updateCalled = true
			var body map[string]any
			_ = json.NewDecoder(req.Body).Decode(&body)
			if _, present := body["id"]; present {
				t.Errorf("expected no id in the update body, got %v", body["id"])
			}
			okUserResponse(w, declaredUserID, "erin")
			return
		}
		http.NotFound(w, req)
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	updated, err := r.pushUserState(context.Background(), user, apiClient, current)
	if err != nil {
		t.Fatalf("pushUserState returned error: %v", err)
	}
	if !updated {
		t.Fatal("expected an update for the changed email")
	}
	if !updateCalled {
		t.Fatal("expected UpdateUser to be called")
	}
}
