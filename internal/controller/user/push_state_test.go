package user

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// pocketIDUserAPIResponse is the JSON shape returned by Pocket-ID user endpoints.
type pocketIDUserAPIResponse struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	IsAdmin     bool   `json:"isAdmin"`
	Disabled    bool   `json:"disabled"`
	Locale      string `json:"locale"`
}

// okUserResponse writes a minimal valid user JSON response.
func okUserResponse(w http.ResponseWriter, id, username string) {
	resp := pocketIDUserAPIResponse{ID: id, Username: username}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func newUserPushReconciler(scheme *runtime.Scheme) *Reconciler {
	fc := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &Reconciler{Client: fc, Scheme: scheme}
	r.EnsureClient(fc)
	return r
}

// TestPushUserState_SkipsWhenInSync verifies that pushUserState makes no API calls
// when the desired state (from the CR spec) already matches the current state in Pocket-ID.
func TestPushUserState_SkipsWhenInSync(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{Name: "alice", Namespace: "default"},
		Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
			Username:    pocketidinternalv1alpha1.StringValue{Value: "alice"},
			FirstName:   pocketidinternalv1alpha1.StringValue{Value: "Alice"},
			LastName:    pocketidinternalv1alpha1.StringValue{Value: "Smith"},
			Email:       pocketidinternalv1alpha1.StringValue{Value: "alice@example.com"},
			DisplayName: pocketidinternalv1alpha1.StringValue{Value: "Alice Smith"},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{UserID: "uid-alice"},
	}

	// current matches desired exactly — ToInput() must equal buildUserInput output
	current := &pocketid.User{
		ID:          "uid-alice",
		Username:    "alice",
		FirstName:   "Alice",
		LastName:    "Smith",
		Email:       "alice@example.com",
		DisplayName: "Alice Smith",
	}

	r := newUserPushReconciler(scheme)

	// Server that fails on any call — verifies no UpdateUser is made.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("unexpected API call during in-sync pushUserState")
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if err := r.pushUserState(ctx, user, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestPushUserState_UpdatesWhenFieldChanged verifies that pushUserState calls UpdateUser
// when a field differs between the desired spec and the current Pocket-ID state.
func TestPushUserState_UpdatesWhenFieldChanged(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{Name: "bob", Namespace: "default"},
		Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
			Username:    pocketidinternalv1alpha1.StringValue{Value: "bob"},
			FirstName:   pocketidinternalv1alpha1.StringValue{Value: "Bob"},
			Email:       pocketidinternalv1alpha1.StringValue{Value: "bob-new@example.com"},
			DisplayName: pocketidinternalv1alpha1.StringValue{Value: "Bob"},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{UserID: "uid-bob"},
	}

	// current has old email — triggers update
	current := &pocketid.User{
		ID:          "uid-bob",
		Username:    "bob",
		FirstName:   "Bob",
		Email:       "bob-old@example.com",
		DisplayName: "Bob",
	}

	r := newUserPushReconciler(scheme)

	updateCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPut && req.URL.Path == "/api/users/uid-bob" {
			updateCalled = true
			okUserResponse(w, "uid-bob", "bob")
			return
		}
		http.NotFound(w, req)
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if err := r.pushUserState(ctx, user, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !updateCalled {
		t.Error("expected UpdateUser to be called when email changed")
	}
}

// TestPushUserState_UpdatesForEachField exercises every field of UserInput to verify that a
// single-field difference between desired and current always triggers UpdateUser.
// This guards against accidentally missing a field in the equality comparison.
func TestPushUserState_UpdatesForEachField(t *testing.T) {
	sv := func(v string) pocketidinternalv1alpha1.StringValue {
		return pocketidinternalv1alpha1.StringValue{Value: v}
	}

	// Baseline values shared by spec and current in the "matching" case.
	const (
		uid   = "uid-field-test"
		uname = "fieldtest"
		fn    = "Field"
		ln    = "Test"
		email = "field@example.com"
		dn    = "Field Test"
	)

	baseSpec := func() pocketidinternalv1alpha1.PocketIDUserSpec {
		return pocketidinternalv1alpha1.PocketIDUserSpec{
			Username:    sv(uname),
			FirstName:   sv(fn),
			LastName:    sv(ln),
			Email:       sv(email),
			DisplayName: sv(dn),
		}
	}
	baseCurrent := func() pocketid.User {
		return pocketid.User{
			ID: uid, Username: uname, FirstName: fn, LastName: ln,
			Email: email, DisplayName: dn,
		}
	}

	cases := []struct {
		name    string
		spec    pocketidinternalv1alpha1.PocketIDUserSpec
		current pocketid.User
	}{
		{
			name: "FirstName changed",
			spec: func() pocketidinternalv1alpha1.PocketIDUserSpec {
				s := baseSpec()
				s.FirstName = sv("NewFirst")
				return s
			}(),
			current: baseCurrent(),
		},
		{
			name: "LastName changed",
			spec: func() pocketidinternalv1alpha1.PocketIDUserSpec {
				s := baseSpec()
				s.LastName = sv("NewLast")
				return s
			}(),
			current: baseCurrent(),
		},
		{
			name: "DisplayName changed",
			spec: func() pocketidinternalv1alpha1.PocketIDUserSpec {
				s := baseSpec()
				s.DisplayName = sv("New Name")
				return s
			}(),
			current: baseCurrent(),
		},
		{
			name: "IsAdmin set to true",
			spec: func() pocketidinternalv1alpha1.PocketIDUserSpec {
				s := baseSpec()
				s.Admin = true
				return s
			}(),
			current: baseCurrent(), // IsAdmin defaults to false
		},
		{
			name: "IsAdmin cleared to false",
			spec: baseSpec(), // Admin defaults to false
			current: func() pocketid.User {
				c := baseCurrent()
				c.IsAdmin = true
				return c
			}(),
		},
		{
			name: "Disabled set to true",
			spec: func() pocketidinternalv1alpha1.PocketIDUserSpec {
				s := baseSpec()
				s.Disabled = true
				return s
			}(),
			current: baseCurrent(), // Disabled defaults to false
		},
		{
			name: "Locale changed",
			spec: func() pocketidinternalv1alpha1.PocketIDUserSpec {
				s := baseSpec()
				s.Locale = "de"
				return s
			}(),
			current: func() pocketid.User {
				c := baseCurrent()
				c.Locale = "en"
				return c
			}(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			scheme := runtime.NewScheme()
			_ = pocketidinternalv1alpha1.AddToScheme(scheme)

			userCR := &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{Name: uname, Namespace: "default"},
				Spec:       tc.spec,
				Status:     pocketidinternalv1alpha1.PocketIDUserStatus{UserID: uid},
			}
			current := tc.current

			r := newUserPushReconciler(scheme)

			updateCalled := false
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method == http.MethodPut && req.URL.Path == "/api/users/"+uid {
					updateCalled = true
					okUserResponse(w, uid, uname)
					return
				}
				http.NotFound(w, req)
			}))
			defer ts.Close()
			apiClient, _ := pocketid.NewClient(ts.URL, "")

			if err := r.pushUserState(ctx, userCR, apiClient, &current); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !updateCalled {
				t.Errorf("expected UpdateUser to be called when %q changed, but it was not", tc.name)
			}
		})
	}
}

// TestPushUserState_SkipsWhenAllFieldsMatch verifies that no update is made when all
// UserInput fields — including booleans and locale — already match current state.
func TestPushUserState_SkipsWhenAllFieldsMatch(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	sv := func(v string) pocketidinternalv1alpha1.StringValue {
		return pocketidinternalv1alpha1.StringValue{Value: v}
	}

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{Name: "full-match", Namespace: "default"},
		Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
			Username:    sv("full-match"),
			FirstName:   sv("Full"),
			LastName:    sv("Match"),
			Email:       sv("full@example.com"),
			DisplayName: sv("Full Match"),
			Admin:       true,
			Disabled:    true,
			Locale:      "fr",
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{UserID: "uid-full"},
	}
	current := &pocketid.User{
		ID: "uid-full", Username: "full-match", FirstName: "Full", LastName: "Match",
		Email: "full@example.com", DisplayName: "Full Match",
		IsAdmin: true, Disabled: true, Locale: "fr",
	}

	r := newUserPushReconciler(scheme)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("unexpected API call: all fields match, no update should occur")
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if err := r.pushUserState(ctx, user, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
