package user

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const claimsUserID = "uid-claims"

// claimsCalls records which Pocket-ID endpoints a pushUserState call reached.
// Custom claims live behind their own endpoint, so profile and claim updates have
// to be observed independently.
type claimsCalls struct {
	profileUpdates int
	claimsUpdates  int
	sentClaims     []map[string]string
}

func newClaimsServer(t *testing.T, calls *claimsCalls) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodPut && req.URL.Path == "/api/users/"+claimsUserID:
			calls.profileUpdates++
			okUserResponse(w, claimsUserID, "claims-user")
		case req.Method == http.MethodPut && req.URL.Path == "/api/custom-claims/user/"+claimsUserID:
			calls.claimsUpdates++
			calls.sentClaims = nil
			if err := json.NewDecoder(req.Body).Decode(&calls.sentClaims); err != nil {
				t.Errorf("decode claims body: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(calls.sentClaims)
		default:
			t.Errorf("unexpected API call: %s %s", req.Method, req.URL.Path)
			http.NotFound(w, req)
		}
	}))
}

// claimsUserCR builds a user CR whose profile already matches claimsCurrent, so any
// observed update is attributable to the custom claims alone.
func claimsUserCR(claims []pocketidinternalv1alpha1.CustomClaim) *pocketidinternalv1alpha1.PocketIDUser {
	sv := func(v string) pocketidinternalv1alpha1.StringValue {
		return pocketidinternalv1alpha1.StringValue{Value: v}
	}
	return &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{Name: "claims-user", Namespace: "default"},
		Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
			Username:     sv("claims-user"),
			FirstName:    sv("Claims"),
			LastName:     sv("User"),
			Email:        sv("claims@example.com"),
			DisplayName:  sv("Claims User"),
			CustomClaims: claims,
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{UserID: claimsUserID},
	}
}

func claimsCurrent(claims []pocketid.CustomClaim) *pocketid.User {
	return &pocketid.User{
		ID:           claimsUserID,
		Username:     "claims-user",
		FirstName:    "Claims",
		LastName:     "User",
		Email:        "claims@example.com",
		DisplayName:  "Claims User",
		CustomClaims: claims,
	}
}

func newClaimsReconciler(t *testing.T) *Reconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	return newUserPushReconciler(scheme)
}

// Claim ordering is not meaningful to Pocket-ID, so a reordered set must not look
// like a diff and retrigger an update on every resync.
func TestPushUserState_SkipsWhenClaimsMatchInAnyOrder(t *testing.T) {
	calls := &claimsCalls{}
	ts := newClaimsServer(t, calls)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	user := claimsUserCR([]pocketidinternalv1alpha1.CustomClaim{
		{Key: "level", Value: "3"},
		{Key: "department", Value: "engineering"},
	})
	current := claimsCurrent([]pocketid.CustomClaim{
		{Key: "department", Value: "engineering"},
		{Key: "level", Value: "3"},
	})

	updated, err := newClaimsReconciler(t).pushUserState(context.Background(), user, apiClient, current)
	if err != nil {
		t.Fatalf("pushUserState: %v", err)
	}
	if updated {
		t.Error("expected pushUserState to report no update")
	}
	if calls.profileUpdates != 0 || calls.claimsUpdates != 0 {
		t.Errorf("expected no API calls, got %+v", calls)
	}
}

// The profile and the claims are separate writes, so a claim-only change must not
// drag an unnecessary user update along with it.
func TestPushUserState_UpdatesOnlyClaimsWhenProfileMatches(t *testing.T) {
	calls := &claimsCalls{}
	ts := newClaimsServer(t, calls)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	user := claimsUserCR([]pocketidinternalv1alpha1.CustomClaim{{Key: "department", Value: "platform"}})
	current := claimsCurrent([]pocketid.CustomClaim{{Key: "department", Value: "engineering"}})

	updated, err := newClaimsReconciler(t).pushUserState(context.Background(), user, apiClient, current)
	if err != nil {
		t.Fatalf("pushUserState: %v", err)
	}
	if !updated {
		t.Error("expected pushUserState to report an update")
	}
	if calls.profileUpdates != 0 {
		t.Errorf("expected no profile update, got %d", calls.profileUpdates)
	}
	if calls.claimsUpdates != 1 {
		t.Fatalf("expected exactly one claims update, got %d", calls.claimsUpdates)
	}
	if len(calls.sentClaims) != 1 || calls.sentClaims[0]["key"] != "department" || calls.sentClaims[0]["value"] != "platform" {
		t.Errorf("claims payload: got %v", calls.sentClaims)
	}
}

// Claims are unchanged here, so the dedicated claims endpoint must stay untouched
// while the profile update goes through.
func TestPushUserState_UpdatesOnlyProfileWhenClaimsMatch(t *testing.T) {
	calls := &claimsCalls{}
	ts := newClaimsServer(t, calls)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	user := claimsUserCR([]pocketidinternalv1alpha1.CustomClaim{{Key: "department", Value: "engineering"}})
	user.Spec.Locale = "de"
	current := claimsCurrent([]pocketid.CustomClaim{{Key: "department", Value: "engineering"}})

	if _, err := newClaimsReconciler(t).pushUserState(context.Background(), user, apiClient, current); err != nil {
		t.Fatalf("pushUserState: %v", err)
	}
	if calls.profileUpdates != 1 {
		t.Errorf("expected exactly one profile update, got %d", calls.profileUpdates)
	}
	if calls.claimsUpdates != 0 {
		t.Errorf("expected no claims update, got %d", calls.claimsUpdates)
	}
}

func TestPushUserState_UpdatesBothWhenProfileAndClaimsChange(t *testing.T) {
	calls := &claimsCalls{}
	ts := newClaimsServer(t, calls)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	user := claimsUserCR([]pocketidinternalv1alpha1.CustomClaim{{Key: "department", Value: "platform"}})
	user.Spec.Locale = "de"
	current := claimsCurrent([]pocketid.CustomClaim{{Key: "department", Value: "engineering"}})

	if _, err := newClaimsReconciler(t).pushUserState(context.Background(), user, apiClient, current); err != nil {
		t.Fatalf("pushUserState: %v", err)
	}
	if calls.profileUpdates != 1 || calls.claimsUpdates != 1 {
		t.Errorf("expected one profile and one claims update, got %+v", calls)
	}
}

// The endpoint replaces the whole set, so removing every claim from the spec has to
// send an empty array rather than skipping the call and leaving stale claims behind.
func TestPushUserState_ClearsClaimsWhenSpecHasNone(t *testing.T) {
	calls := &claimsCalls{}
	ts := newClaimsServer(t, calls)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	user := claimsUserCR(nil)
	current := claimsCurrent([]pocketid.CustomClaim{{Key: "department", Value: "engineering"}})

	if _, err := newClaimsReconciler(t).pushUserState(context.Background(), user, apiClient, current); err != nil {
		t.Fatalf("pushUserState: %v", err)
	}
	if calls.claimsUpdates != 1 {
		t.Fatalf("expected exactly one claims update, got %d", calls.claimsUpdates)
	}
	if len(calls.sentClaims) != 0 {
		t.Errorf("expected an empty claims payload, got %v", calls.sentClaims)
	}
}

// Both sides are empty, so there is nothing to clear and no call to make.
func TestPushUserState_SkipsWhenNeitherSideHasClaims(t *testing.T) {
	calls := &claimsCalls{}
	ts := newClaimsServer(t, calls)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	user := claimsUserCR(nil)
	current := claimsCurrent(nil)

	if _, err := newClaimsReconciler(t).pushUserState(context.Background(), user, apiClient, current); err != nil {
		t.Fatalf("pushUserState: %v", err)
	}
	if calls.claimsUpdates != 0 {
		t.Errorf("expected no claims update, got %d", calls.claimsUpdates)
	}
}

// Status reports the claims Pocket-ID actually holds, including any set outside the
// operator, so it is mirrored from the fetched user rather than from the spec.
func TestUpdateUserStatus_MirrorsCustomClaims(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	user := claimsUserCR(nil)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&pocketidinternalv1alpha1.PocketIDUser{}).
		WithObjects(user).
		Build()
	r := &Reconciler{Client: fakeClient, APIReader: fakeClient, Scheme: scheme}

	current := claimsCurrent([]pocketid.CustomClaim{{Key: "department", Value: "engineering"}})
	if err := r.updateUserStatus(ctx, user, current); err != nil {
		t.Fatalf("updateUserStatus: %v", err)
	}

	updated := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updated); err != nil {
		t.Fatalf("get user: %v", err)
	}
	want := []pocketidinternalv1alpha1.CustomClaim{{Key: "department", Value: "engineering"}}
	if len(updated.Status.CustomClaims) != 1 || updated.Status.CustomClaims[0] != want[0] {
		t.Errorf("status claims: got %v, want %v", updated.Status.CustomClaims, want)
	}
}

// A user with no claims must not keep a stale set in status after they are removed.
func TestUpdateUserStatus_ClearsCustomClaimsWhenNoneRemain(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	user := claimsUserCR(nil)
	user.Status.CustomClaims = []pocketidinternalv1alpha1.CustomClaim{{Key: "department", Value: "engineering"}}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&pocketidinternalv1alpha1.PocketIDUser{}).
		WithObjects(user).
		Build()
	r := &Reconciler{Client: fakeClient, APIReader: fakeClient, Scheme: scheme}

	if err := r.updateUserStatus(ctx, user, claimsCurrent(nil)); err != nil {
		t.Fatalf("updateUserStatus: %v", err)
	}

	updated := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updated); err != nil {
		t.Fatalf("get user: %v", err)
	}
	if len(updated.Status.CustomClaims) != 0 {
		t.Errorf("status claims: got %v, want none", updated.Status.CustomClaims)
	}
}
