package user

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// A field left out of a PATCH keeps its value in Pocket-ID, so every managed field has to be
// sent every time, empty ones included. emailVerified, userGroupIds and id are left to Pocket-ID.
func TestUserPatch(t *testing.T) {
	full := &pocketidinternalv1alpha1.PocketIDUser{Spec: pocketidinternalv1alpha1.PocketIDUserSpec{Admin: true, Disabled: true, Locale: "de"}}
	tests := map[string]struct {
		user  *pocketidinternalv1alpha1.PocketIDUser
		input userInput
		want  map[string]any
	}{
		"every field set": {
			user:  full,
			input: userInput{username: "alice", firstName: "Alice", lastName: "Smith", email: "alice@example.com", displayName: "Alice Smith"},
			want: map[string]any{
				"username": "alice", "firstName": "Alice", "lastName": "Smith", "email": "alice@example.com",
				"displayName": "Alice Smith", "isAdmin": true, "disabled": true, "locale": "de",
			},
		},
		// An empty email collides on the unique index, so it goes out as null, like locale.
		"every field empty": {
			user: &pocketidinternalv1alpha1.PocketIDUser{},
			want: map[string]any{
				"username": "", "firstName": "", "lastName": "", "email": nil,
				"displayName": "", "isAdmin": false, "disabled": false, "locale": nil,
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(userPatch(tt.user, tt.input))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got map[string]any
			_ = json.Unmarshal(raw, &got)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("patch = %v\nwant    %v", got, tt.want)
			}
		})
	}
}

// An unset email stays empty, so it goes out as null and Pocket-ID's REQUIRE_USER_EMAIL is
// enforced rather than worked around with a made-up address.
func TestBuildUserInputLeavesEmailUnset(t *testing.T) {
	fc := fake.NewClientBuilder().WithScheme(userTestScheme()).Build()
	user := &pocketidinternalv1alpha1.PocketIDUser{ObjectMeta: metav1.ObjectMeta{Name: "alice", Namespace: "default"}}
	input, err := (&Reconciler{Client: fc, APIReader: fc}).buildUserInput(context.Background(), user)
	if err != nil {
		t.Fatalf("buildUserInput: %v", err)
	}
	if input.email != "" {
		t.Errorf("email = %q, want empty", input.email)
	}
}

func TestPushUserState(t *testing.T) {
	tests := []struct {
		name       string
		users      []map[string]any
		claims     []pocketidinternalv1alpha1.CustomClaim
		wantCalls  []string
		wantClaims string
		wantErr    func(error) bool
	}{
		{
			name:       "writes the profile and the full set of claims",
			users:      []map[string]any{pocketIDUser("uid", "old-name", "old@example.com")},
			claims:     []pocketidinternalv1alpha1.CustomClaim{{Key: "team", Value: "infra"}},
			wantCalls:  []string{"patch uid", "claims uid"},
			wantClaims: `[{"key":"team","value":"infra"}]`,
		},
		// The endpoint replaces the full set, so no claims has to be sent as [] to clear them.
		{
			name:       "clears claims the spec no longer has",
			users:      []map[string]any{pocketIDUser("uid", "alice", "alice@example.com")},
			wantCalls:  []string{"patch uid", "claims uid"},
			wantClaims: `[]`,
		},
		{
			name:      "a user deleted outside the operator reads as not found",
			wantCalls: []string{"patch uid"},
			wantErr:   pocketid.IsNotFoundError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{Name: "alice", Namespace: "default"},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					Email:        pocketidinternalv1alpha1.StringValue{Value: "alice@example.com"},
					CustomClaims: tt.claims,
				},
				Status: pocketidinternalv1alpha1.PocketIDUserStatus{UserID: "uid"},
			}
			fc := fake.NewClientBuilder().WithScheme(userTestScheme()).Build()
			f := &fakeUsers{users: tt.users}

			got, err := (&Reconciler{Client: fc, APIReader: fc}).pushUserState(context.Background(), user, f.client(t))
			if tt.wantErr != nil {
				if !tt.wantErr(err) {
					t.Fatalf("error = %v", err)
				}
			} else if err != nil {
				t.Fatalf("pushUserState: %v", err)
			}
			if !slices.Equal(f.calls, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", f.calls, tt.wantCalls)
			}
			if tt.wantErr != nil {
				return
			}
			if f.claimsBody[0] != tt.wantClaims {
				t.Errorf("claims body = %s, want %s", f.claimsBody[0], tt.wantClaims)
			}
			// Status comes from the responses: the profile from the PATCH, the claims from their PUT.
			if got.Username != "alice" || len(got.CustomClaims) != len(tt.claims) {
				t.Errorf("returned user = %+v", got)
			}
		})
	}
}

// externalInstance returns a Ready instance adopting the Pocket-ID served by handler, and the
// Secret holding its API key.
func externalInstance(t *testing.T, handler http.Handler) []client.Object {
	ts := httptest.NewTestServer(t, handler)
	ts.Start()
	return []client.Object{
		&pocketidinternalv1alpha1.PocketIDInstance{
			ObjectMeta: metav1.ObjectMeta{Name: "instance", Namespace: "default"},
			Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{External: &pocketidinternalv1alpha1.ExternalInstanceConfig{
				URL: ts.URL,
				APIKeySecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "admin-token"}, Key: "token",
				},
			}},
			Status: pocketidinternalv1alpha1.PocketIDInstanceStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}}},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "admin-token", Namespace: "default"},
			Data:       map[string][]byte{"token": []byte("key")},
		},
	}
}

// A PATCH answering 404 means the user was deleted outside the operator, so status is cleared
// for the next reconcile to recreate it.
func TestReconcile_UserDeletedExternally(t *testing.T) {
	ctx := context.Background()
	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{Name: "alice", Namespace: "default", Finalizers: []string{UserFinalizer}},
		Status:     pocketidinternalv1alpha1.PocketIDUserStatus{UserID: "gone"},
	}
	f := &fakeUsers{}
	objs := append(externalInstance(t, f.handler()), user)
	fc := fake.NewClientBuilder().WithScheme(userTestScheme()).WithObjects(objs...).WithStatusSubresource(objs...).Build()
	r := &Reconciler{Client: fc, BaseReconciler: common.BaseReconciler{Client: fc, APIReader: fc}, APIReader: fc, Scheme: userTestScheme()}

	result, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(user)})
	if err != nil || result.RequeueAfter != common.RequeueImmediate {
		t.Fatalf("Reconcile = %+v, %v; want an immediate requeue", result, err)
	}
	if !slices.Equal(f.calls, []string{"patch gone"}) {
		t.Errorf("calls = %v, want only the PATCH", f.calls)
	}
	latest := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := fc.Get(ctx, client.ObjectKeyFromObject(user), latest); err != nil {
		t.Fatalf("get user: %v", err)
	}
	if latest.Status.UserID != "" {
		t.Errorf("status.userID = %q, want it cleared", latest.Status.UserID)
	}
}

func TestUpdateUserStatus(t *testing.T) {
	ctx := context.Background()
	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{Name: "alice", Namespace: "default"},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			CustomClaims: []pocketidinternalv1alpha1.CustomClaim{{Key: "stale", Value: "x"}},
		},
	}
	fc := fake.NewClientBuilder().WithScheme(userTestScheme()).WithObjects(user).WithStatusSubresource(user).Build()
	r := &Reconciler{Client: fc, APIReader: fc, Scheme: userTestScheme()}

	pUser := pid.UserDto{
		ID: "uid", Username: "alice", FirstName: "Alice", Email: "alice@example.com", DisplayName: "Alice",
		IsAdmin: true, Locale: "de", EmailVerified: true,
		CustomClaims: []pid.CustomClaimDto{{Key: "team", Value: "infra"}, {Key: "dept", Value: "eng"}},
	}
	if err := r.updateUserStatus(ctx, user, pUser); err != nil {
		t.Fatalf("updateUserStatus: %v", err)
	}

	latest := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := fc.Get(ctx, client.ObjectKeyFromObject(user), latest); err != nil {
		t.Fatalf("get user: %v", err)
	}
	status := latest.Status
	if status.UserID != "uid" || !status.IsAdmin || status.Locale != "de" || !status.EmailVerified {
		t.Errorf("status = %+v", status)
	}
	// Pocket-ID returns claims unordered, so status sorts them to stay stable.
	wantClaims := []pocketidinternalv1alpha1.CustomClaim{{Key: "dept", Value: "eng"}, {Key: "team", Value: "infra"}}
	if !reflect.DeepEqual(status.CustomClaims, wantClaims) {
		t.Errorf("status.customClaims = %v, want %v", status.CustomClaims, wantClaims)
	}

	secret := &corev1.Secret{}
	if err := fc.Get(ctx, types.NamespacedName{Name: status.UserInfoSecretName, Namespace: "default"}, secret); err != nil {
		t.Fatalf("get user info secret: %v", err)
	}
	if got := string(secret.Data[UserInfoSecretKeyEmail]); got != "alice@example.com" {
		t.Errorf("user info email = %q", got)
	}
}
