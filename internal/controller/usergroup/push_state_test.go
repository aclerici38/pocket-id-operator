package usergroup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const groupID = "gid"

func existingGroup() []map[string]any {
	return []map[string]any{{"id": groupID, "name": "old-name", "friendlyName": "Old", "notes": "kept"}}
}

// A field left out of a PATCH keeps its value in Pocket-ID, so every field is sent every time.
func TestPushUserGroupState_Patch(t *testing.T) {
	tests := map[string]struct {
		spec pocketidinternalv1alpha1.PocketIDUserGroupSpec
		want map[string]any
	}{
		"every field set": {
			spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{Name: "spec-name", FriendlyName: "Spec Friendly", Notes: "Spec notes"},
			want: map[string]any{"name": "spec-name", "friendlyName": "Spec Friendly", "notes": "Spec notes"},
		},
		// Both names fall back to metadata.name, so neither is ever sent empty.
		"every field empty": {
			want: map[string]any{"name": "resource-name", "friendlyName": "resource-name", "notes": ""},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "resource-name", Namespace: testNamespace},
				Spec:       tt.spec,
				Status:     pocketidinternalv1alpha1.PocketIDUserGroupStatus{GroupID: groupID},
			}
			f := &fakeGroups{groups: existingGroup()}
			if _, err := (&Reconciler{}).pushUserGroupState(context.Background(), group, f.client(t)); err != nil {
				t.Fatalf("pushUserGroupState: %v", err)
			}
			if !reflect.DeepEqual(f.patches, []map[string]any{tt.want}) {
				t.Errorf("patches = %v, want %v", f.patches, tt.want)
			}
		})
	}
}

func TestPushUserGroupState(t *testing.T) {
	tests := []struct {
		name        string
		groups      []map[string]any
		claims      []pocketidinternalv1alpha1.CustomClaim
		users       *pocketidinternalv1alpha1.UserGroupUsers
		wantCalls   []string
		wantClaims  string
		wantMembers string
		wantErr     func(error) bool
	}{
		// The endpoint replaces the full set, so no claims has to be sent as [] to clear them.
		{name: "clears claims and leaves members alone while spec.users is unset", groups: existingGroup(),
			wantCalls: []string{"patch", "claims"}, wantClaims: `[]`},
		{name: "writes the full set of claims", groups: existingGroup(),
			claims:     []pocketidinternalv1alpha1.CustomClaim{{Key: "team", Value: "infra"}},
			wantCalls:  []string{"patch", "claims"},
			wantClaims: `[{"key":"team","value":"infra"}]`},
		// Members added outside the operator are removed once it owns the list.
		{name: "writes the full member list, sorted and deduplicated", groups: existingGroup(),
			users:     &pocketidinternalv1alpha1.UserGroupUsers{UserIDs: []string{"uid-c", "uid-a", "uid-a"}, Usernames: []string{"bob"}},
			wantCalls: []string{"list users bob", "patch", "claims", "members"}, wantClaims: `[]`,
			wantMembers: `{"userIds":["uid-a","uid-bob","uid-c"]}`},
		{name: "clears members when spec.users lists none", groups: existingGroup(),
			users:     &pocketidinternalv1alpha1.UserGroupUsers{},
			wantCalls: []string{"patch", "claims", "members"}, wantClaims: `[]`, wantMembers: `{"userIds":[]}`},
		{name: "a group deleted outside the operator reads as not found",
			wantCalls: []string{"patch"}, wantErr: pocketid.IsNotFoundError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "group", Namespace: testNamespace},
				Spec:       pocketidinternalv1alpha1.PocketIDUserGroupSpec{CustomClaims: tt.claims, Users: tt.users},
				Status:     pocketidinternalv1alpha1.PocketIDUserGroupStatus{GroupID: groupID},
			}
			f := &fakeGroups{groups: tt.groups, users: []map[string]any{{"id": "uid-bob", "username": "bob"}}}

			got, err := (&Reconciler{}).pushUserGroupState(context.Background(), group, f.client(t))
			if tt.wantErr != nil {
				if !tt.wantErr(err) {
					t.Fatalf("error = %v", err)
				}
			} else if err != nil {
				t.Fatalf("pushUserGroupState: %v", err)
			}
			if !slices.Equal(f.calls, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", f.calls, tt.wantCalls)
			}
			if tt.wantErr != nil {
				return
			}
			if f.bodies["claims"] != tt.wantClaims {
				t.Errorf("claims body = %s, want %s", f.bodies["claims"], tt.wantClaims)
			}
			if f.bodies["members"] != tt.wantMembers {
				t.Errorf("members body = %s, want %s", f.bodies["members"], tt.wantMembers)
			}
			// Status comes from the last response.
			if got.Name != "group" || len(got.CustomClaims) != len(tt.claims) {
				t.Errorf("returned group = %+v", got)
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
			ObjectMeta: metav1.ObjectMeta{Name: "instance", Namespace: testNamespace},
			Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{External: &pocketidinternalv1alpha1.ExternalInstanceConfig{
				URL: ts.URL,
				APIKeySecretRef: corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "admin-token"}, Key: "token",
				},
			}},
			Status: pocketidinternalv1alpha1.PocketIDInstanceStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}}},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "admin-token", Namespace: testNamespace},
			Data:       map[string][]byte{"token": []byte("key")},
		},
	}
}

func TestReconcile(t *testing.T) {
	tests := []struct {
		name    string
		groups  []map[string]any
		allowed []pocketidinternalv1alpha1.NamespacedOIDCClientReference
		// wantResult left zero expects the jittered resync.
		wantResult    ctrl.Result
		wantGroupID   string
		wantReady     metav1.ConditionStatus
		wantCalls     []string
		wantFriendly  string
		wantReadyText string
	}{
		{name: "writes the spec and reports Ready", groups: existingGroup(),
			wantGroupID: groupID, wantReady: metav1.ConditionTrue,
			wantCalls: []string{"patch", "claims"}, wantFriendly: "group"},
		// A PATCH answering 404 means the group was deleted outside the operator, so status is
		// cleared for the next reconcile to recreate it.
		{name: "clears status when the group was deleted outside the operator",
			wantResult: ctrl.Result{RequeueAfter: common.RequeueImmediate}, wantCalls: []string{"patch"}},
		// The relationship is only checked here, after the group's own state was written.
		{name: "is not Ready while a referenced OIDC client is missing", groups: existingGroup(),
			allowed:    []pocketidinternalv1alpha1.NamespacedOIDCClientReference{{Name: "missing"}},
			wantResult: ctrl.Result{RequeueAfter: common.Requeue}, wantGroupID: groupID, wantReady: metav1.ConditionFalse,
			wantCalls: []string{"patch", "claims"}, wantFriendly: "group"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "group", Namespace: testNamespace, Finalizers: []string{UserGroupFinalizer}},
				Spec:       pocketidinternalv1alpha1.PocketIDUserGroupSpec{AllowedOIDCClients: tt.allowed},
				Status:     pocketidinternalv1alpha1.PocketIDUserGroupStatus{GroupID: groupID},
			}
			f := &fakeGroups{groups: tt.groups}
			objs := append(externalInstance(t, f.handler()), group)
			fc := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(objs...).WithStatusSubresource(objs...).Build()
			r := &Reconciler{Client: fc, BaseReconciler: common.BaseReconciler{Client: fc, APIReader: fc}, APIReader: fc}

			result, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(group)})
			resynced := tt.wantResult == (ctrl.Result{}) && result.RequeueAfter > 0
			if err != nil || (result != tt.wantResult && !resynced) {
				t.Fatalf("Reconcile = %+v, %v; want %+v", result, err, tt.wantResult)
			}
			if !slices.Equal(f.calls, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", f.calls, tt.wantCalls)
			}
			latest := &pocketidinternalv1alpha1.PocketIDUserGroup{}
			if err := fc.Get(ctx, client.ObjectKeyFromObject(group), latest); err != nil {
				t.Fatalf("get group: %v", err)
			}
			if latest.Status.GroupID != tt.wantGroupID || latest.Status.FriendlyName != tt.wantFriendly {
				t.Errorf("status = %+v", latest.Status)
			}
			if tt.wantReady != "" {
				if ready := meta.FindStatusCondition(latest.Status.Conditions, "Ready"); ready == nil || ready.Status != tt.wantReady {
					t.Errorf("Ready = %+v, want %s", ready, tt.wantReady)
				}
			}
		})
	}
}

func TestUpdateUserGroupStatus(t *testing.T) {
	ctx := context.Background()
	group := &pocketidinternalv1alpha1.PocketIDUserGroup{ObjectMeta: metav1.ObjectMeta{Name: "group", Namespace: testNamespace}}
	fc := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(group).WithStatusSubresource(group).Build()

	createdAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	current := pid.UserGroupDto{
		ID: groupID, Name: "name", FriendlyName: "Friendly", LDAPID: "ldap", CreatedAt: createdAt,
		Users:              []pid.UserDto{{ID: "a"}, {ID: "b"}},
		CustomClaims:       []pid.CustomClaimDto{{Key: "z", Value: "1"}, {Key: "a", Value: "2"}},
		AllowedOIDCClients: []pid.OIDCClientMetaDataDto{{ID: "client-b"}, {ID: "client-a"}},
	}
	if err := (&Reconciler{Client: fc}).updateUserGroupStatus(ctx, group, current); err != nil {
		t.Fatalf("updateUserGroupStatus: %v", err)
	}

	latest := &pocketidinternalv1alpha1.PocketIDUserGroup{}
	if err := fc.Get(ctx, client.ObjectKeyFromObject(group), latest); err != nil {
		t.Fatalf("get group: %v", err)
	}
	// Pocket-ID returns relations unordered, so status sorts them to stay stable.
	want := pocketidinternalv1alpha1.PocketIDUserGroupStatus{
		GroupID: groupID, Name: "name", FriendlyName: "Friendly", LdapID: "ldap",
		CreatedAt:            createdAt.Format(time.RFC3339),
		TotalUserCount:       2,
		CustomClaims:         []pocketidinternalv1alpha1.CustomClaim{{Key: "a", Value: "2"}, {Key: "z", Value: "1"}},
		AllowedOIDCClientIDs: []string{"client-a", "client-b"},
	}
	if !reflect.DeepEqual(latest.Status, want) {
		t.Errorf("status = %+v\nwant     %+v", latest.Status, want)
	}
}
