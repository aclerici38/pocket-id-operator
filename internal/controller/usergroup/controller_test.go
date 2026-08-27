package usergroup

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

const testNamespace = "default"

func TestReconcileUserGroupFinalizers_AddOIDCClientFinalizer(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "finalizer-group",
			Namespace: testNamespace,
		},
	}

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "finalizer-oidc-client",
			Namespace: testNamespace,
		},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
				{Name: group.Name},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(group, oidcClient).
		Build()

	reconciler := &Reconciler{Client: fakeClient, Scheme: scheme}
	updated, err := reconciler.ReconcileUserGroupFinalizers(ctx, group)
	if err != nil {
		t.Fatalf("ReconcileUserGroupFinalizers returned error: %v", err)
	}
	if !updated {
		t.Error("expected updated to be true")
	}

	updatedGroup := &pocketidinternalv1alpha1.PocketIDUserGroup{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: group.Name, Namespace: group.Namespace}, updatedGroup); err != nil {
		t.Fatalf("failed to get updated group: %v", err)
	}

	hasUserGroupFinalizer := false
	hasOIDCClientFinalizer := false
	for _, f := range updatedGroup.Finalizers {
		if f == UserGroupFinalizer {
			hasUserGroupFinalizer = true
		}
		if f == OIDCClientUserGroupFinalizer {
			hasOIDCClientFinalizer = true
		}
	}
	if !hasUserGroupFinalizer {
		t.Error("expected UserGroupFinalizer to be present")
	}
	if !hasOIDCClientFinalizer {
		t.Error("expected OIDCClientUserGroupFinalizer to be present")
	}
}

func TestReconcileUserGroupFinalizers_RemoveOIDCClientFinalizer(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "finalizer-group-cleanup",
			Namespace:  testNamespace,
			Finalizers: []string{UserGroupFinalizer, OIDCClientUserGroupFinalizer},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(group).
		Build()

	reconciler := &Reconciler{Client: fakeClient, Scheme: scheme}
	updated, err := reconciler.ReconcileUserGroupFinalizers(ctx, group)
	if err != nil {
		t.Fatalf("ReconcileUserGroupFinalizers returned error: %v", err)
	}
	if !updated {
		t.Error("expected updated to be true")
	}

	updatedGroup := &pocketidinternalv1alpha1.PocketIDUserGroup{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: group.Name, Namespace: group.Namespace}, updatedGroup); err != nil {
		t.Fatalf("failed to get updated group: %v", err)
	}

	hasUserGroupFinalizer := false
	hasOIDCClientFinalizer := false
	for _, f := range updatedGroup.Finalizers {
		if f == UserGroupFinalizer {
			hasUserGroupFinalizer = true
		}
		if f == OIDCClientUserGroupFinalizer {
			hasOIDCClientFinalizer = true
		}
	}
	if !hasUserGroupFinalizer {
		t.Error("expected UserGroupFinalizer to be present")
	}
	if hasOIDCClientFinalizer {
		t.Error("expected OIDCClientUserGroupFinalizer to be removed")
	}
}

func TestReconcileDelete_BlockWhenReferencedByOIDCClient(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "finalizer-group-delete",
			Namespace:         testNamespace,
			Finalizers:        []string{UserGroupFinalizer},
			DeletionTimestamp: &now,
		},
	}

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "finalizer-oidc-client-delete",
			Namespace: testNamespace,
		},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
				{Name: group.Name},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(group, oidcClient).
		Build()

	reconciler := &Reconciler{Client: fakeClient, Scheme: scheme}
	result, err := reconciler.ReconcileDelete(ctx, group)
	if err != nil {
		t.Fatalf("ReconcileDelete returned error: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Error("expected RequeueAfter to be positive when blocked")
	}

	updatedGroup := &pocketidinternalv1alpha1.PocketIDUserGroup{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: group.Name, Namespace: group.Namespace}, updatedGroup); err != nil {
		t.Fatalf("failed to get updated group: %v", err)
	}

	// The group is already deleting here, so OIDCClientUserGroupFinalizer can no longer be added.
	hasUserGroupFinalizer := false
	for _, f := range updatedGroup.Finalizers {
		if f == UserGroupFinalizer {
			hasUserGroupFinalizer = true
			break
		}
	}
	if !hasUserGroupFinalizer {
		t.Error("expected UserGroupFinalizer to be retained so deletion stays blocked")
	}
}

func TestReconcileDelete_RemoveFinalizerWhenNoInstance(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "delete-no-instance-group",
			Namespace:  testNamespace,
			Finalizers: []string{UserGroupFinalizer},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{
			GroupID: "group-id",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(group).
		Build()

	reconciler := &Reconciler{Client: fakeClient, Scheme: scheme}
	_, err := reconciler.ReconcileDelete(ctx, group)
	if err != nil {
		t.Fatalf("ReconcileDelete returned error: %v", err)
	}

	updated := &pocketidinternalv1alpha1.PocketIDUserGroup{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: group.Name, Namespace: group.Namespace}, updated); err != nil {
		t.Fatalf("failed to get updated group: %v", err)
	}

	for _, f := range updated.Finalizers {
		if f == UserGroupFinalizer {
			t.Error("expected UserGroupFinalizer to be removed")
		}
	}
}

func TestReconcileDelete_KeepFinalizerWhenAPIClientNotReady(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "delete-instance",
			Namespace: testNamespace,
		},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
		},
	}

	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "delete-api-client-error-group",
			Namespace:  testNamespace,
			Finalizers: []string{UserGroupFinalizer},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{
			GroupID: "group-id",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(instance, group).
		Build()

	reconciler := &Reconciler{Client: fakeClient, Scheme: scheme}
	_, err := reconciler.ReconcileDelete(ctx, group)
	if err != nil {
		t.Fatalf("ReconcileDelete returned error: %v", err)
	}

	updated := &pocketidinternalv1alpha1.PocketIDUserGroup{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: group.Name, Namespace: group.Namespace}, updated); err != nil {
		t.Fatalf("failed to get updated group: %v", err)
	}

	found := false
	for _, f := range updated.Finalizers {
		if f == UserGroupFinalizer {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected UserGroupFinalizer to be kept")
	}
}

func TestReconcileUserGroupFinalizers_ExternalRefsDoNotCouple(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	// The CR is named "developers" and the client references a Pocket-ID group that
	// is also named "developers". They must stay decoupled: an external ref names a
	// group in Pocket-ID, never a CR, so it must not add the blocking finalizer.
	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "developers", Namespace: testNamespace},
	}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "external-only-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
				{GroupName: "developers"},
				{GroupID: "gid-developers"},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(group, oidcClient).
		Build()

	reconciler := &Reconciler{Client: fakeClient, Scheme: scheme}
	if _, err := reconciler.ReconcileUserGroupFinalizers(ctx, group); err != nil {
		t.Fatalf("ReconcileUserGroupFinalizers returned error: %v", err)
	}

	updatedGroup := &pocketidinternalv1alpha1.PocketIDUserGroup{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: group.Name, Namespace: group.Namespace}, updatedGroup); err != nil {
		t.Fatalf("failed to get updated group: %v", err)
	}
	for _, f := range updatedGroup.Finalizers {
		if f == OIDCClientUserGroupFinalizer {
			t.Error("expected no OIDCClientUserGroupFinalizer for an external-only reference")
		}
	}
}

func TestOIDCClientAllowsGroup_ExternalRefsNeverMatch(t *testing.T) {
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "client-a", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
				{GroupName: "developers"},
				{GroupID: "gid-dev"},
			},
		},
	}
	if oidcClientAllowsGroup(oidcClient, testNamespace, "developers") {
		t.Error("expected groupName not to match a CR of the same name")
	}
	if oidcClientAllowsGroup(oidcClient, testNamespace, "gid-dev") {
		t.Error("expected groupID not to match a CR of the same name")
	}
}

func TestOIDCClientAllowsGroup_MixedRefsMatchOnlyTheCRRef(t *testing.T) {
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "client-a", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
				{GroupName: "developers"},
				{Name: "local-admins"},
			},
		},
	}
	if !oidcClientAllowsGroup(oidcClient, testNamespace, "local-admins") {
		t.Error("expected the CR ref to match")
	}
	if oidcClientAllowsGroup(oidcClient, testNamespace, "developers") {
		t.Error("expected the external ref not to match")
	}
}

func TestOIDCClientAllowsGroup_CRRefRespectsNamespace(t *testing.T) {
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "client-a", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
				{Name: "admins", Namespace: "other"},
			},
		},
	}
	if !oidcClientAllowsGroup(oidcClient, "other", "admins") {
		t.Error("expected a match in the referenced namespace")
	}
	if oidcClientAllowsGroup(oidcClient, testNamespace, "admins") {
		t.Error("expected no match in the client's own namespace")
	}
}
