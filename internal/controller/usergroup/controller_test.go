package usergroup

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

	hasOIDCClientFinalizer := false
	for _, f := range updatedGroup.Finalizers {
		if f == OIDCClientUserGroupFinalizer {
			hasOIDCClientFinalizer = true
			break
		}
	}
	if !hasOIDCClientFinalizer {
		t.Error("expected OIDCClientUserGroupFinalizer to be added when blocked")
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
			EncryptionKey: pocketidinternalv1alpha1.EnvValue{Value: "0123456789abcdef"},
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

func newAggregationFakeClient(scheme *runtime.Scheme, objs ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithIndex(&pocketidinternalv1alpha1.PocketIDOIDCClient{}, "pocketidoidcclient.allowedGroup", func(raw client.Object) []string {
			oc := raw.(*pocketidinternalv1alpha1.PocketIDOIDCClient)
			var keys []string
			for _, ref := range oc.Spec.AllowedUserGroups {
				if ref.Name == "" {
					continue
				}
				ns := ref.Namespace
				if ns == "" {
					ns = oc.Namespace
				}
				keys = append(keys, ns+"/"+ref.Name)
			}
			return keys
		}).
		Build()
}

func readyCondition() []metav1.Condition {
	return []metav1.Condition{{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Reconciled",
		LastTransitionTime: metav1.Now(),
	}}
}

func TestAggregateAllowedOIDCClientIDs_DirectOnly(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "client-a", Namespace: testNamespace},
		Status:     pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "cid-a", Conditions: readyCondition()},
	}
	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group-1", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			AllowedOIDCClients: []pocketidinternalv1alpha1.NamespacedOIDCClientReference{{Name: "client-a"}},
		},
	}

	fc := newAggregationFakeClient(scheme, oidcClient, group)
	reconciler := &Reconciler{Client: fc, Scheme: scheme}

	ids, err := reconciler.aggregateAllowedOIDCClientIDs(ctx, group)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 1 || ids[0] != "cid-a" {
		t.Errorf("expected [cid-a], got %v", ids)
	}
}

func TestAggregateAllowedOIDCClientIDs_ReverseOnly(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "client-b", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{{Name: "group-2"}},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "cid-b", Conditions: readyCondition()},
	}
	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group-2", Namespace: testNamespace},
	}

	fc := newAggregationFakeClient(scheme, oidcClient, group)
	reconciler := &Reconciler{Client: fc, Scheme: scheme}

	ids, err := reconciler.aggregateAllowedOIDCClientIDs(ctx, group)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 1 || ids[0] != "cid-b" {
		t.Errorf("expected [cid-b], got %v", ids)
	}
}

func TestAggregateAllowedOIDCClientIDs_Union(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	clientA := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "client-a", Namespace: testNamespace},
		Status:     pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "cid-a", Conditions: readyCondition()},
	}
	clientB := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "client-b", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{{Name: "group-3"}},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "cid-b", Conditions: readyCondition()},
	}
	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group-3", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			AllowedOIDCClients: []pocketidinternalv1alpha1.NamespacedOIDCClientReference{{Name: "client-a"}},
		},
	}

	fc := newAggregationFakeClient(scheme, clientA, clientB, group)
	reconciler := &Reconciler{Client: fc, Scheme: scheme}

	ids, err := reconciler.aggregateAllowedOIDCClientIDs(ctx, group)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 IDs, got %v", ids)
	}
	idSet := map[string]bool{}
	for _, id := range ids {
		idSet[id] = true
	}
	if !idSet["cid-a"] || !idSet["cid-b"] {
		t.Errorf("expected {cid-a, cid-b}, got %v", ids)
	}
}

func TestAggregateAllowedOIDCClientIDs_SkipsNotReady(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "client-nr", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{{Name: "group-4"}},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "cid-nr"},
	}
	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group-4", Namespace: testNamespace},
	}

	fc := newAggregationFakeClient(scheme, oidcClient, group)
	reconciler := &Reconciler{Client: fc, Scheme: scheme}

	ids, err := reconciler.aggregateAllowedOIDCClientIDs(ctx, group)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected empty (not-ready client skipped), got %v", ids)
	}
}

func TestAggregateAllowedOIDCClientIDs_NilWhenNoRefs(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group-5", Namespace: testNamespace},
	}

	fc := newAggregationFakeClient(scheme, group)
	reconciler := &Reconciler{Client: fc, Scheme: scheme}

	ids, err := reconciler.aggregateAllowedOIDCClientIDs(ctx, group)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ids != nil {
		t.Errorf("expected nil when no refs from either side, got %v", ids)
	}
}
