package usergroup

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

// A group whose deletion is blocked still exists in Pocket-ID, so it must report
// Ready. Regression: the blocked branch used to return without touching status,
// freezing a stale Ready=False and breaking every OIDC client that referenced it.
func TestReconcileDelete_BlockedGroupBecomesReady(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "blocked-group",
			Namespace:         "default",
			Finalizers:        []string{UserGroupFinalizer, OIDCClientUserGroupFinalizer},
			DeletionTimestamp: &now,
		},
		Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{
			GroupID: "group-id",
			Conditions: []metav1.Condition{{
				Type:               "Ready",
				Status:             metav1.ConditionFalse,
				Reason:             "InstanceNotReady",
				LastTransitionTime: now,
			}},
		},
	}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "default"},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
				{Name: group.Name, Namespace: group.Namespace},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(group, oidcClient).
		WithStatusSubresource(group).
		Build()

	r := &Reconciler{Client: c, APIReader: c, Scheme: scheme}
	result, err := r.ReconcileDelete(context.Background(), group)
	if err != nil {
		t.Fatalf("ReconcileDelete returned error: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("expected requeue while blocked, got %s", result.RequeueAfter)
	}

	updated := &pocketidinternalv1alpha1.PocketIDUserGroup{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: group.Name, Namespace: group.Namespace}, updated); err != nil {
		t.Fatalf("failed to get updated group: %v", err)
	}
	ready := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
	if ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("expected Ready=True while deletion is blocked, got %+v", ready)
	}
	if ready.Reason != "DeletionBlocked" {
		t.Fatalf("expected reason DeletionBlocked, got %q", ready.Reason)
	}
	if !containsString(updated.Finalizers, OIDCClientUserGroupFinalizer) {
		t.Fatalf("expected blocking finalizer to remain, got %v", updated.Finalizers)
	}
}

// Once nothing references the group the delete must proceed rather than parking
// it on DeletionBlocked forever.
func TestReconcileDelete_UnreferencedGroupIsNotBlocked(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "unreferenced-group",
			Namespace:         "default",
			Finalizers:        []string{UserGroupFinalizer, OIDCClientUserGroupFinalizer},
			DeletionTimestamp: &now,
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(group).
		WithStatusSubresource(group).
		Build()

	r := &Reconciler{Client: c, APIReader: c, Scheme: scheme}
	if _, err := r.ReconcileDelete(context.Background(), group); err != nil {
		t.Fatalf("ReconcileDelete returned error: %v", err)
	}

	updated := &pocketidinternalv1alpha1.PocketIDUserGroup{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: group.Name, Namespace: group.Namespace}, updated); err != nil {
		t.Fatalf("failed to get updated group: %v", err)
	}
	if containsString(updated.Finalizers, OIDCClientUserGroupFinalizer) {
		t.Fatalf("expected blocking finalizer to be dropped, got %v", updated.Finalizers)
	}
	if ready := meta.FindStatusCondition(updated.Status.Conditions, "Ready"); ready != nil && ready.Reason == "DeletionBlocked" {
		t.Fatal("unreferenced group must not be marked DeletionBlocked")
	}
}

func containsString(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
