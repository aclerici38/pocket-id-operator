package user

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

// A user whose deletion is blocked still exists in Pocket-ID, so it must report
// Ready. Regression: the blocked branch used to return without touching status,
// freezing a stale Ready=False that propagated to every group referencing it.
func TestReconcileDelete_BlockedUserBecomesReady(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "blocked-user",
			Namespace:         "default",
			Finalizers:        []string{UserFinalizer, UserGroupUserFinalizer},
			DeletionTimestamp: &now,
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			UserID: "user-id",
			Conditions: []metav1.Condition{{
				Type:               "Ready",
				Status:             metav1.ConditionFalse,
				Reason:             "InstanceNotReady",
				LastTransitionTime: now,
			}},
		},
	}
	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group", Namespace: "default"},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			Users: &pocketidinternalv1alpha1.UserGroupUsers{
				UserRefs: []pocketidinternalv1alpha1.NamespacedUserReference{
					{Name: user.Name, Namespace: user.Namespace},
				},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user, group).
		WithStatusSubresource(user).
		Build()

	r := &Reconciler{Client: c, APIReader: c, Scheme: scheme}
	result, err := r.ReconcileDelete(context.Background(), user)
	if err != nil {
		t.Fatalf("ReconcileDelete returned error: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("expected requeue while blocked, got %s", result.RequeueAfter)
	}

	updated := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updated); err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	ready := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
	if ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("expected Ready=True while deletion is blocked, got %+v", ready)
	}
	if ready.Reason != "DeletionBlocked" {
		t.Fatalf("expected reason DeletionBlocked, got %q", ready.Reason)
	}
	if !containsFinalizer(updated.Finalizers, UserGroupUserFinalizer) {
		t.Fatalf("expected blocking finalizer to remain, got %v", updated.Finalizers)
	}
}
