package api

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

// An API whose deletion is blocked still exists in Pocket-ID, so it must report
// Ready or the OIDC clients granted access to it stop reconciling.
func TestReconcileDelete_BlockedAPIBecomesReady(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	api := &pocketidinternalv1alpha1.PocketIDAPI{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "blocked-api",
			Namespace:         "default",
			Finalizers:        []string{APIFinalizer, OIDCClientAPIFinalizer},
			DeletionTimestamp: &now,
		},
		Status: pocketidinternalv1alpha1.PocketIDAPIStatus{
			APIID: "api-id",
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
			APIAccess: []pocketidinternalv1alpha1.OIDCClientAPIAccess{
				{APIRef: pocketidinternalv1alpha1.NamespacedAPIReference{Name: api.Name, Namespace: api.Namespace}},
			},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(api, oidcClient).
		WithStatusSubresource(api).
		Build()

	r := &Reconciler{Client: c, APIReader: c, Scheme: scheme}
	result, err := r.ReconcileDelete(context.Background(), api)
	if err != nil {
		t.Fatalf("ReconcileDelete returned error: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("expected requeue while blocked, got %s", result.RequeueAfter)
	}

	updated := &pocketidinternalv1alpha1.PocketIDAPI{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: api.Name, Namespace: api.Namespace}, updated); err != nil {
		t.Fatalf("failed to get updated API: %v", err)
	}
	ready := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
	if ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("expected Ready=True while deletion is blocked, got %+v", ready)
	}
	if ready.Reason != "DeletionBlocked" {
		t.Fatalf("expected reason DeletionBlocked, got %q", ready.Reason)
	}
}
