package common

import (
	"context"
	"errors"
	"net/http"
	"testing"

	runtimeclient "github.com/go-openapi/runtime"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const testFinalizer = "pocketid.internal/test-finalizer"

func deleteScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1 to scheme: %v", err)
	}
	if err := pocketidinternalv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add pocketid to scheme: %v", err)
	}
	return scheme
}

// deletingUserGroup is mid-deletion, still carrying the finalizer and a Pocket-ID ID.
func deletingUserGroup() *pocketidinternalv1alpha1.PocketIDUserGroup {
	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "group",
			Namespace:  "pocket-id",
			Finalizers: []string{testFinalizer},
		},
	}
	group.Status.GroupID = "group-id"
	return group
}

// deleteReconciler wires a reconciler against a fake cluster holding the resource, one
// external instance, and the Secret its API key comes from.
func deleteReconciler(t *testing.T, obj client.Object) (*BaseReconciler, client.Client) {
	t.Helper()
	instance := externalInstance("admin-token", "token")
	secret := apiKeySecret("pocket-id", "admin-token", "token", "key")

	k8s := fake.NewClientBuilder().
		WithScheme(deleteScheme(t)).
		WithObjects(obj, instance, secret).
		Build()

	return &BaseReconciler{Client: k8s, APIReader: k8s}, k8s
}

// A resource whose Pocket-ID counterpart is already gone must still finish terminating.
func TestReconcileDeleteWithPocketID_TolerantOfMissingResource(t *testing.T) {
	group := deletingUserGroup()
	reconciler, k8s := deleteReconciler(t, group)

	notFound := runtimeclient.NewAPIError("DeleteAPIUserGroupsID", nil, http.StatusNotFound)
	called := false
	result, err := reconciler.ReconcileDeleteWithPocketID(
		context.Background(), group, group.Status.GroupID, nil, testFinalizer,
		func(context.Context, *pocketid.Client, string) error {
			called = true
			return notFound
		},
	)
	if err != nil {
		t.Fatalf("ReconcileDeleteWithPocketID: %v", err)
	}
	if !called {
		t.Fatal("the delete never reached Pocket-ID, so this proves nothing about a 404")
	}
	if result != (ctrl.Result{}) {
		t.Errorf("result: got %+v, want no requeue", result)
	}

	stored := &pocketidinternalv1alpha1.PocketIDUserGroup{}
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(group), stored); err != nil {
		t.Fatalf("get user group: %v", err)
	}
	if controllerutil.ContainsFinalizer(stored, testFinalizer) {
		t.Error("finalizer still present after deleting an already-absent resource")
	}
}

// Any other failure keeps the finalizer, or the object is left behind in Pocket-ID.
func TestReconcileDeleteWithPocketID_KeepsFinalizerOnRealFailure(t *testing.T) {
	group := deletingUserGroup()
	reconciler, k8s := deleteReconciler(t, group)

	serverError := runtimeclient.NewAPIError("DeleteAPIUserGroupsID", nil, http.StatusInternalServerError)
	_, err := reconciler.ReconcileDeleteWithPocketID(
		context.Background(), group, group.Status.GroupID, nil, testFinalizer,
		func(context.Context, *pocketid.Client, string) error { return serverError },
	)
	if err == nil {
		t.Fatal("ReconcileDeleteWithPocketID: expected the delete failure to surface")
	}

	stored := &pocketidinternalv1alpha1.PocketIDUserGroup{}
	if err := k8s.Get(context.Background(), client.ObjectKeyFromObject(group), stored); err != nil {
		t.Fatalf("get user group: %v", err)
	}
	if !controllerutil.ContainsFinalizer(stored, testFinalizer) {
		t.Error("finalizer removed even though the delete failed")
	}
}

func TestRequeueAfterFor(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "plain failure", err: errors.New("boom"), want: "standard"},
		{name: "not found", err: runtimeclient.NewAPIError("op", nil, http.StatusNotFound), want: "standard"},
		{name: "throttled without a delay", err: runtimeclient.NewAPIError("op", nil, http.StatusTooManyRequests), want: "standard"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := RequeueAfterFor(test.err); got != Requeue {
				t.Errorf("RequeueAfterFor: got %v, want %v", got, Requeue)
			}
		})
	}
}

// A Retry-After above the standard delay is honored, and an excessive one is capped.
func TestRequeueAfterFor_HonorsRetryAfter(t *testing.T) {
	throttled := &pocketid.APIError{
		StatusCode: http.StatusTooManyRequests,
		Code:       "rate_limited",
		RetryAfter: 30 * Requeue,
	}
	if got := RequeueAfterFor(throttled); got != 30*Requeue {
		t.Errorf("RequeueAfterFor: got %v, want %v", got, 30*Requeue)
	}

	throttled.RetryAfter = 2 * MaxRateLimitRequeue
	if got := RequeueAfterFor(throttled); got != MaxRateLimitRequeue {
		t.Errorf("RequeueAfterFor: got %v, want the cap %v", got, MaxRateLimitRequeue)
	}
}
