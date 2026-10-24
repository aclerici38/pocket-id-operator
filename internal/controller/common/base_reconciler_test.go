package common

import (
	"context"
	"errors"
	"net/http"
	"testing"

	runtimeclient "github.com/go-openapi/runtime"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
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

// statusPatchCountingClient wires a fake cluster holding obj and counts status patches sent to it.
func statusPatchCountingClient(t *testing.T, obj client.Object) (client.Client, *int) {
	t.Helper()
	patches := 0
	k8s := fake.NewClientBuilder().
		WithScheme(deleteScheme(t)).
		WithObjects(obj).
		WithStatusSubresource(obj).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, c client.Client, subResourceName string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				patches++
				return c.Status().Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()
	return k8s, &patches
}

// An unchanged status must not reach the API server; a changed or cleared one must.
func TestPatchStatus_SkipsEmptyPatch(t *testing.T) {
	group := deletingUserGroup()
	k8s, patches := statusPatchCountingClient(t, group)
	ctx := context.Background()
	stored := &pocketidinternalv1alpha1.PocketIDUserGroup{}

	if err := PatchStatus(ctx, k8s, group, group.DeepCopy()); err != nil {
		t.Fatalf("unchanged patch: %v", err)
	}
	if *patches != 0 {
		t.Fatalf("unchanged status sent %d patches, want 0", *patches)
	}

	base := group.DeepCopy()
	group.Status.GroupID = "new-id"
	if err := PatchStatus(ctx, k8s, group, base); err != nil {
		t.Fatalf("changed patch: %v", err)
	}
	if *patches != 1 {
		t.Fatalf("changed status sent %d patches, want 1", *patches)
	}
	if err := k8s.Get(ctx, client.ObjectKeyFromObject(group), stored); err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.Status.GroupID != "new-id" {
		t.Fatalf("stored GroupID = %q, want %q", stored.Status.GroupID, "new-id")
	}

	// Clearing a field drives recreation, so the null it produces must still be sent.
	r := &BaseReconciler{Client: k8s}
	if err := r.ClearStatusField(ctx, group, func() { group.Status.GroupID = "" }); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if *patches != 2 {
		t.Fatalf("cleared status sent %d patches, want 2", *patches)
	}
	if err := k8s.Get(ctx, client.ObjectKeyFromObject(group), stored); err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.Status.GroupID != "" {
		t.Fatalf("stored GroupID = %q, want it cleared", stored.Status.GroupID)
	}
}

// A repeated Ready condition is skipped, but a generation bump with the same status must
// still persist the new observedGeneration.
func TestSetReadyCondition_SkipsUnchanged(t *testing.T) {
	group := deletingUserGroup()
	group.Generation = 1
	k8s, patches := statusPatchCountingClient(t, group)
	r := &BaseReconciler{Client: k8s}
	ctx := context.Background()

	for range 2 {
		if err := r.SetReadyCondition(ctx, group, metav1.ConditionTrue, "Reconciled", "in sync"); err != nil {
			t.Fatalf("set ready: %v", err)
		}
	}
	if *patches != 1 {
		t.Fatalf("repeated Ready sent %d patches, want 1", *patches)
	}

	group.Generation = 2
	if err := r.SetReadyCondition(ctx, group, metav1.ConditionTrue, "Reconciled", "in sync"); err != nil {
		t.Fatalf("set ready after generation bump: %v", err)
	}
	if *patches != 2 {
		t.Fatalf("generation bump sent %d patches, want 2", *patches)
	}
	stored := &pocketidinternalv1alpha1.PocketIDUserGroup{}
	if err := k8s.Get(ctx, client.ObjectKeyFromObject(group), stored); err != nil {
		t.Fatalf("get: %v", err)
	}
	if cond := meta.FindStatusCondition(stored.Status.Conditions, "Ready"); cond == nil || cond.ObservedGeneration != 2 {
		t.Fatalf("stored Ready condition = %+v, want observedGeneration 2", cond)
	}
}
