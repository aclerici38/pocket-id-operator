package helpers

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	pocketidv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

// A finalizer that arrives after deletion has started can never be written: the API server
// rejects it permanently. Attempting it anyway wedges the delete path in a retry loop that
// leaves the object undeletable, so EnsureFinalizer must skip rather than try.
//
// The fake client does not enforce that rule, which is why this is asserted on the guard
// itself; the wedge it prevents is covered end-to-end against envtest in
// internal/controller/deletion_finalizer_race_test.go.
func TestEnsureFinalizer_SkipsObjectBeingDeleted(t *testing.T) {
	now := metav1.NewTime(time.Now())
	group := &pocketidv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "deleting-group",
			Namespace:         "default",
			Finalizers:        []string{"pocketid.internal/user-group-finalizer"},
			DeletionTimestamp: &now,
		},
	}

	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(group).Build()

	updated, err := EnsureFinalizer(context.Background(), c, group, "pocketid.internal/too-late")
	if err != nil {
		t.Fatalf("EnsureFinalizer: got %v, want no error", err)
	}
	if updated {
		t.Error("EnsureFinalizer reported an update, but nothing can be added to a deleting object")
	}
	if controllerutil.ContainsFinalizer(group, "pocketid.internal/too-late") {
		t.Error("finalizer was added to an object that is already being deleted")
	}
}

// The guard must not affect the normal path, where finalizers are added before deletion.
func TestEnsureFinalizer_AddsToLiveObject(t *testing.T) {
	group := &pocketidv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "live-group", Namespace: "default"},
	}

	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(group).Build()

	updated, err := EnsureFinalizer(context.Background(), c, group, "pocketid.internal/user-group-finalizer")
	if err != nil {
		t.Fatalf("EnsureFinalizer: got %v, want no error", err)
	}
	if !updated {
		t.Error("EnsureFinalizer reported no update, but the finalizer was missing")
	}
	if !controllerutil.ContainsFinalizer(group, "pocketid.internal/user-group-finalizer") {
		t.Error("finalizer was not added to a live object")
	}
}
