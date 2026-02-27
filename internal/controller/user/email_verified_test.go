package user

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

// TestPushUserState_PreservesEmailVerified verifies that when a user has
// EmailVerified=true in status (set by a prior sync from Pocket-ID), the
// UpdateUser call sends emailVerified=true so a reconcile does not reset it.
func TestPushUserState_PreservesEmailVerified(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "verified-user",
			Namespace: "default",
		},
		Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
			Email: pocketidinternalv1alpha1.StringValue{Value: "verified@example.com"},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			UserID:        "some-id",
			EmailVerified: true,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&pocketidinternalv1alpha1.PocketIDUser{}).
		WithObjects(user).
		Build()

	reconciler := &Reconciler{Client: fakeClient, APIReader: fakeClient, Scheme: scheme}

	input, err := reconciler.buildUserInput(context.Background(), user)
	if err != nil {
		t.Fatalf("buildUserInput returned error: %v", err)
	}

	if !input.EmailVerified {
		t.Fatal("expected EmailVerified=true in UserInput when status.EmailVerified is true, but got false")
	}
}

// TestPushUserState_UnverifiedUserSendsFalse verifies that a user whose email
// has not been verified sends emailVerified=false, which is the zero value and
// correct default.
func TestPushUserState_UnverifiedUserSendsFalse(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unverified-user",
			Namespace: "default",
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			UserID:        "some-id",
			EmailVerified: false,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&pocketidinternalv1alpha1.PocketIDUser{}).
		WithObjects(user).
		Build()

	reconciler := &Reconciler{Client: fakeClient, APIReader: fakeClient, Scheme: scheme}

	input, err := reconciler.buildUserInput(context.Background(), user)
	if err != nil {
		t.Fatalf("buildUserInput returned error: %v", err)
	}

	if input.EmailVerified {
		t.Fatal("expected EmailVerified=false in UserInput when status.EmailVerified is false, but got true")
	}
}
