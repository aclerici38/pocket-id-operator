package controller

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

func TestReconcileAuth_DelaysAuthSwitchUntilUserReady(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "instance",
			Namespace: "default",
		},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			Auth: &pocketidinternalv1alpha1.AuthConfig{
				UserRef:    &pocketidinternalv1alpha1.NamespacedUserReference{Name: "new-user"},
				APIKeyName: "new-key",
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDInstanceStatus{
			AuthUserRef:       "old-user",
			AuthUserNamespace: "default",
			AuthAPIKeyName:    "old-key",
		},
	}
	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-user",
			Namespace: "default",
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			IsAdmin: true,
			Conditions: []metav1.Condition{
				{
					Type:   "Ready",
					Status: metav1.ConditionFalse,
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(instance, user).
		Build()

	reconciler := &PocketIDInstanceReconciler{Client: client, Scheme: scheme}
	result, err := reconciler.reconcileAuth(context.Background(), instance)
	if err != nil {
		t.Fatalf("reconcileAuth returned error: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("expected requeue when auth user is not ready, got %s", result.RequeueAfter)
	}
	if result.RequeueAfter > 15*time.Second {
		t.Fatalf("expected a short requeue, got %s", result.RequeueAfter)
	}
}

func TestReconcileAuth_BlocksWhenAuthUserNotAdmin(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "instance",
			Namespace: "default",
		},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			Auth: &pocketidinternalv1alpha1.AuthConfig{
				UserRef:    &pocketidinternalv1alpha1.NamespacedUserReference{Name: "non-admin"},
				APIKeyName: "key",
			},
		},
	}
	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "non-admin",
			Namespace: "default",
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			UserID:  "user-123",
			IsAdmin: false,
			Conditions: []metav1.Condition{
				{
					Type:   "Ready",
					Status: metav1.ConditionTrue,
				},
			},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "non-admin-key-key",
			Namespace: "default",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(instance, user, secret).
		Build()

	reconciler := &PocketIDInstanceReconciler{Client: client, Scheme: scheme}
	result, err := reconciler.reconcileAuth(context.Background(), instance)
	if err != nil {
		t.Fatalf("reconcileAuth returned error: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("expected requeue when auth user is not admin, got %s", result.RequeueAfter)
	}
	if result.RequeueAfter < 20*time.Second {
		t.Fatalf("expected a slower requeue for non-admin auth user, got %s", result.RequeueAfter)
	}
}
