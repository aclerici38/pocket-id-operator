package controller

import (
	"context"
	"strings"
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
	if result.RequeueAfter < 5*time.Second {
		t.Fatalf("expected a requeue for non-admin auth user, got %s", result.RequeueAfter)
	}
}

func TestReconcileAuth_ResolvesAPIKeyFromUserStatus(t *testing.T) {
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
				UserRef:    &pocketidinternalv1alpha1.NamespacedUserReference{Name: "my-user"},
				APIKeyName: "my-api-key",
			},
		},
	}

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-user",
			Namespace: "default",
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			IsAdmin: true,
			APIKeys: []pocketidinternalv1alpha1.APIKeyStatus{
				{
					Name:       "my-api-key",
					SecretName: "custom-secret-name",
					SecretKey:  "token",
				},
			},
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue},
			},
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "custom-secret-name",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"token": []byte("my-api-key-token"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(instance, user, secret).
		WithStatusSubresource(instance).
		Build()

	reconciler := &PocketIDInstanceReconciler{Client: client, Scheme: scheme}
	result, err := reconciler.reconcileAuth(context.Background(), instance)

	if err != nil {
		t.Fatalf("reconcileAuth returned error: %v", err)
	}
	if result.RequeueAfter > 0 {
		t.Fatalf("expected no requeue, got RequeueAfter=%s", result.RequeueAfter)
	}
}

func TestReconcileAuth_ErrorsWhenAPIKeyNotInUserStatus(t *testing.T) {
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
				UserRef:    &pocketidinternalv1alpha1.NamespacedUserReference{Name: "my-user"},
				APIKeyName: "missing-key",
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDInstanceStatus{
			Bootstrapped: true,
		},
	}

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-user",
			Namespace: "default",
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			IsAdmin: true,
			APIKeys: []pocketidinternalv1alpha1.APIKeyStatus{
				{
					Name:       "different-key",
					SecretName: "different-secret",
					SecretKey:  "token",
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

	if err == nil {
		t.Fatal("expected error when API key not found in user status after bootstrap")
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("expected requeue after error, got %s", result.RequeueAfter)
	}
}

func TestReconcileAuth_BootstrapsWhenAPIKeyNotInStatus(t *testing.T) {
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
				UserRef:    &pocketidinternalv1alpha1.NamespacedUserReference{Name: "my-user"},
				APIKeyName: "new-key",
			},
			EncryptionKey: pocketidinternalv1alpha1.EnvValue{
				Value: "test-encryption-key-1234567890",
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDInstanceStatus{
			Bootstrapped: false,
		},
	}

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-user",
			Namespace: "default",
		},
		Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
			Admin: true,
			Email: pocketidinternalv1alpha1.StringValue{Value: "test@example.com"},
			APIKeys: []pocketidinternalv1alpha1.APIKeySpec{
				{Name: "new-key"},
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			IsAdmin: true,
			APIKeys: []pocketidinternalv1alpha1.APIKeyStatus{},
		},
	}

	// Create static API key secret (now created before bootstrap in Reconcile)
	staticAPIKeySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "instance-static-api-key",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"token": []byte("test-static-api-key"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(instance, user, staticAPIKeySecret).
		WithStatusSubresource(instance, user).
		Build()

	reconciler := &PocketIDInstanceReconciler{Client: client, APIReader: client, Scheme: scheme}
	_, err := reconciler.reconcileAuth(context.Background(), instance)

	// Bootstrap will fail with network error since there's no running instance
	// This is expected - we just verify it attempted bootstrap (didn't error on API key lookup)
	// The key validation is that it doesn't error with "API key not found" but rather
	// with a bootstrap/network error
	if err == nil {
		t.Fatal("expected bootstrap to fail without running instance")
	}
	if !strings.Contains(err.Error(), "setup") && !strings.Contains(err.Error(), "execute request") {
		t.Fatalf("expected bootstrap/network error, got: %v", err)
	}
}

func TestReconcileAuth_ErrorsWhenSecretMissingAfterBootstrap(t *testing.T) {
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
				UserRef:    &pocketidinternalv1alpha1.NamespacedUserReference{Name: "my-user"},
				APIKeyName: "my-key",
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDInstanceStatus{
			Bootstrapped: true,
		},
	}

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-user",
			Namespace: "default",
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			IsAdmin: true,
			APIKeys: []pocketidinternalv1alpha1.APIKeyStatus{
				{
					Name:       "my-key",
					SecretName: "missing-secret",
					SecretKey:  "token",
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

	if err == nil {
		t.Fatal("expected error when secret not found after bootstrap")
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("expected requeue after error, got %s", result.RequeueAfter)
	}
}

func TestReconcileAuth_RequeuesWhenAPIKeyHasNoSecretName(t *testing.T) {
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
				UserRef:    &pocketidinternalv1alpha1.NamespacedUserReference{Name: "my-user"},
				APIKeyName: "my-key",
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDInstanceStatus{
			Bootstrapped: false,
		},
	}

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-user",
			Namespace: "default",
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			IsAdmin: true,
			APIKeys: []pocketidinternalv1alpha1.APIKeyStatus{
				{
					Name:       "my-key",
					SecretName: "", // Empty secret name
					SecretKey:  "token",
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
		t.Fatalf("expected no error when API key not ready, got: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatal("expected requeue when API key secret name not set")
	}
}

func TestReconcileAuth_ResolvesAPIKeyFromDifferentNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "instance",
			Namespace: "instance-ns",
		},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			Auth: &pocketidinternalv1alpha1.AuthConfig{
				UserRef: &pocketidinternalv1alpha1.NamespacedUserReference{
					Name:      "my-user",
					Namespace: "user-ns",
				},
				APIKeyName: "cross-ns-key",
			},
		},
	}

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-user",
			Namespace: "user-ns",
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			IsAdmin: true,
			APIKeys: []pocketidinternalv1alpha1.APIKeyStatus{
				{
					Name:       "cross-ns-key",
					SecretName: "cross-ns-secret",
					SecretKey:  "token",
				},
			},
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue},
			},
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cross-ns-secret",
			Namespace: "user-ns",
		},
		Data: map[string][]byte{
			"token": []byte("cross-ns-token"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(instance, user, secret).
		WithStatusSubresource(instance).
		Build()

	reconciler := &PocketIDInstanceReconciler{Client: client, Scheme: scheme}
	result, err := reconciler.reconcileAuth(context.Background(), instance)

	if err != nil {
		t.Fatalf("reconcileAuth returned error: %v", err)
	}
	if result.RequeueAfter > 0 {
		t.Fatalf("expected no requeue, got RequeueAfter=%s", result.RequeueAfter)
	}
}
