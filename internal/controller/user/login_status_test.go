package user

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

func TestCleanupOneTimeToken_ExpiredClears(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	expiredAt := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "expired-user",
			Namespace: "default",
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			OneTimeLoginToken:     "token",
			OneTimeLoginURL:       "http://example.com/lc/token",
			OneTimeLoginExpiresAt: expiredAt,
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&pocketidinternalv1alpha1.PocketIDUser{}).
		WithObjects(user).
		Build()

	reconciler := &Reconciler{Client: client, APIReader: client, Scheme: scheme}
	if _, err := reconciler.cleanupOneTimeToken(context.Background(), user); err != nil {
		t.Fatalf("cleanupOneTimeToken returned error: %v", err)
	}

	updated := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updated); err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if updated.Status.OneTimeLoginToken != "" || updated.Status.OneTimeLoginURL != "" || updated.Status.OneTimeLoginExpiresAt != expiredAt {
		t.Fatalf("expected token and URL to be cleared while expiry remains, got token=%q url=%q expiresAt=%q",
			updated.Status.OneTimeLoginToken, updated.Status.OneTimeLoginURL, updated.Status.OneTimeLoginExpiresAt)
	}
}

func TestCleanupOneTimeToken_FutureRequeues(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	expiresAt := time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339)
	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "future-user",
			Namespace: "default",
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			OneTimeLoginToken:     "token",
			OneTimeLoginURL:       "http://example.com/lc/token",
			OneTimeLoginExpiresAt: expiresAt,
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&pocketidinternalv1alpha1.PocketIDUser{}).
		WithObjects(user).
		Build()

	reconciler := &Reconciler{Client: client, APIReader: client, Scheme: scheme}
	result, err := reconciler.cleanupOneTimeToken(context.Background(), user)
	if err != nil {
		t.Fatalf("cleanupOneTimeToken returned error: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("expected positive RequeueAfter, got %s", result.RequeueAfter)
	}

	updated := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updated); err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if updated.Status.OneTimeLoginToken == "" || updated.Status.OneTimeLoginURL == "" || updated.Status.OneTimeLoginExpiresAt == "" {
		t.Fatalf("expected login status fields to remain set, got token=%q url=%q expiresAt=%q",
			updated.Status.OneTimeLoginToken, updated.Status.OneTimeLoginURL, updated.Status.OneTimeLoginExpiresAt)
	}
}

func TestCleanupOneTimeToken_InvalidTimestampClears(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "invalid-user",
			Namespace: "default",
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			OneTimeLoginToken:     "token",
			OneTimeLoginURL:       "http://example.com/lc/token",
			OneTimeLoginExpiresAt: "not-a-time",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&pocketidinternalv1alpha1.PocketIDUser{}).
		WithObjects(user).
		Build()

	reconciler := &Reconciler{Client: client, APIReader: client, Scheme: scheme}
	if _, err := reconciler.cleanupOneTimeToken(context.Background(), user); err != nil {
		t.Fatalf("cleanupOneTimeToken returned error: %v", err)
	}

	updated := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updated); err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if updated.Status.OneTimeLoginToken != "" || updated.Status.OneTimeLoginURL != "" || updated.Status.OneTimeLoginExpiresAt != "not-a-time" {
		t.Fatalf("expected token and URL to be cleared and expiry preserved, got token=%q url=%q expiresAt=%q",
			updated.Status.OneTimeLoginToken, updated.Status.OneTimeLoginURL, updated.Status.OneTimeLoginExpiresAt)
	}
}

func TestSetOneTimeLoginStatus_SetsTokenURLAndExpiry(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "status-user",
			Namespace: "default",
		},
	}
	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "instance",
			Namespace: "default",
		},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			AppURL: "http://example.com",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&pocketidinternalv1alpha1.PocketIDUser{}).
		WithObjects(user).
		Build()

	reconciler := &Reconciler{Client: client, APIReader: client, Scheme: scheme}
	now := time.Now().UTC()
	if err := reconciler.SetOneTimeLoginStatus(context.Background(), user, instance, "token123"); err != nil {
		t.Fatalf("SetOneTimeLoginStatus returned error: %v", err)
	}

	updated := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updated); err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}

	if updated.Status.OneTimeLoginToken != "token123" {
		t.Fatalf("expected token to be set, got %q", updated.Status.OneTimeLoginToken)
	}
	expectedURL := "http://example.com/lc/token123"
	if updated.Status.OneTimeLoginURL != expectedURL {
		t.Fatalf("expected URL %q, got %q", expectedURL, updated.Status.OneTimeLoginURL)
	}
	if updated.Status.OneTimeLoginExpiresAt == "" {
		t.Fatal("expected expiresAt to be set")
	}
	parsed, err := time.Parse(time.RFC3339, updated.Status.OneTimeLoginExpiresAt)
	if err != nil {
		t.Fatalf("failed to parse expiresAt: %v", err)
	}
	minExpiry := now.Add(time.Duration(DefaultLoginTokenExpiryMin-1) * time.Minute)
	maxExpiry := now.Add(time.Duration(DefaultLoginTokenExpiryMin+1) * time.Minute)
	if parsed.Before(minExpiry) || parsed.After(maxExpiry) {
		t.Fatalf("expected expiresAt within %s and %s, got %s", minExpiry, maxExpiry, parsed)
	}
}
