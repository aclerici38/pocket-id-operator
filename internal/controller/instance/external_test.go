package instance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
)

func externalTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil {
		t.Fatalf("add client-go scheme: %v", err)
	}
	if err := pocketidinternalv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add pocketid scheme: %v", err)
	}
	return s
}

func newExternalInstance(url string) *pocketidinternalv1alpha1.PocketIDInstance {
	return &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "adopted", Namespace: "pocket-id"},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			External: &pocketidinternalv1alpha1.ExternalInstanceConfig{
				URL: url,
				APIKeySecretRef: corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "admin-token"},
					Key:                  "token",
				},
			},
		},
	}
}

func apiKeySecret(name, key, value string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "pocket-id"},
		Data:       map[string][]byte{key: []byte(value)},
	}
}

// newReconcilerFor builds a Reconciler backed by a fake client that already holds
// the given objects, with the instance registered for the status subresource so
// reconcileExternal's status Patch succeeds.
func newReconcilerFor(t *testing.T, instance *pocketidinternalv1alpha1.PocketIDInstance, objs ...client.Object) *Reconciler {
	t.Helper()
	s := externalTestScheme(t)
	all := append([]client.Object{instance}, objs...)
	fc := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(all...).
		WithStatusSubresource(instance).
		Build()
	return &Reconciler{Client: fc, APIReader: fc, Scheme: s}
}

func readyCondition(t *testing.T, r *Reconciler, instance *pocketidinternalv1alpha1.PocketIDInstance) *metav1.Condition {
	t.Helper()
	got := &pocketidinternalv1alpha1.PocketIDInstance{}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(instance), got); err != nil {
		t.Fatalf("get instance: %v", err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, "Ready")
	if cond == nil {
		t.Fatal("Ready condition not set")
	}
	return cond
}

func TestReconcileExternal_Reachable(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"currentVersion":"2.8.0"}`))
	}))
	defer srv.Close()

	instance := newExternalInstance(srv.URL)
	r := newReconcilerFor(t, instance, apiKeySecret("admin-token", "token", "api-key"))

	if _, err := r.reconcileExternal(ctx, instance); err != nil {
		t.Fatalf("reconcileExternal: %v", err)
	}

	got := &pocketidinternalv1alpha1.PocketIDInstance{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(instance), got); err != nil {
		t.Fatalf("get instance: %v", err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, "Ready")
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("expected Ready=True, got %+v", cond)
	}
	if cond.Reason != "Ready" {
		t.Errorf("reason: got %q, want %q", cond.Reason, "Ready")
	}
	if got.Status.Version != "2.8.0" {
		t.Errorf("version: got %q, want %q", got.Status.Version, "2.8.0")
	}
	if got.Status.StaticAPIKeySecretName != "" {
		t.Errorf("StaticAPIKeySecretName should be cleared for external instances, got %q", got.Status.StaticAPIKeySecretName)
	}
}

func TestReconcileExternal_Unreachable(t *testing.T) {
	ctx := context.Background()
	// Server is reachable but returns an error status, so GetCurrentVersion fails.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	instance := newExternalInstance(srv.URL)
	r := newReconcilerFor(t, instance, apiKeySecret("admin-token", "token", "api-key"))

	if _, err := r.reconcileExternal(ctx, instance); err != nil {
		t.Fatalf("reconcileExternal should not return an error on unreachable instance: %v", err)
	}

	cond := readyCondition(t, r, instance)
	if cond.Status != metav1.ConditionFalse {
		t.Fatalf("expected Ready=False, got %+v", cond)
	}
	if cond.Reason != "Unreachable" {
		t.Errorf("reason: got %q, want %q", cond.Reason, "Unreachable")
	}
}

func TestReconcileExternal_APIKeySecretMissing(t *testing.T) {
	ctx := context.Background()
	// No API key secret present, so the client cannot be built.
	instance := newExternalInstance("https://auth.example.com")
	r := newReconcilerFor(t, instance)

	if _, err := r.reconcileExternal(ctx, instance); err != nil {
		t.Fatalf("reconcileExternal should not return an error when secret is missing: %v", err)
	}

	cond := readyCondition(t, r, instance)
	if cond.Status != metav1.ConditionFalse {
		t.Fatalf("expected Ready=False, got %+v", cond)
	}
	if cond.Reason != "APIClientError" {
		t.Errorf("reason: got %q, want %q", cond.Reason, "APIClientError")
	}
}

// TestReconcile_ExternalSkipsWorkload locks in the invariant that an external
// instance never enters the deploy pipeline: Reconcile must early-return into
// reconcileExternal, so no Deployment, Service, or operator-managed static API
// key Secret (the carrier for ENCRYPTION_KEY / STATIC_API_KEY env) is created.
func TestReconcile_ExternalSkipsWorkload(t *testing.T) {
	ctx := context.Background()
	// Pointed at an unreachable URL on purpose (connection refused, fails fast): the
	// workload-skipping behavior must hold regardless of reachability.
	instance := newExternalInstance("http://127.0.0.1:1")
	r := newReconcilerFor(t, instance, apiKeySecret("admin-token", "token", "api-key"))

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(instance)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	key := client.ObjectKeyFromObject(instance)

	if err := r.Get(ctx, key, &appsv1.Deployment{}); !apierrors.IsNotFound(err) {
		t.Errorf("expected no Deployment for external instance, got err=%v", err)
	}
	if err := r.Get(ctx, key, &appsv1.StatefulSet{}); !apierrors.IsNotFound(err) {
		t.Errorf("expected no StatefulSet for external instance, got err=%v", err)
	}
	if err := r.Get(ctx, key, &corev1.Service{}); !apierrors.IsNotFound(err) {
		t.Errorf("expected no Service for external instance, got err=%v", err)
	}

	staticKey := types.NamespacedName{Namespace: instance.Namespace, Name: common.StaticAPIKeySecretName(instance.Name)}
	if err := r.Get(ctx, staticKey, &corev1.Secret{}); !apierrors.IsNotFound(err) {
		t.Errorf("expected no operator-managed static API key Secret for external instance, got err=%v", err)
	}
}

func TestReconcileExternal_ObservedGeneration(t *testing.T) {
	ctx := context.Background()
	instance := newExternalInstance("https://auth.example.com")
	instance.Generation = 7
	r := newReconcilerFor(t, instance)

	if _, err := r.reconcileExternal(ctx, instance); err != nil {
		t.Fatalf("reconcileExternal: %v", err)
	}

	cond := readyCondition(t, r, instance)
	if cond.ObservedGeneration != 7 {
		t.Errorf("observedGeneration: got %d, want %d", cond.ObservedGeneration, 7)
	}
}
