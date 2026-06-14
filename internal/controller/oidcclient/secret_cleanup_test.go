package oidcclient

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
)

func secretCleanupReconciler(t *testing.T, objs ...client.Object) *Reconciler {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("add corev1 scheme: %v", err)
	}
	if err := pocketidinternalv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add pocketid scheme: %v", err)
	}
	fc := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
	r := &Reconciler{Client: fc, APIReader: fc, Scheme: s}
	r.EnsureClient(fc)
	return r
}

func TestReconcileSecret_DisabledDeletesManagedSecret(t *testing.T) {
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{Enabled: boolPtr(false)},
		},
	}
	managed := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-client-oidc-credentials",
			Namespace: testNamespace,
			Labels:    map[string]string{common.ManagedByLabelKey: common.ManagedByLabelValue},
		},
	}

	r := secretCleanupReconciler(t, oidcClient, managed)

	// instance and apiClient are unused by the disabled-secret branch.
	if err := r.ReconcileSecret(context.Background(), oidcClient, nil, nil); err != nil {
		t.Fatalf("ReconcileSecret returned error: %v", err)
	}

	err := r.Get(context.Background(), types.NamespacedName{Name: managed.Name, Namespace: testNamespace}, &corev1.Secret{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected managed secret to be deleted, got err=%v", err)
	}
}

func TestReconcileSecret_DisabledPreservesUserOwnedSecret(t *testing.T) {
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{
				Enabled: boolPtr(false),
				Name:    "user-owned-oidc",
			},
		},
	}
	// A secret the user created and named, with no managed-by label.
	userOwned := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user-owned-oidc",
			Namespace: testNamespace,
		},
	}

	r := secretCleanupReconciler(t, oidcClient, userOwned)

	if err := r.ReconcileSecret(context.Background(), oidcClient, nil, nil); err != nil {
		t.Fatalf("ReconcileSecret returned error: %v", err)
	}

	if err := r.Get(context.Background(), types.NamespacedName{Name: userOwned.Name, Namespace: testNamespace}, &corev1.Secret{}); err != nil {
		t.Fatalf("expected user-owned secret to be preserved, got err=%v", err)
	}
}
