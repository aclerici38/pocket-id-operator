package helpers

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

	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
)

func secretsTestClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("add corev1 scheme: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
}

func managedSecret(name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels:    map[string]string{common.ManagedByLabelKey: common.ManagedByLabelValue},
		},
	}
}

func unmanagedSecret(name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
	}
}

func secretExists(t *testing.T, c client.Client, name string) bool {
	t.Helper()
	err := c.Get(context.Background(), types.NamespacedName{Name: name, Namespace: "default"}, &corev1.Secret{})
	if err == nil {
		return true
	}
	if apierrors.IsNotFound(err) {
		return false
	}
	t.Fatalf("unexpected error getting secret %s: %v", name, err)
	return false
}

func TestDeleteSecretIfManaged_DeletesManagedSecret(t *testing.T) {
	c := secretsTestClient(t, managedSecret("managed"))

	if err := DeleteSecretIfManaged(context.Background(), c, "default", "managed"); err != nil {
		t.Fatalf("DeleteSecretIfManaged returned error: %v", err)
	}
	if secretExists(t, c, "managed") {
		t.Fatal("expected managed secret to be deleted")
	}
}

func TestDeleteSecretIfManaged_PreservesUnmanagedSecret(t *testing.T) {
	c := secretsTestClient(t, unmanagedSecret("user-owned"))

	if err := DeleteSecretIfManaged(context.Background(), c, "default", "user-owned"); err != nil {
		t.Fatalf("DeleteSecretIfManaged returned error: %v", err)
	}
	if !secretExists(t, c, "user-owned") {
		t.Fatal("expected unmanaged (user-owned) secret to be preserved")
	}
}

func TestDeleteSecretIfManaged_PreservesSecretWithWrongManagedByValue(t *testing.T) {
	s := unmanagedSecret("other-operator")
	s.Labels = map[string]string{common.ManagedByLabelKey: "another-operator"}
	c := secretsTestClient(t, s)

	if err := DeleteSecretIfManaged(context.Background(), c, "default", "other-operator"); err != nil {
		t.Fatalf("DeleteSecretIfManaged returned error: %v", err)
	}
	if !secretExists(t, c, "other-operator") {
		t.Fatal("expected secret managed by a different operator to be preserved")
	}
}

func TestDeleteSecretIfManaged_MissingSecretIsNoOp(t *testing.T) {
	c := secretsTestClient(t)

	if err := DeleteSecretIfManaged(context.Background(), c, "default", "does-not-exist"); err != nil {
		t.Fatalf("DeleteSecretIfManaged returned error for missing secret: %v", err)
	}
}

func TestDeleteSecretsIfManaged_DeletesOnlyManaged(t *testing.T) {
	c := secretsTestClient(t,
		managedSecret("managed-a"),
		unmanagedSecret("user-owned-b"),
		managedSecret("managed-c"),
	)

	names := []string{"managed-a", "user-owned-b", "managed-c", "missing-d"}
	if err := DeleteSecretsIfManaged(context.Background(), c, "default", names); err != nil {
		t.Fatalf("DeleteSecretsIfManaged returned error: %v", err)
	}

	if secretExists(t, c, "managed-a") {
		t.Fatal("expected managed-a to be deleted")
	}
	if secretExists(t, c, "managed-c") {
		t.Fatal("expected managed-c to be deleted")
	}
	if !secretExists(t, c, "user-owned-b") {
		t.Fatal("expected user-owned-b to be preserved")
	}
}
