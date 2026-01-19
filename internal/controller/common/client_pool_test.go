package common

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

func TestClientPool_SingletonPerInstance(t *testing.T) {
	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance",
			Namespace: "default",
		},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			Image: "test:latest",
		},
		Status: pocketidinternalv1alpha1.PocketIDInstanceStatus{
			StaticAPIKeySecretName: "test-instance-static-api-key",
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance-static-api-key",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"token": []byte("test-static-api-key-token"),
		},
	}

	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(instance, secret).
		Build()

	pool := NewClientPoolManager()
	ctx := context.Background()

	client1, err := pool.GetClient(ctx, k8sClient, k8sClient, instance)
	if err != nil {
		t.Fatalf("Failed to get client 1: %v", err)
	}

	client2, err := pool.GetClient(ctx, k8sClient, k8sClient, instance)
	if err != nil {
		t.Fatalf("Failed to get client 2: %v", err)
	}

	if client1 != client2 {
		t.Error("Expected same client instance, got different instances")
	}
}

func TestClientPool_RemoveClient(t *testing.T) {
	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance",
			Namespace: "default",
		},
		Status: pocketidinternalv1alpha1.PocketIDInstanceStatus{
			StaticAPIKeySecretName: "test-instance-static-api-key",
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance-static-api-key",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"token": []byte("test-static-api-key-token"),
		},
	}

	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(instance, secret).
		Build()

	pool := NewClientPoolManager()
	ctx := context.Background()

	_, err := pool.GetClient(ctx, k8sClient, k8sClient, instance)
	if err != nil {
		t.Fatalf("Failed to get client: %v", err)
	}

	pool.RemoveClient(instance)

	_, err = pool.GetClient(ctx, k8sClient, k8sClient, instance)
	if err != nil {
		t.Fatalf("Failed to get client after removal: %v", err)
	}
}
