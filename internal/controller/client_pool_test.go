package controller

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
	// Create test instance
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

	// Create static API key secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance-static-api-key",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"token": []byte("test-static-api-key-token"),
		},
	}

	// Create fake client
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(instance, secret).
		Build()

	// Create a new pool for this test
	pool := NewClientPoolManager()
	ctx := context.Background()

	// Get client multiple times - should return same instance
	client1, err := pool.GetClient(ctx, k8sClient, k8sClient, instance)
	if err != nil {
		t.Fatalf("Failed to get client 1: %v", err)
	}

	client2, err := pool.GetClient(ctx, k8sClient, k8sClient, instance)
	if err != nil {
		t.Fatalf("Failed to get client 2: %v", err)
	}

	// Verify same client instance (same pointer)
	if client1 != client2 {
		t.Error("Expected same client instance, got different instances")
	}

	// Verify pool has the client
	pool.mu.RLock()
	poolSize := len(pool.clients)
	pool.mu.RUnlock()

	if poolSize != 1 {
		t.Errorf("Expected 1 client in pool, got %d", poolSize)
	}
}

func TestClientPool_RemoveClient(t *testing.T) {
	pool := NewClientPoolManager()

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance",
			Namespace: "default",
		},
	}

	// Manually add a client to the pool
	pool.mu.Lock()
	pool.clients[instanceKey(instance)] = &pooledClient{
		instanceKey: instanceKey(instance),
	}
	pool.mu.Unlock()

	// Verify it exists
	pool.mu.RLock()
	if len(pool.clients) != 1 {
		t.Errorf("Expected 1 client before removal, got %d", len(pool.clients))
	}
	pool.mu.RUnlock()

	// Remove the client
	pool.RemoveClient(instance)

	// Verify it was removed
	pool.mu.RLock()
	if len(pool.clients) != 0 {
		t.Errorf("Expected 0 clients after removal, got %d", len(pool.clients))
	}
	pool.mu.RUnlock()
}
