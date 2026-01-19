package helpers

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

func TestResolveStringValue_DirectValue(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	ctx := context.Background()

	sv := pocketidv1alpha1.StringValue{
		Value: "direct-value",
	}

	result, err := ResolveStringValue(ctx, client, nil, "default", sv, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "direct-value" {
		t.Errorf("expected 'direct-value', got '%s'", result)
	}
}

func TestResolveStringValue_ExplicitSecretRef(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"key1": []byte("value-from-secret"),
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	ctx := context.Background()

	sv := pocketidv1alpha1.StringValue{
		ValueFrom: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "test-secret"},
			Key:                  "key1",
		},
	}

	result, err := ResolveStringValue(ctx, client, nil, "default", sv, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "value-from-secret" {
		t.Errorf("expected 'value-from-secret', got '%s'", result)
	}
}

func TestResolveStringValue_ExplicitSecretRef_MissingKey_ShouldError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"key1": []byte("value-from-secret"),
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	ctx := context.Background()

	sv := pocketidv1alpha1.StringValue{
		ValueFrom: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "test-secret"},
			Key:                  "missing-key",
		},
	}

	_, err := ResolveStringValue(ctx, client, nil, "default", sv, "", "")
	if err == nil {
		t.Fatal("expected error for missing key in explicit secret reference, got nil")
	}
}

func TestResolveStringValue_FallbackSecret(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fallback-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"firstName": []byte("John"),
			"lastName":  []byte("Doe"),
			"email":     []byte("john@example.com"),
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	ctx := context.Background()

	sv := pocketidv1alpha1.StringValue{}

	result, err := ResolveStringValue(ctx, client, nil, "default", sv, "fallback-secret", "firstName")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "John" {
		t.Errorf("expected 'John', got '%s'", result)
	}
}

func TestResolveStringValue_FallbackSecret_MissingKey_ReturnsEmpty(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fallback-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"firstName": []byte("John"),
			"lastName":  []byte("Doe"),
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	ctx := context.Background()

	sv := pocketidv1alpha1.StringValue{}

	result, err := ResolveStringValue(ctx, client, nil, "default", sv, "fallback-secret", "email")
	if err != nil {
		t.Fatalf("unexpected error for missing key in fallback secret: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty string for missing key in fallback secret, got '%s'", result)
	}
}

func TestResolveStringValue_DirectValueOverridesFallback(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fallback-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"firstName": []byte("John"),
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	ctx := context.Background()

	sv := pocketidv1alpha1.StringValue{
		Value: "DirectValue",
	}

	result, err := ResolveStringValue(ctx, client, nil, "default", sv, "fallback-secret", "firstName")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "DirectValue" {
		t.Errorf("expected direct value 'DirectValue' to override fallback, got '%s'", result)
	}
}

func TestResolveStringValue_NoValueReturnsEmpty(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	ctx := context.Background()

	sv := pocketidv1alpha1.StringValue{}

	result, err := ResolveStringValue(ctx, client, nil, "default", sv, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty string, got '%s'", result)
	}
}
