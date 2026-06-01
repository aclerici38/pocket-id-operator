package common

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

func newSecretScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1 to scheme: %v", err)
	}
	return scheme
}

func fakeReader(t *testing.T, objs ...client.Object) client.Reader {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(newSecretScheme(t)).WithObjects(objs...).Build()
}

func externalInstance(namespace, secretName, secretKey, url string) *pocketidinternalv1alpha1.PocketIDInstance {
	inst := &pocketidinternalv1alpha1.PocketIDInstance{}
	inst.Name = "external-instance"
	inst.Namespace = namespace
	inst.Spec.External = &pocketidinternalv1alpha1.ExternalInstanceConfig{
		URL: url,
		APIKeySecretRef: corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
			Key:                  secretKey,
		},
	}
	return inst
}

func apiKeySecret(namespace, name, key, value string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Data:       map[string][]byte{key: []byte(value)},
	}
}

// --- getExternalAPIKey ---

func TestGetExternalAPIKey_Success(t *testing.T) {
	ctx := context.Background()
	secret := apiKeySecret("pocket-id", "admin-token", "token", "super-secret-key")
	reader := fakeReader(t, secret)
	inst := externalInstance("pocket-id", "admin-token", "token", "https://auth.example.com")

	key, err := getExternalAPIKey(ctx, reader, inst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "super-secret-key" {
		t.Errorf("api key: got %q, want %q", key, "super-secret-key")
	}
}

func TestGetExternalAPIKey_CustomKeyName(t *testing.T) {
	ctx := context.Background()
	// The Secret stores the token under a non-default key; the ref must honor it.
	secret := apiKeySecret("pocket-id", "admin-token", "api-key", "value-under-custom-key")
	reader := fakeReader(t, secret)
	inst := externalInstance("pocket-id", "admin-token", "api-key", "https://auth.example.com")

	key, err := getExternalAPIKey(ctx, reader, inst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "value-under-custom-key" {
		t.Errorf("api key: got %q, want %q", key, "value-under-custom-key")
	}
}

func TestGetExternalAPIKey_NilReader(t *testing.T) {
	ctx := context.Background()
	inst := externalInstance("pocket-id", "admin-token", "token", "https://auth.example.com")

	_, err := getExternalAPIKey(ctx, nil, inst)
	if !errors.Is(err, ErrAPIClientNotReady) {
		t.Fatalf("expected ErrAPIClientNotReady, got %v", err)
	}
}

func TestGetExternalAPIKey_SecretNotFound(t *testing.T) {
	ctx := context.Background()
	reader := fakeReader(t) // no secrets
	inst := externalInstance("pocket-id", "missing-secret", "token", "https://auth.example.com")

	_, err := getExternalAPIKey(ctx, reader, inst)
	if !errors.Is(err, ErrAPIClientNotReady) {
		t.Fatalf("expected ErrAPIClientNotReady, got %v", err)
	}
}

func TestGetExternalAPIKey_KeyMissingInSecret(t *testing.T) {
	ctx := context.Background()
	// Secret exists but does not contain the referenced key.
	secret := apiKeySecret("pocket-id", "admin-token", "some-other-key", "value")
	reader := fakeReader(t, secret)
	inst := externalInstance("pocket-id", "admin-token", "token", "https://auth.example.com")

	_, err := getExternalAPIKey(ctx, reader, inst)
	if !errors.Is(err, ErrAPIClientNotReady) {
		t.Fatalf("expected ErrAPIClientNotReady, got %v", err)
	}
}

func TestGetExternalAPIKey_EmptyValue(t *testing.T) {
	ctx := context.Background()
	// Key is present but holds an empty value, which must be rejected.
	secret := apiKeySecret("pocket-id", "admin-token", "token", "")
	reader := fakeReader(t, secret)
	inst := externalInstance("pocket-id", "admin-token", "token", "https://auth.example.com")

	_, err := getExternalAPIKey(ctx, reader, inst)
	if !errors.Is(err, ErrAPIClientNotReady) {
		t.Fatalf("expected ErrAPIClientNotReady, got %v", err)
	}
}

func TestGetExternalAPIKey_ReadsFromInstanceNamespace(t *testing.T) {
	ctx := context.Background()
	// Secret lives in the instance's namespace; a same-named secret elsewhere must not be used.
	wrong := apiKeySecret("other-ns", "admin-token", "token", "wrong-namespace-value")
	right := apiKeySecret("pocket-id", "admin-token", "token", "correct-value")
	reader := fakeReader(t, wrong, right)
	inst := externalInstance("pocket-id", "admin-token", "token", "https://auth.example.com")

	key, err := getExternalAPIKey(ctx, reader, inst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "correct-value" {
		t.Errorf("api key: got %q, want %q", key, "correct-value")
	}
}

// --- resolveAPIClientCredentials ---

func TestResolveAPIClientCredentials_External(t *testing.T) {
	ctx := context.Background()
	secret := apiKeySecret("pocket-id", "admin-token", "token", "ext-key")
	reader := fakeReader(t, secret)
	inst := externalInstance("pocket-id", "admin-token", "token", "https://auth.example.com")

	url, key, err := resolveAPIClientCredentials(ctx, reader, inst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if url != "https://auth.example.com" {
		t.Errorf("url: got %q, want %q", url, "https://auth.example.com")
	}
	if key != "ext-key" {
		t.Errorf("key: got %q, want %q", key, "ext-key")
	}
}

func TestResolveAPIClientCredentials_ExternalPropagatesSecretError(t *testing.T) {
	ctx := context.Background()
	reader := fakeReader(t) // secret absent
	inst := externalInstance("pocket-id", "admin-token", "token", "https://auth.example.com")

	_, _, err := resolveAPIClientCredentials(ctx, reader, inst)
	if !errors.Is(err, ErrAPIClientNotReady) {
		t.Fatalf("expected ErrAPIClientNotReady, got %v", err)
	}
}

func TestResolveAPIClientCredentials_Deployed(t *testing.T) {
	ctx := context.Background()
	// Deployed (non-external) instances resolve to the in-cluster service URL and
	// the operator-managed static API key secret.
	inst := &pocketidinternalv1alpha1.PocketIDInstance{}
	inst.Name = "deployed"
	inst.Namespace = "pocket-id"
	secret := apiKeySecret("pocket-id", StaticAPIKeySecretName("deployed"), "token", "static-key")
	reader := fakeReader(t, secret)

	url, key, err := resolveAPIClientCredentials(ctx, reader, inst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := InternalServiceURL("deployed", "pocket-id"); url != want {
		t.Errorf("url: got %q, want %q", url, want)
	}
	if key != "static-key" {
		t.Errorf("key: got %q, want %q", key, "static-key")
	}
}

func TestResolveAPIClientCredentials_DeployedMissingStaticSecret(t *testing.T) {
	ctx := context.Background()
	inst := &pocketidinternalv1alpha1.PocketIDInstance{}
	inst.Name = "deployed"
	inst.Namespace = "pocket-id"
	reader := fakeReader(t) // no static api key secret

	_, _, err := resolveAPIClientCredentials(ctx, reader, inst)
	if !errors.Is(err, ErrAPIClientNotReady) {
		t.Fatalf("expected ErrAPIClientNotReady, got %v", err)
	}
}

// --- GetAPIClient ---

func TestGetAPIClient_ExternalSuccess(t *testing.T) {
	ctx := context.Background()
	secret := apiKeySecret("pocket-id", "admin-token", "token", "ext-key")
	reader := fakeReader(t, secret)
	inst := externalInstance("pocket-id", "admin-token", "token", "https://auth.example.com")

	apiClient, err := GetAPIClient(ctx, nil, reader, inst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if apiClient == nil {
		t.Fatal("expected a non-nil API client")
	}
}

func TestGetAPIClient_ExternalPropagatesError(t *testing.T) {
	ctx := context.Background()
	reader := fakeReader(t) // secret missing -> credential resolution fails
	inst := externalInstance("pocket-id", "admin-token", "token", "https://auth.example.com")

	_, err := GetAPIClient(ctx, nil, reader, inst)
	if !errors.Is(err, ErrAPIClientNotReady) {
		t.Fatalf("expected ErrAPIClientNotReady, got %v", err)
	}
}
