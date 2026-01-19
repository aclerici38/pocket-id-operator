package oidcclient

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const testNamespace = "default"

func TestOidcClientInput(t *testing.T) {
	reconciler := &Reconciler{}
	oidc := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fallback-name",
		},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			ClientID:                 "client-id",
			CallbackURLs:             []string{"https://example.com/callback"},
			LogoutCallbackURLs:       []string{"https://example.com/logout"},
			LaunchURL:                "https://example.com",
			LogoURL:                  "https://example.com/logo.png",
			DarkLogoURL:              "https://example.com/logo-dark.png",
			IsPublic:                 true,
			PKCEEnabled:              true,
			RequiresReauthentication: true,
			FederatedIdentities: []pocketidinternalv1alpha1.OIDCClientFederatedIdentity{
				{
					Issuer:   "https://issuer.example.com",
					Subject:  "subject",
					Audience: "audience",
					JWKS:     "https://issuer.example.com/jwks",
				},
			},
			AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
				{Name: "group"},
			},
		},
	}

	input := reconciler.OidcClientInput(oidc)
	if input.Name != "fallback-name" {
		t.Errorf("expected Name %q, got %q", "fallback-name", input.Name)
	}
	if !input.HasLogo {
		t.Error("expected HasLogo to be true")
	}
	if !input.HasDarkLogo {
		t.Error("expected HasDarkLogo to be true")
	}
	if !input.IsGroupRestricted {
		t.Error("expected IsGroupRestricted to be true")
	}
	if input.Credentials == nil {
		t.Fatal("expected Credentials to not be nil")
	}
	if len(input.Credentials.FederatedIdentities) != 1 {
		t.Fatalf("expected 1 federated identity, got %d", len(input.Credentials.FederatedIdentities))
	}
	expected := pocketid.OIDCClientFederatedIdentity{
		Issuer:   "https://issuer.example.com",
		Subject:  "subject",
		Audience: "audience",
		JWKS:     "https://issuer.example.com/jwks",
	}
	if input.Credentials.FederatedIdentities[0] != expected {
		t.Errorf("expected federated identity %+v, got %+v", expected, input.Credentials.FederatedIdentities[0])
	}
}

func TestGetSecretName_Default(t *testing.T) {
	reconciler := &Reconciler{}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-client",
		},
	}
	name := reconciler.GetSecretName(oidcClient)
	if name != "my-client-oidc-credentials" {
		t.Errorf("expected %q, got %q", "my-client-oidc-credentials", name)
	}
}

func TestGetSecretName_Custom(t *testing.T) {
	reconciler := &Reconciler{}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-client",
		},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{
				Name: "custom-secret",
			},
		},
	}
	name := reconciler.GetSecretName(oidcClient)
	if name != "custom-secret" {
		t.Errorf("expected %q, got %q", "custom-secret", name)
	}
}

func TestGetSecretName_EmptyCustom(t *testing.T) {
	reconciler := &Reconciler{}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-client",
		},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{
				Name: "",
			},
		},
	}
	name := reconciler.GetSecretName(oidcClient)
	if name != "my-client-oidc-credentials" {
		t.Errorf("expected %q, got %q", "my-client-oidc-credentials", name)
	}
}

func TestGetSecretKeys_Defaults(t *testing.T) {
	reconciler := &Reconciler{}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-client",
		},
	}
	keys := reconciler.GetSecretKeys(oidcClient)
	if keys.ClientID != "client_id" {
		t.Errorf("expected ClientID %q, got %q", "client_id", keys.ClientID)
	}
	if keys.ClientSecret != "client_secret" {
		t.Errorf("expected ClientSecret %q, got %q", "client_secret", keys.ClientSecret)
	}
	if keys.IssuerURL != "issuer_url" {
		t.Errorf("expected IssuerURL %q, got %q", "issuer_url", keys.IssuerURL)
	}
	if keys.CallbackURLs != "callback_urls" {
		t.Errorf("expected CallbackURLs %q, got %q", "callback_urls", keys.CallbackURLs)
	}
	if keys.LogoutCallbackURLs != "logout_callback_urls" {
		t.Errorf("expected LogoutCallbackURLs %q, got %q", "logout_callback_urls", keys.LogoutCallbackURLs)
	}
}

func TestGetSecretKeys_Custom(t *testing.T) {
	reconciler := &Reconciler{}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-client",
		},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{
				Keys: &pocketidinternalv1alpha1.OIDCClientSecretKeys{
					ClientID:           "custom_client_id",
					ClientSecret:       "custom_client_secret",
					IssuerURL:          "custom_issuer",
					CallbackURLs:       "custom_callbacks",
					LogoutCallbackURLs: "custom_logout",
				},
			},
		},
	}
	keys := reconciler.GetSecretKeys(oidcClient)
	if keys.ClientID != "custom_client_id" {
		t.Errorf("expected ClientID %q, got %q", "custom_client_id", keys.ClientID)
	}
	if keys.ClientSecret != "custom_client_secret" {
		t.Errorf("expected ClientSecret %q, got %q", "custom_client_secret", keys.ClientSecret)
	}
	if keys.IssuerURL != "custom_issuer" {
		t.Errorf("expected IssuerURL %q, got %q", "custom_issuer", keys.IssuerURL)
	}
	if keys.CallbackURLs != "custom_callbacks" {
		t.Errorf("expected CallbackURLs %q, got %q", "custom_callbacks", keys.CallbackURLs)
	}
	if keys.LogoutCallbackURLs != "custom_logout" {
		t.Errorf("expected LogoutCallbackURLs %q, got %q", "custom_logout", keys.LogoutCallbackURLs)
	}
}

func TestGetSecretKeys_PartialCustom(t *testing.T) {
	reconciler := &Reconciler{}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-client",
		},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{
				Keys: &pocketidinternalv1alpha1.OIDCClientSecretKeys{
					ClientID: "custom_client_id",
				},
			},
		},
	}
	keys := reconciler.GetSecretKeys(oidcClient)
	if keys.ClientID != "custom_client_id" {
		t.Errorf("expected ClientID %q, got %q", "custom_client_id", keys.ClientID)
	}
	if keys.ClientSecret != "client_secret" {
		t.Errorf("expected ClientSecret %q, got %q", "client_secret", keys.ClientSecret)
	}
	if keys.IssuerURL != "issuer_url" {
		t.Errorf("expected IssuerURL %q, got %q", "issuer_url", keys.IssuerURL)
	}
}

func TestReconcileSecret_DeleteWhenDisabled(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	enabled := false
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-disabled-secret",
			Namespace: testNamespace,
		},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{
				Enabled: &enabled,
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			ClientID: "client-123",
		},
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-disabled-secret-oidc-credentials",
			Namespace: testNamespace,
		},
		Data: map[string][]byte{
			"client_id": []byte("client-123"),
		},
	}

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance",
			Namespace: testNamespace,
		},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			AppURL:        "http://test.example.com",
			EncryptionKey: pocketidinternalv1alpha1.EnvValue{Value: "0123456789abcdef"},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(oidcClient, secret, instance).
		Build()

	reconciler := &Reconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	err := reconciler.ReconcileSecret(ctx, oidcClient, instance, nil)
	if err != nil {
		t.Fatalf("ReconcileSecret returned error: %v", err)
	}

	deletedSecret := &corev1.Secret{}
	err = fakeClient.Get(ctx, client.ObjectKey{Name: secret.Name, Namespace: testNamespace}, deletedSecret)
	if err == nil {
		t.Fatal("expected secret to be deleted")
	}
}

func TestReconcileSecret_NoErrorWhenDisablingNonExistent(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	enabled := false
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-no-secret",
			Namespace: testNamespace,
		},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{
				Enabled: &enabled,
			},
		},
	}

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance",
			Namespace: testNamespace,
		},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			AppURL:        "http://test.example.com",
			EncryptionKey: pocketidinternalv1alpha1.EnvValue{Value: "0123456789abcdef"},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(oidcClient, instance).
		Build()

	reconciler := &Reconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	err := reconciler.ReconcileSecret(ctx, oidcClient, instance, nil)
	if err != nil {
		t.Fatalf("ReconcileSecret returned error: %v", err)
	}
}

func TestReconcileSecret_CreateForPublicClient(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-public-enabled",
			Namespace: testNamespace,
			UID:       "test-uid-public",
		},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			IsPublic:     true,
			CallbackURLs: []string{"https://example.com/callback"},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			ClientID: "client-789",
		},
	}

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance",
			Namespace: testNamespace,
		},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			AppURL:        "http://test.example.com",
			EncryptionKey: pocketidinternalv1alpha1.EnvValue{Value: "0123456789abcdef"},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(oidcClient, instance).
		Build()

	reconciler := &Reconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	err := reconciler.ReconcileSecret(ctx, oidcClient, instance, nil)
	if err != nil {
		t.Fatalf("ReconcileSecret returned error: %v", err)
	}

	secret := &corev1.Secret{}
	err = fakeClient.Get(ctx, client.ObjectKey{
		Name:      "test-public-enabled-oidc-credentials",
		Namespace: testNamespace,
	}, secret)
	if err != nil {
		t.Fatalf("expected secret to exist: %v", err)
	}

	if _, ok := secret.Data["client_id"]; !ok {
		t.Error("expected secret to have client_id key")
	}
	if _, ok := secret.Data["client_secret"]; ok {
		t.Error("expected secret to NOT have client_secret key for public client")
	}
	if _, ok := secret.Data["issuer_url"]; !ok {
		t.Error("expected secret to have issuer_url key")
	}
}

func TestReconcileDelete_RemoveFinalizerWhenNoInstance(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "delete-oidc-no-instance",
			Namespace:  testNamespace,
			Finalizers: []string{oidcClientFinalizer},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			ClientID: "client-id",
		},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(resource).
		Build()

	reconciler := &Reconciler{Client: fakeClient, Scheme: scheme}
	_, err := reconciler.ReconcileDelete(ctx, resource)
	if err != nil {
		t.Fatalf("ReconcileDelete returned error: %v", err)
	}

	updated := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: resource.Name, Namespace: resource.Namespace}, updated); err != nil {
		t.Fatalf("failed to get updated resource: %v", err)
	}
	for _, f := range updated.Finalizers {
		if f == oidcClientFinalizer {
			t.Error("expected finalizer to be removed")
		}
	}
}

func TestReconcileDelete_KeepFinalizerWhenAPIClientNotReady(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "delete-oidc-instance",
			Namespace: testNamespace,
		},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			EncryptionKey: pocketidinternalv1alpha1.EnvValue{Value: "0123456789abcdef"},
		},
	}

	resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "delete-oidc-api-client-error",
			Namespace:  testNamespace,
			Finalizers: []string{oidcClientFinalizer},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			ClientID: "client-id",
		},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(instance, resource).
		Build()

	reconciler := &Reconciler{Client: fakeClient, Scheme: scheme}
	_, err := reconciler.ReconcileDelete(ctx, resource)
	if err != nil {
		t.Fatalf("ReconcileDelete returned error: %v", err)
	}

	updated := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Name: resource.Name, Namespace: resource.Namespace}, updated); err != nil {
		t.Fatalf("failed to get updated resource: %v", err)
	}
	found := false
	for _, f := range updated.Finalizers {
		if f == oidcClientFinalizer {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finalizer to be kept")
	}
}
