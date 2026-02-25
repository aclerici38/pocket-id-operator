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

func newAggregationFakeClient(scheme *runtime.Scheme, objs ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithIndex(&pocketidinternalv1alpha1.PocketIDUserGroup{}, "pocketidusergroup.allowedOIDCClient", func(raw client.Object) []string {
			ug := raw.(*pocketidinternalv1alpha1.PocketIDUserGroup)
			var keys []string
			for _, ref := range ug.Spec.AllowedOIDCClients {
				if ref.Name == "" {
					continue
				}
				ns := ref.Namespace
				if ns == "" {
					ns = ug.Namespace
				}
				keys = append(keys, ns+"/"+ref.Name)
			}
			return keys
		}).
		Build()
}

func readyCondition() []metav1.Condition {
	return []metav1.Condition{{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Reconciled",
		LastTransitionTime: metav1.Now(),
	}}
}

func TestAggregateAllowedUserGroupIDs_DirectOnly(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group-a", Namespace: testNamespace},
		Status:     pocketidinternalv1alpha1.PocketIDUserGroupStatus{GroupID: "gid-a", Conditions: readyCondition()},
	}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "client-1", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{{Name: "group-a"}},
		},
	}

	fc := newAggregationFakeClient(scheme, group, oidcClient)
	reconciler := &Reconciler{Client: fc, Scheme: scheme}

	ids, err := reconciler.aggregateAllowedUserGroupIDs(ctx, oidcClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 1 || ids[0] != "gid-a" {
		t.Errorf("expected [gid-a], got %v", ids)
	}
}

func TestAggregateAllowedUserGroupIDs_ReverseOnly(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group-b", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			AllowedOIDCClients: []pocketidinternalv1alpha1.NamespacedOIDCClientReference{{Name: "client-2"}},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{GroupID: "gid-b", Conditions: readyCondition()},
	}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "client-2", Namespace: testNamespace},
	}

	fc := newAggregationFakeClient(scheme, group, oidcClient)
	reconciler := &Reconciler{Client: fc, Scheme: scheme}

	ids, err := reconciler.aggregateAllowedUserGroupIDs(ctx, oidcClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 1 || ids[0] != "gid-b" {
		t.Errorf("expected [gid-b], got %v", ids)
	}
}

func TestAggregateAllowedUserGroupIDs_Union(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	groupA := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group-a", Namespace: testNamespace},
		Status:     pocketidinternalv1alpha1.PocketIDUserGroupStatus{GroupID: "gid-a", Conditions: readyCondition()},
	}
	groupB := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group-b", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			AllowedOIDCClients: []pocketidinternalv1alpha1.NamespacedOIDCClientReference{{Name: "client-3"}},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{GroupID: "gid-b", Conditions: readyCondition()},
	}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "client-3", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{{Name: "group-a"}},
		},
	}

	fc := newAggregationFakeClient(scheme, groupA, groupB, oidcClient)
	reconciler := &Reconciler{Client: fc, Scheme: scheme}

	ids, err := reconciler.aggregateAllowedUserGroupIDs(ctx, oidcClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 IDs, got %v", ids)
	}
	idSet := map[string]bool{}
	for _, id := range ids {
		idSet[id] = true
	}
	if !idSet["gid-a"] || !idSet["gid-b"] {
		t.Errorf("expected {gid-a, gid-b}, got %v", ids)
	}
}

func TestAggregateAllowedUserGroupIDs_SkipsNotReady(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group-nr", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			AllowedOIDCClients: []pocketidinternalv1alpha1.NamespacedOIDCClientReference{{Name: "client-4"}},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{GroupID: "gid-nr"},
	}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "client-4", Namespace: testNamespace},
	}

	fc := newAggregationFakeClient(scheme, group, oidcClient)
	reconciler := &Reconciler{Client: fc, Scheme: scheme}

	ids, err := reconciler.aggregateAllowedUserGroupIDs(ctx, oidcClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected empty (not-ready group skipped), got %v", ids)
	}
}

func TestAggregateAllowedUserGroupIDs_NilWhenNoRefs(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "client-5", Namespace: testNamespace},
	}

	fc := newAggregationFakeClient(scheme, oidcClient)
	reconciler := &Reconciler{Client: fc, Scheme: scheme}

	ids, err := reconciler.aggregateAllowedUserGroupIDs(ctx, oidcClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ids != nil {
		t.Errorf("expected nil when no refs from either side, got %v", ids)
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

// --- SCIM unit tests ---

// fakeSCIMAPI is a minimal implementation of PocketIDOIDCClientAPI for SCIM tests.
// Only SCIM-related methods are used; the rest panic if called unexpectedly.
type fakeSCIMAPI struct {
	existingProvider   *pocketid.SCIMServiceProvider // returned by GetOIDCClientSCIMServiceProvider
	getProviderErr     error
	createErr          error
	updateErr          error
	deleteErr          error
	created            *pocketid.SCIMServiceProviderInput
	updated            map[string]pocketid.SCIMServiceProviderInput // keyed by SCIM provider ID
	deleted            []string                                     // SCIM provider IDs passed to Delete
	getProviderCallIDs []string                                     // oidcClientIDs passed to GetOIDCClientSCIMServiceProvider
}

func (f *fakeSCIMAPI) ListOIDCClients(_ context.Context, _ string) ([]*pocketid.OIDCClient, error) {
	panic("not implemented")
}
func (f *fakeSCIMAPI) CreateOIDCClient(_ context.Context, _ pocketid.OIDCClientInput) (*pocketid.OIDCClient, error) {
	panic("not implemented")
}
func (f *fakeSCIMAPI) GetOIDCClient(_ context.Context, _ string) (*pocketid.OIDCClient, error) {
	panic("not implemented")
}
func (f *fakeSCIMAPI) UpdateOIDCClient(_ context.Context, _ string, _ pocketid.OIDCClientInput) (*pocketid.OIDCClient, error) {
	panic("not implemented")
}
func (f *fakeSCIMAPI) UpdateOIDCClientAllowedGroups(_ context.Context, _ string, _ []string) error {
	panic("not implemented")
}
func (f *fakeSCIMAPI) GetOIDCClientSCIMServiceProvider(_ context.Context, oidcClientID string) (*pocketid.SCIMServiceProvider, error) {
	f.getProviderCallIDs = append(f.getProviderCallIDs, oidcClientID)
	return f.existingProvider, f.getProviderErr
}
func (f *fakeSCIMAPI) CreateSCIMServiceProvider(_ context.Context, input pocketid.SCIMServiceProviderInput) (*pocketid.SCIMServiceProvider, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.created = &input
	return &pocketid.SCIMServiceProvider{ID: "new-scim-id", Endpoint: input.Endpoint, Token: input.Token}, nil
}
func (f *fakeSCIMAPI) UpdateSCIMServiceProvider(_ context.Context, id string, input pocketid.SCIMServiceProviderInput) (*pocketid.SCIMServiceProvider, error) {
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	if f.updated == nil {
		f.updated = make(map[string]pocketid.SCIMServiceProviderInput)
	}
	f.updated[id] = input
	return &pocketid.SCIMServiceProvider{ID: id, Endpoint: input.Endpoint, Token: input.Token}, nil
}
func (f *fakeSCIMAPI) DeleteSCIMServiceProvider(_ context.Context, id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, id)
	return nil
}

// newSCIMReconciler creates a Reconciler with a fake K8s client and the given objects.
func newSCIMReconciler(t *testing.T, objs ...client.Object) *Reconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := pocketidinternalv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithStatusSubresource(objs...).Build()
	r := &Reconciler{Client: fc, Scheme: scheme}
	r.EnsureClient(fc)
	return r
}

func oidcClientWithSCIM(scimSpec *pocketidinternalv1alpha1.SCIMSpec, scimProviderID string) *pocketidinternalv1alpha1.PocketIDOIDCClient {
	return &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "test-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			SCIM: scimSpec,
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			ClientID:       "oidc-client-id",
			SCIMProviderID: scimProviderID,
		},
	}
}

func TestReconcileSCIM_NoSpec_NoTrackedID_NoExisting(t *testing.T) {
	// spec.scim == nil, status.scimProviderID == "", client not yet ready (adoption path):
	// should call GetOIDCClientSCIMServiceProvider to check for stale providers, find none, no-op.
	ctx := context.Background()
	oidcClient := oidcClientWithSCIM(nil, "") // no conditions → not ready
	r := newSCIMReconciler(t, oidcClient)
	api := &fakeSCIMAPI{existingProvider: nil}

	if err := r.ReconcileSCIM(ctx, oidcClient, api); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(api.getProviderCallIDs) == 0 {
		t.Error("expected GetOIDCClientSCIMServiceProvider to be called on first reconcile (not-ready path)")
	}
	if len(api.deleted) > 0 {
		t.Errorf("expected no deletions, got %v", api.deleted)
	}
}

func TestReconcileSCIM_NoSpec_NoTrackedID_SkipsCheckWhenReady(t *testing.T) {
	// spec.scim == nil, status.scimProviderID == "", client already Ready:
	// should NOT call GetOIDCClientSCIMServiceProvider — state is already known clean.
	ctx := context.Background()
	oidcClient := oidcClientWithSCIM(nil, "")
	oidcClient.Status.Conditions = []metav1.Condition{
		{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled"},
	}
	r := newSCIMReconciler(t, oidcClient)
	api := &fakeSCIMAPI{}

	if err := r.ReconcileSCIM(ctx, oidcClient, api); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(api.getProviderCallIDs) > 0 {
		t.Errorf("expected GetOIDCClientSCIMServiceProvider to be skipped when Ready, but it was called with %v", api.getProviderCallIDs)
	}
	if len(api.deleted) > 0 {
		t.Errorf("expected no deletions, got %v", api.deleted)
	}
}

func TestReconcileSCIM_NoSpec_WithTrackedID_DeletesIt(t *testing.T) {
	// spec.scim == nil but status.scimProviderID is set → must delete
	ctx := context.Background()
	oidcClient := oidcClientWithSCIM(nil, "existing-scim-id")
	r := newSCIMReconciler(t, oidcClient)
	api := &fakeSCIMAPI{}

	if err := r.ReconcileSCIM(ctx, oidcClient, api); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(api.deleted) != 1 || api.deleted[0] != "existing-scim-id" {
		t.Errorf("expected deletion of existing-scim-id, got %v", api.deleted)
	}
	if oidcClient.Status.SCIMProviderID != "" {
		t.Errorf("expected SCIMProviderID to be cleared, got %q", oidcClient.Status.SCIMProviderID)
	}
}

func TestReconcileSCIM_NoSpec_NoTrackedID_StaleInPocketID_DeletesIt(t *testing.T) {
	// Adoption scenario: spec.scim == nil, no tracked ID, client not yet ready,
	// but pocket-id has an existing provider — should detect and delete it.
	ctx := context.Background()
	oidcClient := oidcClientWithSCIM(nil, "") // no conditions → not ready, triggers stale check
	r := newSCIMReconciler(t, oidcClient)
	api := &fakeSCIMAPI{
		existingProvider: &pocketid.SCIMServiceProvider{ID: "stale-scim-id", Endpoint: "https://old.example.com/scim"},
	}

	if err := r.ReconcileSCIM(ctx, oidcClient, api); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(api.getProviderCallIDs) == 0 {
		t.Error("expected GetOIDCClientSCIMServiceProvider to be called to detect stale provider")
	}
	if len(api.deleted) != 1 || api.deleted[0] != "stale-scim-id" {
		t.Errorf("expected deletion of stale-scim-id, got %v", api.deleted)
	}
}

func TestReconcileSCIM_WithSpec_NoTrackedID_NoExisting_Creates(t *testing.T) {
	// spec.scim set, no tracked ID, pocket-id has nothing → create
	ctx := context.Background()
	oidcClient := oidcClientWithSCIM(&pocketidinternalv1alpha1.SCIMSpec{
		Endpoint: "https://scim.example.com/v2",
	}, "")
	r := newSCIMReconciler(t, oidcClient)
	api := &fakeSCIMAPI{existingProvider: nil}

	if err := r.ReconcileSCIM(ctx, oidcClient, api); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if api.created == nil {
		t.Fatal("expected CreateSCIMServiceProvider to be called")
	}
	if api.created.Endpoint != "https://scim.example.com/v2" {
		t.Errorf("expected endpoint %q, got %q", "https://scim.example.com/v2", api.created.Endpoint)
	}
	if api.created.OIDCClientID != "oidc-client-id" {
		t.Errorf("expected OIDCClientID %q, got %q", "oidc-client-id", api.created.OIDCClientID)
	}
	if oidcClient.Status.SCIMProviderID != "new-scim-id" {
		t.Errorf("expected SCIMProviderID %q, got %q", "new-scim-id", oidcClient.Status.SCIMProviderID)
	}
}

func TestReconcileSCIM_WithSpec_NoTrackedID_ExistingInPocketID_Adopts(t *testing.T) {
	// spec.scim set, no tracked ID, pocket-id already has one → adopt (update + set ID)
	ctx := context.Background()
	oidcClient := oidcClientWithSCIM(&pocketidinternalv1alpha1.SCIMSpec{
		Endpoint: "https://scim.example.com/v2",
	}, "")
	r := newSCIMReconciler(t, oidcClient)
	api := &fakeSCIMAPI{
		existingProvider: &pocketid.SCIMServiceProvider{ID: "adopt-scim-id", Endpoint: "https://old.example.com/scim"},
	}

	if err := r.ReconcileSCIM(ctx, oidcClient, api); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if api.created != nil {
		t.Error("expected no create call during adoption")
	}
	if _, ok := api.updated["adopt-scim-id"]; !ok {
		t.Errorf("expected update of adopt-scim-id, updated map: %v", api.updated)
	}
	if oidcClient.Status.SCIMProviderID != "adopt-scim-id" {
		t.Errorf("expected SCIMProviderID %q, got %q", "adopt-scim-id", oidcClient.Status.SCIMProviderID)
	}
}

func TestReconcileSCIM_WithSpec_WithTrackedID_Updates(t *testing.T) {
	// spec.scim set, tracked ID exists → update
	ctx := context.Background()
	oidcClient := oidcClientWithSCIM(&pocketidinternalv1alpha1.SCIMSpec{
		Endpoint: "https://scim.example.com/v2",
	}, "tracked-scim-id")
	r := newSCIMReconciler(t, oidcClient)
	api := &fakeSCIMAPI{}

	if err := r.ReconcileSCIM(ctx, oidcClient, api); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if api.created != nil {
		t.Error("expected no create call")
	}
	input, ok := api.updated["tracked-scim-id"]
	if !ok {
		t.Fatalf("expected update of tracked-scim-id, updated map: %v", api.updated)
	}
	if input.Endpoint != "https://scim.example.com/v2" {
		t.Errorf("expected endpoint %q, got %q", "https://scim.example.com/v2", input.Endpoint)
	}
}

func TestReconcileSCIM_TokenFromSecret(t *testing.T) {
	// spec.scim.tokenSecretRef resolves correctly from a K8s Secret
	ctx := context.Background()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "scim-token-secret", Namespace: testNamespace},
		Data:       map[string][]byte{"token": []byte("super-secret-token")},
	}
	oidcClient := oidcClientWithSCIM(&pocketidinternalv1alpha1.SCIMSpec{
		Endpoint: "https://scim.example.com/v2",
		TokenSecretRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "scim-token-secret"},
			Key:                  "token",
		},
	}, "")
	r := newSCIMReconciler(t, oidcClient, secret)
	api := &fakeSCIMAPI{existingProvider: nil}

	if err := r.ReconcileSCIM(ctx, oidcClient, api); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if api.created == nil {
		t.Fatal("expected CreateSCIMServiceProvider to be called")
	}
	if api.created.Token != "super-secret-token" {
		t.Errorf("expected token %q, got %q", "super-secret-token", api.created.Token)
	}
}

func TestReconcileSCIM_TokenFromSecret_MissingSecret_ReturnsError(t *testing.T) {
	// tokenSecretRef references a non-existent Secret → error
	ctx := context.Background()
	oidcClient := oidcClientWithSCIM(&pocketidinternalv1alpha1.SCIMSpec{
		Endpoint: "https://scim.example.com/v2",
		TokenSecretRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "does-not-exist"},
			Key:                  "token",
		},
	}, "")
	r := newSCIMReconciler(t, oidcClient)
	api := &fakeSCIMAPI{}

	err := r.ReconcileSCIM(ctx, oidcClient, api)
	if err == nil {
		t.Fatal("expected error for missing secret, got nil")
	}
}

func TestReconcileSCIM_TokenFromSecret_MissingKey_ReturnsError(t *testing.T) {
	// Secret exists but the key is absent → error
	ctx := context.Background()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "scim-token-secret", Namespace: testNamespace},
		Data:       map[string][]byte{"other-key": []byte("value")},
	}
	oidcClient := oidcClientWithSCIM(&pocketidinternalv1alpha1.SCIMSpec{
		Endpoint: "https://scim.example.com/v2",
		TokenSecretRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "scim-token-secret"},
			Key:                  "token",
		},
	}, "")
	r := newSCIMReconciler(t, oidcClient, secret)
	api := &fakeSCIMAPI{}

	err := r.ReconcileSCIM(ctx, oidcClient, api)
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
}
