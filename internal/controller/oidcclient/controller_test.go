package oidcclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
	"github.com/aclerici38/pocket-id-operator/internal/metrics"
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

	input := reconciler.OidcClientInput(oidc, nil, "https://example.com/logo.png", "https://example.com/logo-dark.png")
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

func TestOidcClientName_DefaultsToMetadataName(t *testing.T) {
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "k8s-name"},
	}
	if got := oidcClientName(oidcClient); got != "k8s-name" {
		t.Errorf("expected metadata.name %q, got %q", "k8s-name", got)
	}
}

func TestOidcClientName_UsesSpecName(t *testing.T) {
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "k8s-name"},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Name: "display-name",
		},
	}
	if got := oidcClientName(oidcClient); got != "display-name" {
		t.Errorf("expected spec.name %q, got %q", "display-name", got)
	}
}

func TestOidcClientInput_UsesSpecNameWhenSet(t *testing.T) {
	reconciler := &Reconciler{}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "k8s-name"},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Name: "display-name",
		},
	}
	input := reconciler.OidcClientInput(oidcClient, nil, "", "")
	if input.Name != "display-name" {
		t.Errorf("expected spec.name %q in OIDCClientInput.Name, got %q", "display-name", input.Name)
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

func TestGetSecretAdditionalLabels(t *testing.T) {
	reconciler := &Reconciler{}

	testLabels := map[string]string{"label-1": "value1", "label-2": "value2"}

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-client",
		},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{
				AdditionalLabels: testLabels,
			},
		},
	}

	labels := reconciler.GetSecretLabels(oidcClient)

	if _, exists := labels["label-1"]; !exists {
		t.Errorf("expected label %q to exist", "label-1")
	} else {
		if labels["label-1"] != "value1" {
			t.Errorf("expected label %q to have value %q", "label-1", "value1")
		}
	}

	if _, exists := labels["label-2"]; !exists {
		t.Errorf("expected label %q to exist", "label-2")
	} else {
		if labels["label-2"] != "value2" {
			t.Errorf("expected label %q to have value %q", "label-2", "value2")
		}
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
			// The operator stamps this label on every secret it creates; a
			// secret it manages must be deleted when the secret is disabled.
			Labels: map[string]string{common.ManagedByLabelKey: common.ManagedByLabelValue},
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
			EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
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
			EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
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
			EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
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

// TestReconcileSecret_StoreClientSecretDisabled verifies that storeClientSecret=false
// skips regeneration entirely (a nil apiClient would error if the regenerate branch ran),
// omits client_secret from the secret, and drops a pre-existing client_secret key. The
// manual regenerate annotation must also be ignored rather than regenerating a value
// that would then be discarded.
func TestReconcileSecret_StoreClientSecretDisabled(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	for _, tc := range []struct {
		name            string
		existingSecret  *corev1.Secret
		regenAnnotation bool
	}{
		{name: "new secret omits client_secret"},
		{name: "existing client_secret key is dropped", existingSecret: &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-no-store-oidc-credentials",
				Namespace: testNamespace,
				Labels:    common.ManagedByLabels(nil),
			},
			Data: map[string][]byte{"client_id": []byte("client-123"), "client_secret": []byte("old-secret")},
		}},
		{name: "manual regenerate annotation is ignored", regenAnnotation: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-no-store",
					Namespace: testNamespace,
					UID:       "test-uid-no-store",
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					CallbackURLs: []string{"https://example.com/callback"},
					Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{
						StoreClientSecret: boolPtr(false),
					},
				},
				Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
					ClientID: "client-123",
				},
			}
			if tc.regenAnnotation {
				oidcClient.Annotations = map[string]string{"pocketid.internal/regenerate-client-secret": "true"}
			}

			instance := &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: testNamespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					AppURL:        "http://test.example.com",
					EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
				},
			}

			objs := []client.Object{oidcClient, instance}
			if tc.existingSecret != nil {
				objs = append(objs, tc.existingSecret)
			}
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(objs...).
				Build()

			reconciler := &Reconciler{
				Client: fakeClient,
				Scheme: scheme,
			}

			// nil apiClient: regenerating would fail, proving the branch is skipped.
			if err := reconciler.ReconcileSecret(ctx, oidcClient, instance, nil); err != nil {
				t.Fatalf("ReconcileSecret returned error: %v", err)
			}

			secret := &corev1.Secret{}
			if err := fakeClient.Get(ctx, client.ObjectKey{
				Name:      "test-no-store-oidc-credentials",
				Namespace: testNamespace,
			}, secret); err != nil {
				t.Fatalf("expected secret to exist: %v", err)
			}

			if _, ok := secret.Data["client_secret"]; ok {
				t.Error("expected secret to NOT have client_secret key when storeClientSecret is false")
			}
			if _, ok := secret.Data["client_id"]; !ok {
				t.Error("expected secret to have client_id key")
			}
			if _, ok := secret.Data["issuer_url"]; !ok {
				t.Error("expected secret to have issuer_url key")
			}
		})
	}
}

// TestReconcileSecret_StoreClientSecretDisabledClearsRotationGauges guards against stale
// rotation metrics: when rotation and storeClientSecret are turned off in the same update,
// the regeneration block is skipped entirely, so the skip path itself must record the
// schedule as disabled and delete the schedule gauges left by the previously enabled config.
func TestReconcileSecret_StoreClientSecretDisabledClearsRotationGauges(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	const name = "test-no-store-gauges"

	// Simulate gauges left behind by a previously enabled rotation schedule.
	metrics.SetOIDCClientRotationEnabled(testNamespace, name, true)
	metrics.SetOIDCClientRotationSchedule(testNamespace, name, 3600, 1_700_000_000, 1_700_003_600)

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace, UID: "test-uid-no-store-gauges"},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			CallbackURLs: []string{"https://example.com/callback"},
			Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{
				StoreClientSecret: boolPtr(false),
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "client-gauges"},
	}
	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "test-instance", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			AppURL:        "http://test.example.com",
			EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(oidcClient, instance).Build()
	reconciler := &Reconciler{Client: fakeClient, Scheme: scheme}

	if err := reconciler.ReconcileSecret(ctx, oidcClient, instance, nil); err != nil {
		t.Fatalf("ReconcileSecret returned error: %v", err)
	}

	if got := testutil.ToFloat64(metrics.OIDCClientRotationEnabled.WithLabelValues(testNamespace, name)); got != 0 {
		t.Errorf("expected rotation enabled gauge to be 0, got %v", got)
	}
	// DeleteLabelValues reports whether the series existed; the schedule gauges must be gone.
	if metrics.OIDCClientRotationIntervalSeconds.DeleteLabelValues(testNamespace, name) {
		t.Error("expected rotation interval gauge to have been deleted")
	}
	if metrics.OIDCClientLastRotationTimestamp.DeleteLabelValues(testNamespace, name) {
		t.Error("expected last rotation timestamp gauge to have been deleted")
	}
	if metrics.OIDCClientNextRotationTimestamp.DeleteLabelValues(testNamespace, name) {
		t.Error("expected next rotation timestamp gauge to have been deleted")
	}
}

// TestAdvanceInstanceRotationStatus covers the min-spacing aggregate self-heal: the secret's
// lastRotatedAtAnnotation is the durable source of truth, and instance.Status.LastRotatedClientSecret
// must converge to it on a later reconcile even if the original status write was lost — without ever
// regressing a value another client already moved past.
func TestAdvanceInstanceRotationStatus(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	t1 := time.Now().UTC().Truncate(time.Second)
	t2 := t1.Add(time.Hour)

	secretWith := func(ts *time.Time) *corev1.Secret {
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "sec", Namespace: testNamespace}}
		if ts != nil {
			s.Annotations = map[string]string{lastScheduledRotationAtAnnotation: ts.Format(time.RFC3339)}
		}
		return s
	}
	instanceWith := func(ts *time.Time) *pocketidinternalv1alpha1.PocketIDInstance {
		inst := &pocketidinternalv1alpha1.PocketIDInstance{
			ObjectMeta: metav1.ObjectMeta{Name: "test-instance", Namespace: testNamespace},
		}
		if ts != nil {
			inst.Status.LastRotatedClientSecret = &metav1.Time{Time: *ts}
		}
		return inst
	}
	tp := func(ts time.Time) *time.Time { return &ts }

	tests := []struct {
		name        string
		storedAgg   *time.Time // aggregate persisted on the API server (what APIReader sees)
		cachedAgg   *time.Time // aggregate on the in-scope (possibly stale) instance
		annotation  *time.Time // secret's lastRotatedAtAnnotation, nil = no annotation
		rotatedNow  bool       // whether the rotation happened in this same reconcile
		wantStored  *time.Time // expected persisted aggregate after the call
		wantPatched bool       // whether the stored object should have changed
	}{
		{
			name:        "self-heal from lost write",
			storedAgg:   nil, // previous reconcile rotated but failed to persist this
			cachedAgg:   nil,
			annotation:  tp(t1),
			rotatedNow:  false, // not this reconcile → genuine lost-write
			wantStored:  tp(t1),
			wantPatched: true,
		},
		{
			name:        "expected advance after this reconcile's rotation",
			storedAgg:   nil, // we are the first writer of the aggregate for this rotation
			cachedAgg:   nil,
			annotation:  tp(t1),
			rotatedNow:  true,
			wantStored:  tp(t1),
			wantPatched: true,
		},
		{
			name:       "already in sync skips the write",
			storedAgg:  tp(t1),
			cachedAgg:  tp(t1),
			annotation: tp(t1),
			wantStored: tp(t1),
		},
		{
			name:       "stale cache but fresh already ahead does not regress",
			storedAgg:  tp(t2), // another client already advanced it past us
			cachedAgg:  nil,    // our cached view is behind, forcing the fresh read
			annotation: tp(t1),
			wantStored: tp(t2),
		},
		{
			// A manual-only rotation never writes lastScheduledRotationAtAnnotation, so the
			// aggregate must not move even though the secret was rotated.
			name:       "manual rotation (no scheduled annotation) does not advance",
			storedAgg:  nil,
			cachedAgg:  nil,
			annotation: nil,
			wantStored: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stored := instanceWith(tc.storedAgg)
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(stored).
				WithStatusSubresource(stored).
				Build()

			reconciler := &Reconciler{Client: fakeClient, APIReader: fakeClient, Scheme: scheme}

			// The in-scope instance carries the (possibly stale) cached aggregate.
			cached := instanceWith(tc.cachedAgg)
			cached.ResourceVersion = stored.ResourceVersion

			if err := reconciler.advanceInstanceRotationStatus(context.Background(), cached, secretWith(tc.annotation), tc.rotatedNow); err != nil {
				t.Fatalf("advanceInstanceRotationStatus returned error: %v", err)
			}

			got := &pocketidinternalv1alpha1.PocketIDInstance{}
			if err := fakeClient.Get(context.Background(), client.ObjectKey{Name: "test-instance", Namespace: testNamespace}, got); err != nil {
				t.Fatalf("failed to get instance: %v", err)
			}

			switch {
			case tc.wantStored == nil && got.Status.LastRotatedClientSecret != nil:
				t.Fatalf("expected aggregate to stay unset, got %v", got.Status.LastRotatedClientSecret)
			case tc.wantStored != nil && got.Status.LastRotatedClientSecret == nil:
				t.Fatalf("expected aggregate %v, got nil", tc.wantStored)
			case tc.wantStored != nil && !got.Status.LastRotatedClientSecret.Time.Equal(*tc.wantStored):
				t.Fatalf("expected aggregate %v, got %v", tc.wantStored, got.Status.LastRotatedClientSecret.Time)
			}

			if tc.wantPatched && got.ResourceVersion == stored.ResourceVersion {
				t.Fatalf("expected a status write but resourceVersion was unchanged (%s)", got.ResourceVersion)
			}
		})
	}
}

// rotationSecretServer returns an httptest server that answers the regenerate-secret endpoint.
func rotationSecretServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secret":"rotated-secret"}`))
	}))
}

// TestReconcileSecret_ScheduledRotation verifies a scheduled rotation writes BOTH secret
// annotations, mirrors the per-client LastRotatedAt, and advances the instance aggregate.
func TestReconcileSecret_ScheduledRotation(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "rot-client", Namespace: testNamespace, UID: "rot-uid"},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			CallbackURLs: []string{"https://example.com/cb"},
			ClientSecretRotation: &pocketidinternalv1alpha1.ClientSecretRotation{
				Enabled:  true,
				Interval: &metav1.Duration{Duration: 24 * time.Hour},
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "rot-id"},
	}

	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rot-client-oidc-credentials",
			Namespace: testNamespace,
			// Last rotation was 48h ago and the 24h interval has elapsed → rotation is due.
			Annotations: map[string]string{
				lastRotatedAtAnnotation: time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339),
			},
		},
		Data: map[string][]byte{
			"client_id":     []byte("rot-id"),
			"client_secret": []byte("old-secret"),
		},
	}

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "test-instance", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			AppURL:        "http://test.example.com",
			EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(oidcClient, existingSecret, instance).
		WithStatusSubresource(oidcClient, instance).
		Build()

	ts := rotationSecretServer(t)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	reconciler := &Reconciler{Client: fakeClient, APIReader: fakeClient, Scheme: scheme}
	if err := reconciler.ReconcileSecret(ctx, oidcClient, instance, apiClient); err != nil {
		t.Fatalf("ReconcileSecret returned error: %v", err)
	}

	gotSecret := &corev1.Secret{}
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: existingSecret.Name, Namespace: testNamespace}, gotSecret); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if got := string(gotSecret.Data["client_secret"]); got != "rotated-secret" {
		t.Errorf("expected rotated client_secret, got %q", got)
	}
	if _, ok := gotSecret.Annotations[lastRotatedAtAnnotation]; !ok {
		t.Error("expected lastRotatedAtAnnotation to be set")
	}
	if _, ok := gotSecret.Annotations[lastScheduledRotationAtAnnotation]; !ok {
		t.Error("expected lastScheduledRotationAtAnnotation to be set for a scheduled rotation")
	}

	gotInstance := &pocketidinternalv1alpha1.PocketIDInstance{}
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: "test-instance", Namespace: testNamespace}, gotInstance); err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if gotInstance.Status.LastRotatedClientSecret == nil {
		t.Error("expected instance LastRotatedClientSecret to advance for a scheduled rotation")
	}

	gotClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: "rot-client", Namespace: testNamespace}, gotClient); err != nil {
		t.Fatalf("get oidcclient: %v", err)
	}
	if gotClient.Status.LastRotatedAt == nil {
		t.Error("expected oidcclient LastRotatedAt to be mirrored")
	}
}

// TestReconcileSecret_WindowDrivenRotation is the window-driven analog of the scheduled-rotation
// round trip: no interval, only a maintenance window that is currently open with a missed opening
// owed. It must rotate the secret, stamp both rotation annotations, advance the instance aggregate,
// and mirror status — proving window-driven rotations are first-class scheduled rotations.
func TestReconcileSecret_WindowDrivenRotation(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// A daily window that opened a minute ago and stays open 30m → reliably open now.
	opened := time.Now().Add(-1 * time.Minute)
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "rot-client", Namespace: testNamespace, UID: "rot-uid"},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			CallbackURLs: []string{"https://example.com/cb"},
			ClientSecretRotation: &pocketidinternalv1alpha1.ClientSecretRotation{
				Enabled: true,
				Window: &pocketidinternalv1alpha1.RotationWindow{
					Opens:       fmt.Sprintf("%d %d * * *", opened.Minute(), opened.Hour()),
					ClosesAfter: metav1.Duration{Duration: 30 * time.Minute},
				},
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "rot-id"},
	}

	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rot-client-oidc-credentials",
			Namespace: testNamespace,
			// Last rotation was 48h ago, before this opening → an opening is owed.
			Annotations: map[string]string{
				lastRotatedAtAnnotation: time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339),
			},
		},
		Data: map[string][]byte{
			"client_id":     []byte("rot-id"),
			"client_secret": []byte("old-secret"),
		},
	}

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "test-instance", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			AppURL:        "http://test.example.com",
			EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(oidcClient, existingSecret, instance).
		WithStatusSubresource(oidcClient, instance).
		Build()

	ts := rotationSecretServer(t)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	reconciler := &Reconciler{Client: fakeClient, APIReader: fakeClient, Scheme: scheme}
	if err := reconciler.ReconcileSecret(ctx, oidcClient, instance, apiClient); err != nil {
		t.Fatalf("ReconcileSecret returned error: %v", err)
	}

	gotSecret := &corev1.Secret{}
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: existingSecret.Name, Namespace: testNamespace}, gotSecret); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if got := string(gotSecret.Data["client_secret"]); got != "rotated-secret" {
		t.Errorf("expected rotated client_secret, got %q", got)
	}
	if _, ok := gotSecret.Annotations[lastRotatedAtAnnotation]; !ok {
		t.Error("expected lastRotatedAtAnnotation to be set")
	}
	if _, ok := gotSecret.Annotations[lastScheduledRotationAtAnnotation]; !ok {
		t.Error("expected lastScheduledRotationAtAnnotation to be set for a window-driven scheduled rotation")
	}

	gotInstance := &pocketidinternalv1alpha1.PocketIDInstance{}
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: "test-instance", Namespace: testNamespace}, gotInstance); err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if gotInstance.Status.LastRotatedClientSecret == nil {
		t.Error("expected instance LastRotatedClientSecret to advance for a window-driven rotation")
	}

	gotClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: "rot-client", Namespace: testNamespace}, gotClient); err != nil {
		t.Fatalf("get oidcclient: %v", err)
	}
	if gotClient.Status.LastRotatedAt == nil {
		t.Error("expected oidcclient LastRotatedAt to be mirrored")
	}
}

// TestReconcileSecret_ManualRotation verifies a manual (annotation-triggered) rotation writes
// only lastRotatedAtAnnotation and mirrors LastRotatedAt, but does NOT write the scheduled
// annotation or advance the instance aggregate.
func TestReconcileSecret_ManualRotation(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "man-client",
			Namespace:   testNamespace,
			UID:         "man-uid",
			Annotations: map[string]string{"pocketid.internal/regenerate-client-secret": "true"},
		},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			CallbackURLs: []string{"https://example.com/cb"},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "man-id"},
	}

	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "man-client-oidc-credentials", Namespace: testNamespace},
		Data: map[string][]byte{
			"client_id":     []byte("man-id"),
			"client_secret": []byte("old-secret"),
		},
	}

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "test-instance", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			AppURL:        "http://test.example.com",
			EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(oidcClient, existingSecret, instance).
		WithStatusSubresource(oidcClient, instance).
		Build()

	ts := rotationSecretServer(t)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	reconciler := &Reconciler{Client: fakeClient, APIReader: fakeClient, Scheme: scheme}
	if err := reconciler.ReconcileSecret(ctx, oidcClient, instance, apiClient); err != nil {
		t.Fatalf("ReconcileSecret returned error: %v", err)
	}

	gotSecret := &corev1.Secret{}
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: existingSecret.Name, Namespace: testNamespace}, gotSecret); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if got := string(gotSecret.Data["client_secret"]); got != "rotated-secret" {
		t.Errorf("expected rotated client_secret, got %q", got)
	}
	if _, ok := gotSecret.Annotations[lastRotatedAtAnnotation]; !ok {
		t.Error("expected lastRotatedAtAnnotation to be set for a manual rotation")
	}
	if _, ok := gotSecret.Annotations[lastScheduledRotationAtAnnotation]; ok {
		t.Error("manual rotation must NOT set lastScheduledRotationAtAnnotation")
	}

	gotInstance := &pocketidinternalv1alpha1.PocketIDInstance{}
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: "test-instance", Namespace: testNamespace}, gotInstance); err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if gotInstance.Status.LastRotatedClientSecret != nil {
		t.Errorf("manual rotation must NOT advance the instance aggregate, got %v", gotInstance.Status.LastRotatedClientSecret)
	}

	gotClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: "man-client", Namespace: testNamespace}, gotClient); err != nil {
		t.Fatalf("get oidcclient: %v", err)
	}
	if gotClient.Status.LastRotatedAt == nil {
		t.Error("expected oidcclient LastRotatedAt to be mirrored for a manual rotation")
	}
}

// TestReconcileSecret_InitialCreationIsNotScheduled is the regression guard for the most
// dangerous annotation-drift case: a confidential client with rotation ENABLED whose secret does
// not exist yet. This first reconcile must perform an "initial" (unscheduled) creation — it stamps
// lastRotatedAtAnnotation to start the interval clock, but must NOT stamp the scheduled annotation
// and must NOT advance the instance aggregate. If initial creations counted as scheduled
// rotations, a fleet of newly-created clients would each consume the instance-wide min-spacing
// budget and starve one another.
func TestReconcileSecret_InitialCreationIsNotScheduled(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "init-client", Namespace: testNamespace, UID: "init-uid"},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			CallbackURLs: []string{"https://example.com/cb"},
			// Rotation is enabled, but with no secret yet the secret must still be created via the
			// initial (unscheduled) path rather than treated as a scheduled rotation.
			ClientSecretRotation: &pocketidinternalv1alpha1.ClientSecretRotation{
				Enabled:  true,
				Interval: &metav1.Duration{Duration: 24 * time.Hour},
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "init-id"},
	}

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "test-instance", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			AppURL:        "http://test.example.com",
			EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
		},
	}

	// No existing secret in the store → initial creation.
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(oidcClient, instance).
		WithStatusSubresource(oidcClient, instance).
		Build()

	ts := rotationSecretServer(t)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	reconciler := &Reconciler{Client: fakeClient, APIReader: fakeClient, Scheme: scheme}
	if err := reconciler.ReconcileSecret(ctx, oidcClient, instance, apiClient); err != nil {
		t.Fatalf("ReconcileSecret returned error: %v", err)
	}

	gotSecret := &corev1.Secret{}
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: "init-client-oidc-credentials", Namespace: testNamespace}, gotSecret); err != nil {
		t.Fatalf("expected secret to be created: %v", err)
	}
	if got := string(gotSecret.Data["client_secret"]); got != "rotated-secret" {
		t.Errorf("expected a freshly generated client_secret, got %q", got)
	}
	// lastRotatedAtAnnotation IS set: initial creation is a rotation and must start the clock.
	if _, ok := gotSecret.Annotations[lastRotatedAtAnnotation]; !ok {
		t.Error("expected lastRotatedAtAnnotation to be set on initial creation")
	}
	// scheduled annotation must NOT be set: initial creation is not a scheduled rotation.
	if _, ok := gotSecret.Annotations[lastScheduledRotationAtAnnotation]; ok {
		t.Error("initial creation must NOT set lastScheduledRotationAtAnnotation")
	}

	// The instance aggregate must NOT advance — otherwise creating N clients would each consume
	// the global min-spacing budget.
	gotInstance := &pocketidinternalv1alpha1.PocketIDInstance{}
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: "test-instance", Namespace: testNamespace}, gotInstance); err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if gotInstance.Status.LastRotatedClientSecret != nil {
		t.Errorf("initial creation must NOT advance the instance aggregate, got %v", gotInstance.Status.LastRotatedClientSecret)
	}
}

// TestReconcileSecret_NotDuePreservesAnnotations is the regression guard against annotation drift
// on the steady-state path: a reconcile that does NOT rotate must leave the secret untouched. The
// existing lastRotatedAtAnnotation must survive byte-for-byte (re-stamping it would silently reset
// the interval anchor so the secret never rotates), the client_secret must stay as-is, no scheduled
// annotation may appear, and the instance aggregate must not move. A nil apiClient guarantees the
// test fails loudly if the code ever attempts a rotation it shouldn't.
func TestReconcileSecret_NotDuePreservesAnnotations(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	// Last rotation 1h ago against a 24h interval → not due.
	origRotatedAt := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "steady-client", Namespace: testNamespace, UID: "steady-uid"},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			CallbackURLs: []string{"https://example.com/cb"},
			ClientSecretRotation: &pocketidinternalv1alpha1.ClientSecretRotation{
				Enabled:  true,
				Interval: &metav1.Duration{Duration: 24 * time.Hour},
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "steady-id"},
	}

	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "steady-client-oidc-credentials",
			Namespace:   testNamespace,
			Annotations: map[string]string{lastRotatedAtAnnotation: origRotatedAt},
		},
		Data: map[string][]byte{
			"client_id":     []byte("steady-id"),
			"client_secret": []byte("old-secret"),
		},
	}

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "test-instance", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			AppURL:        "http://test.example.com",
			EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(oidcClient, existingSecret, instance).
		WithStatusSubresource(oidcClient, instance).
		Build()

	// nil apiClient: the not-due path must never call the rotation endpoint. If it tries, the
	// regenerate branch errors on the nil client and the test fails.
	reconciler := &Reconciler{Client: fakeClient, APIReader: fakeClient, Scheme: scheme}
	if err := reconciler.ReconcileSecret(ctx, oidcClient, instance, nil); err != nil {
		t.Fatalf("ReconcileSecret returned error: %v", err)
	}

	gotSecret := &corev1.Secret{}
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: existingSecret.Name, Namespace: testNamespace}, gotSecret); err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if got := string(gotSecret.Data["client_secret"]); got != "old-secret" {
		t.Errorf("not-due reconcile must preserve the existing client_secret, got %q", got)
	}
	if got := gotSecret.Annotations[lastRotatedAtAnnotation]; got != origRotatedAt {
		t.Errorf("not-due reconcile must preserve lastRotatedAtAnnotation verbatim (anchor drift): got %q, want %q", got, origRotatedAt)
	}
	if _, ok := gotSecret.Annotations[lastScheduledRotationAtAnnotation]; ok {
		t.Error("not-due reconcile must NOT create lastScheduledRotationAtAnnotation")
	}

	gotInstance := &pocketidinternalv1alpha1.PocketIDInstance{}
	if err := fakeClient.Get(ctx, client.ObjectKey{Name: "test-instance", Namespace: testNamespace}, gotInstance); err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if gotInstance.Status.LastRotatedClientSecret != nil {
		t.Errorf("not-due reconcile must NOT advance the instance aggregate, got %v", gotInstance.Status.LastRotatedClientSecret)
	}
}

// TestRotationDue locks the three-gate decision, most importantly that min-spacing actually
// blocks a scheduled rotation (the thundering-herd guarantee) and the gate precedence.
func TestRotationDue(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	now := time.Now()
	ann := func(d time.Duration) map[string]string {
		return map[string]string{lastRotatedAtAnnotation: now.Add(d).UTC().Format(time.RFC3339)}
	}
	rot := func(interval time.Duration, window *pocketidinternalv1alpha1.RotationWindow) *pocketidinternalv1alpha1.ClientSecretRotation {
		return &pocketidinternalv1alpha1.ClientSecretRotation{
			Enabled:  true,
			Interval: &metav1.Duration{Duration: interval},
			Window:   window,
		}
	}
	tp := func(d time.Duration) *metav1.Time { ts := metav1.NewTime(now.Add(d)); return &ts }

	// winRot builds a window-driven rotation: enabled with a window but no interval, so the
	// window opening is the sole trigger.
	winRot := func(window *pocketidinternalv1alpha1.RotationWindow) *pocketidinternalv1alpha1.ClientSecretRotation {
		return &pocketidinternalv1alpha1.ClientSecretRotation{Enabled: true, Window: window}
	}
	// openNowWindow builds a daily window whose most recent opening was a minute ago and stays
	// open 30m, so it is reliably open right now regardless of wall-clock time.
	openNowWindow := func() *pocketidinternalv1alpha1.RotationWindow {
		opened := time.Now().Add(-1 * time.Minute)
		return &pocketidinternalv1alpha1.RotationWindow{
			Opens:       fmt.Sprintf("%d %d * * *", opened.Minute(), opened.Hour()),
			ClosesAfter: metav1.Duration{Duration: 30 * time.Minute},
		}
	}
	// missedWindow builds a daily window that opened two hours ago and closed an hour ago, so it
	// is reliably closed now with its most recent opening in the recent past — modelling a missed
	// opening for a secret last rotated before it.
	missedWindow := func() *pocketidinternalv1alpha1.RotationWindow {
		opened := time.Now().Add(-2 * time.Hour)
		return &pocketidinternalv1alpha1.RotationWindow{
			Opens:       fmt.Sprintf("%d %d * * *", opened.Minute(), opened.Hour()),
			ClosesAfter: metav1.Duration{Duration: time.Hour},
		}
	}

	// closedWindow opens at midnight Jan 1 and stays open 1h — effectively always closed.
	closedWindow := &pocketidinternalv1alpha1.RotationWindow{Opens: "0 0 1 1 *", ClosesAfter: metav1.Duration{Duration: time.Hour}}

	tests := []struct {
		name       string
		rotation   *pocketidinternalv1alpha1.ClientSecretRotation
		secretAnn  map[string]string
		minSpacing time.Duration
		lastGlobal *metav1.Time
		omitInst   bool // omit the instance from the store → APIReader read fails
		wantDue    bool
		wantErr    bool
		wantDefer  string
	}{
		{name: "nil rotation is never due", rotation: nil, secretAnn: ann(-48 * time.Hour)},
		{name: "disabled rotation is never due", rotation: &pocketidinternalv1alpha1.ClientSecretRotation{Enabled: false, Interval: &metav1.Duration{Duration: time.Hour}}, secretAnn: ann(-48 * time.Hour)},
		{name: "interval not elapsed blocks", rotation: rot(24*time.Hour, nil), secretAnn: ann(-1 * time.Hour)},
		{name: "due when interval elapsed and spacing ok", rotation: rot(24*time.Hour, nil), secretAnn: ann(-48 * time.Hour), wantDue: true},
		{name: "window closed defers", rotation: rot(24*time.Hour, closedWindow), secretAnn: ann(-48 * time.Hour), wantDefer: "window_closed"},
		{name: "min-spacing blocks the herd", rotation: rot(24*time.Hour, nil), secretAnn: ann(-48 * time.Hour), minSpacing: time.Hour, lastGlobal: tp(-30 * time.Minute), wantDefer: "min_spacing"},
		{name: "min-spacing met allows rotation", rotation: rot(24*time.Hour, nil), secretAnn: ann(-48 * time.Hour), minSpacing: time.Hour, lastGlobal: tp(-90 * time.Minute), wantDue: true},
		{name: "invalid window config errors", rotation: rot(24*time.Hour, &pocketidinternalv1alpha1.RotationWindow{Opens: "* * * * *", ClosesAfter: metav1.Duration{Duration: 2 * time.Minute}}), secretAnn: ann(-48 * time.Hour), wantErr: true, wantDefer: "window_error"},
		{name: "APIReader failure errors", rotation: rot(24*time.Hour, nil), secretAnn: ann(-48 * time.Hour), omitInst: true, wantErr: true},

		// Window-driven rotation: interval unset, the window opening is the trigger.
		{name: "window-driven due when open and never rotated", rotation: winRot(openNowWindow()), wantDue: true},
		{name: "window-driven due when open and last rotation predates opening", rotation: winRot(openNowWindow()), secretAnn: ann(-48 * time.Hour), wantDue: true},
		{name: "window-driven not due when already rotated this opening", rotation: winRot(openNowWindow()), secretAnn: ann(-30 * time.Second)},
		// A missed opening (the window opened since the last rotation but is now closed) defers as
		// window_missed — distinct from interval mode's window_closed, which is healthy waiting for
		// an upcoming window rather than an opening that came and went unserved.
		{name: "window-driven missed opening defers as window_missed", rotation: winRot(missedWindow()), secretAnn: ann(-48 * time.Hour), wantDefer: "window_missed"},
		// No opening has occurred since the last rotation (closedWindow last fired Jan 1, before the
		// recent rotation), so nothing is owed and there is no deferral.
		{name: "window-driven not owed when no opening since last rotation", rotation: winRot(closedWindow), secretAnn: ann(-48 * time.Hour)},
		{name: "window-driven invalid window errors", rotation: winRot(&pocketidinternalv1alpha1.RotationWindow{Opens: "* * * * *", ClosesAfter: metav1.Duration{Duration: 2 * time.Minute}}), secretAnn: ann(-48 * time.Hour), wantErr: true, wantDefer: "window_error"},
		{name: "window-driven honors min-spacing", rotation: winRot(openNowWindow()), secretAnn: ann(-48 * time.Hour), minSpacing: time.Hour, lastGlobal: tp(-30 * time.Minute), wantDefer: "min_spacing"},
		{name: "window-driven due when min-spacing met", rotation: winRot(openNowWindow()), secretAnn: ann(-48 * time.Hour), minSpacing: time.Hour, lastGlobal: tp(-90 * time.Minute), wantDue: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testNamespace},
				Spec:       pocketidinternalv1alpha1.PocketIDOIDCClientSpec{ClientSecretRotation: tc.rotation},
			}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "c-oidc-credentials", Namespace: testNamespace, Annotations: tc.secretAnn}}
			instance := &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{Name: "test-instance", Namespace: testNamespace},
			}
			if tc.minSpacing > 0 {
				instance.Spec.OIDCClientRotation = &pocketidinternalv1alpha1.OIDCClientRotationConfig{MinSpacing: metav1.Duration{Duration: tc.minSpacing}}
			}
			instance.Status.LastRotatedClientSecret = tc.lastGlobal

			builder := fake.NewClientBuilder().WithScheme(scheme)
			if !tc.omitInst {
				builder = builder.WithObjects(instance)
			}
			fakeClient := builder.Build()

			r := &Reconciler{Client: fakeClient, APIReader: fakeClient, Scheme: scheme}
			eval, err := r.rotationDue(ctx, oidcClient, instance, secret)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if eval.deferReason != tc.wantDefer {
					t.Errorf("deferReason = %q, want %q", eval.deferReason, tc.wantDefer)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eval.due != tc.wantDue {
				t.Errorf("rotationDue = %v, want %v", eval.due, tc.wantDue)
			}
			if eval.deferReason != tc.wantDefer {
				t.Errorf("deferReason = %q, want %q", eval.deferReason, tc.wantDefer)
			}
		})
	}
}

// TestRotationTrigger exercises the trigger dispatcher (the only mode-specific seam) in both modes
// against a fixed clock. The window opens at 1am daily and stays open 4h (opens 1am, closes 5am);
// the most recent fire relative to the test instants is 1am on Jan 31.
func TestRotationTrigger(t *testing.T) {
	opensAt := time.Date(2026, 1, 31, 1, 0, 0, 0, time.UTC)
	insideWindow := time.Date(2026, 1, 31, 2, 0, 0, 0, time.UTC)
	outsideWindow := time.Date(2026, 1, 31, 6, 0, 0, 0, time.UTC)
	elapsedLR := time.Date(2026, 1, 29, 2, 0, 0, 0, time.UTC) // > 24h before either instant
	freshLR := opensAt                                        // 1h before insideWindow → interval not elapsed

	win4h := &pocketidinternalv1alpha1.RotationWindow{Opens: "0 1 * * *", ClosesAfter: metav1.Duration{Duration: 4 * time.Hour}}
	invalidWin := &pocketidinternalv1alpha1.RotationWindow{Opens: "* * * * *", ClosesAfter: metav1.Duration{Duration: 2 * time.Minute}}
	iv := func(w *pocketidinternalv1alpha1.RotationWindow) *pocketidinternalv1alpha1.ClientSecretRotation {
		return &pocketidinternalv1alpha1.ClientSecretRotation{Enabled: true, Interval: &metav1.Duration{Duration: 24 * time.Hour}, Window: w}
	}
	wd := func(w *pocketidinternalv1alpha1.RotationWindow) *pocketidinternalv1alpha1.ClientSecretRotation {
		return &pocketidinternalv1alpha1.ClientSecretRotation{Enabled: true, Window: w}
	}

	tests := []struct {
		name          string
		rotation      *pocketidinternalv1alpha1.ClientSecretRotation
		lastRotated   time.Time
		creation      time.Time
		now           time.Time
		wantOwed      bool
		wantWindow    bool // expected windowOpen
		wantHasWindow bool
		wantErr       bool
	}{
		// Interval-driven.
		{name: "interval elapsed, no window", rotation: iv(nil), lastRotated: elapsedLR, now: insideWindow, wantOwed: true},
		{name: "interval not elapsed, no window", rotation: iv(nil), lastRotated: freshLR, now: insideWindow},
		{name: "interval elapsed, window open", rotation: iv(win4h), lastRotated: elapsedLR, now: insideWindow, wantOwed: true, wantWindow: true, wantHasWindow: true},
		{name: "interval elapsed, window closed", rotation: iv(win4h), lastRotated: elapsedLR, now: outsideWindow, wantOwed: true, wantHasWindow: true},
		// The window is only evaluated once owed, so an invalid window is harmless until the interval fires.
		{name: "interval not elapsed, invalid window not evaluated", rotation: iv(invalidWin), lastRotated: freshLR, now: insideWindow, wantHasWindow: true},
		{name: "interval elapsed, invalid window errors", rotation: iv(invalidWin), lastRotated: elapsedLR, now: insideWindow, wantHasWindow: true, wantErr: true},

		// Window-driven.
		{name: "window-driven owed and open", rotation: wd(win4h), lastRotated: elapsedLR, now: insideWindow, wantOwed: true, wantWindow: true, wantHasWindow: true},
		{name: "window-driven owed but closed (missed opening)", rotation: wd(win4h), lastRotated: elapsedLR, now: outsideWindow, wantOwed: true, wantHasWindow: true},
		{name: "window-driven not owed (already rotated this opening)", rotation: wd(win4h), lastRotated: opensAt.Add(30 * time.Minute), now: insideWindow, wantWindow: true, wantHasWindow: true},
		{name: "window-driven never rotated is anchored on creation", rotation: wd(win4h), creation: elapsedLR, now: insideWindow, wantOwed: true, wantWindow: true, wantHasWindow: true},
		{name: "window-driven invalid window errors", rotation: wd(invalidWin), lastRotated: elapsedLR, now: insideWindow, wantHasWindow: true, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			owed, windowOpen, hasWindow, err := rotationTrigger(tc.rotation, tc.lastRotated, tc.creation, tc.now)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if hasWindow != tc.wantHasWindow {
				t.Errorf("hasWindow = %v, want %v", hasWindow, tc.wantHasWindow)
			}
			if tc.wantErr {
				return // owed/windowOpen are unspecified on error
			}
			if owed != tc.wantOwed {
				t.Errorf("owed = %v, want %v", owed, tc.wantOwed)
			}
			if windowOpen != tc.wantWindow {
				t.Errorf("windowOpen = %v, want %v", windowOpen, tc.wantWindow)
			}
		})
	}
}

// TestSecretRegenDecision pins the scheduled-vs-manual-vs-initial classification that drives
// whether the scheduled annotation and instance aggregate get written.
func TestSecretRegenDecision(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	now := time.Now()
	const secretName = "c-oidc-credentials"
	dueRotation := &pocketidinternalv1alpha1.ClientSecretRotation{Enabled: true, Interval: &metav1.Duration{Duration: 24 * time.Hour}}
	// windowDueRotation is interval-less: a daily window that opened a minute ago (open 30m), so a
	// secret last rotated long before now is due right now and classified as a scheduled rotation.
	opened := now.Add(-1 * time.Minute)
	windowDueRotation := &pocketidinternalv1alpha1.ClientSecretRotation{
		Enabled: true,
		Window: &pocketidinternalv1alpha1.RotationWindow{
			Opens:       fmt.Sprintf("%d %d * * *", opened.Minute(), opened.Hour()),
			ClosesAfter: metav1.Duration{Duration: 30 * time.Minute},
		},
	}

	fullSecret := func(annAge time.Duration) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:        secretName,
				Namespace:   testNamespace,
				Annotations: map[string]string{lastRotatedAtAnnotation: now.Add(annAge).UTC().Format(time.RFC3339)},
			},
			Data: map[string][]byte{"client_id": []byte("c-id"), "client_secret": []byte("old")},
		}
	}

	tests := []struct {
		name            string
		regenAnnotation bool
		rotation        *pocketidinternalv1alpha1.ClientSecretRotation
		secret          *corev1.Secret // nil = not in the store
		wantRegen       bool
		wantScheduled   bool
	}{
		{name: "missing secret is initial creation", secret: nil, wantRegen: true, wantScheduled: false},
		{name: "missing client_secret regenerates unscheduled", secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: testNamespace}, Data: map[string][]byte{"client_id": []byte("c-id")}}, wantRegen: true, wantScheduled: false},
		{name: "manual annotation regenerates unscheduled", regenAnnotation: true, secret: fullSecret(-1 * time.Hour), wantRegen: true, wantScheduled: false},
		{name: "scheduled rotation due", rotation: dueRotation, secret: fullSecret(-48 * time.Hour), wantRegen: true, wantScheduled: true},
		{name: "not due does not regenerate", rotation: dueRotation, secret: fullSecret(-1 * time.Hour), wantRegen: false, wantScheduled: false},
		{name: "window-driven rotation due is scheduled", rotation: windowDueRotation, secret: fullSecret(-48 * time.Hour), wantRegen: true, wantScheduled: true},
		{name: "window-driven already rotated this opening is not due", rotation: windowDueRotation, secret: fullSecret(-30 * time.Second), wantRegen: false, wantScheduled: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: testNamespace},
				Spec:       pocketidinternalv1alpha1.PocketIDOIDCClientSpec{ClientSecretRotation: tc.rotation},
			}
			if tc.regenAnnotation {
				oidcClient.Annotations = map[string]string{"pocketid.internal/regenerate-client-secret": "true"}
			}
			instance := &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{Name: "test-instance", Namespace: testNamespace},
			}

			objs := []client.Object{instance}
			if tc.secret != nil {
				objs = append(objs, tc.secret)
			}
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

			r := &Reconciler{Client: fakeClient, APIReader: fakeClient, Scheme: scheme}
			decision, err := r.secretRegenDecision(ctx, oidcClient, instance, secretName)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision.regenerate != tc.wantRegen || decision.scheduled != tc.wantScheduled {
				t.Errorf("got (regen=%v, scheduled=%v), want (regen=%v, scheduled=%v)", decision.regenerate, decision.scheduled, tc.wantRegen, tc.wantScheduled)
			}
		})
	}
}

// TestReconcileSecret_InstanceStatusWriteFailureRequeues proves the durability fix: when the
// instance aggregate write fails, ReconcileSecret returns an error so the reconcile requeues
// instead of silently leaving min-spacing blind.
func TestReconcileSecret_InstanceStatusWriteFailureRequeues(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "rot-client", Namespace: testNamespace, UID: "rot-uid"},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			CallbackURLs: []string{"https://example.com/cb"},
			ClientSecretRotation: &pocketidinternalv1alpha1.ClientSecretRotation{
				Enabled:  true,
				Interval: &metav1.Duration{Duration: 24 * time.Hour},
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "rot-id"},
	}
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "rot-client-oidc-credentials",
			Namespace:   testNamespace,
			Annotations: map[string]string{lastRotatedAtAnnotation: time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)},
		},
		Data: map[string][]byte{"client_id": []byte("rot-id"), "client_secret": []byte("old-secret")},
	}
	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "test-instance", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			AppURL:        "http://test.example.com",
			EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
		},
	}

	baseClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(oidcClient, existingSecret, instance).
		WithStatusSubresource(oidcClient, instance).
		Build()

	// Fail only the instance status patch; let the per-client status mirror succeed.
	failing := interceptor.NewClient(baseClient, interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, c client.Client, subResourceName string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			if _, ok := obj.(*pocketidinternalv1alpha1.PocketIDInstance); ok {
				return fmt.Errorf("simulated instance status patch failure")
			}
			return c.Status().Patch(ctx, obj, patch, opts...)
		},
	})

	ts := rotationSecretServer(t)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	reconciler := &Reconciler{Client: failing, APIReader: failing, Scheme: scheme}
	if err := reconciler.ReconcileSecret(ctx, oidcClient, instance, apiClient); err == nil {
		t.Fatal("expected ReconcileSecret to return an error when the instance status write fails")
	}
}

// TestReconcileSecret_SelfHealsAfterLostInstanceWrite is the full round trip: a scheduled
// rotation fires but the instance aggregate write is lost (pass 1); on the next reconcile the
// secret is NOT re-rotated (interval gate) yet the aggregate self-heals from the durable
// scheduled annotation (pass 2). This proves the rotation and the aggregate recording are
// decoupled exactly as intended.
func TestReconcileSecret_SelfHealsAfterLostInstanceWrite(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "rot-client", Namespace: testNamespace, UID: "rot-uid"},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			CallbackURLs: []string{"https://example.com/cb"},
			ClientSecretRotation: &pocketidinternalv1alpha1.ClientSecretRotation{
				Enabled:  true,
				Interval: &metav1.Duration{Duration: 24 * time.Hour},
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "rot-id"},
	}
	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "rot-client-oidc-credentials",
			Namespace:   testNamespace,
			Annotations: map[string]string{lastRotatedAtAnnotation: time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)},
		},
		Data: map[string][]byte{"client_id": []byte("rot-id"), "client_secret": []byte("old-secret")},
	}
	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "test-instance", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			AppURL:        "http://test.example.com",
			EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
		},
	}

	baseClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(oidcClient, existingSecret, instance).
		WithStatusSubresource(oidcClient, instance).
		Build()

	// Fail only the FIRST instance status patch; later ones succeed.
	var instancePatchCalls int
	healing := interceptor.NewClient(baseClient, interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, c client.Client, subResourceName string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			if _, ok := obj.(*pocketidinternalv1alpha1.PocketIDInstance); ok {
				instancePatchCalls++
				if instancePatchCalls == 1 {
					return fmt.Errorf("simulated instance status patch failure")
				}
			}
			return c.Status().Patch(ctx, obj, patch, opts...)
		},
	})

	// Count secret regenerations to prove pass 2 does not rotate again.
	var regenCalls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		regenCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secret":"rotated-secret"}`))
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	reconciler := &Reconciler{Client: healing, APIReader: healing, Scheme: scheme}

	// Pass 1: rotation fires, secret + annotations are durable, but the aggregate write is lost.
	if err := reconciler.ReconcileSecret(ctx, oidcClient, instance, apiClient); err == nil {
		t.Fatal("pass 1: expected error from the lost instance status write")
	}

	secretAfter1 := &corev1.Secret{}
	if err := healing.Get(ctx, client.ObjectKey{Name: existingSecret.Name, Namespace: testNamespace}, secretAfter1); err != nil {
		t.Fatalf("pass 1: get secret: %v", err)
	}
	scheduledTS, ok := secretAfter1.Annotations[lastScheduledRotationAtAnnotation]
	if !ok {
		t.Fatal("pass 1: scheduled annotation must be durable even though the status write failed")
	}
	instanceAfter1 := &pocketidinternalv1alpha1.PocketIDInstance{}
	if err := healing.Get(ctx, client.ObjectKey{Name: "test-instance", Namespace: testNamespace}, instanceAfter1); err != nil {
		t.Fatalf("pass 1: get instance: %v", err)
	}
	if instanceAfter1.Status.LastRotatedClientSecret != nil {
		t.Fatalf("pass 1: aggregate must stay unset after a failed write, got %v", instanceAfter1.Status.LastRotatedClientSecret)
	}

	// Pass 2: interval has not elapsed, so no re-rotation — but the aggregate heals from the annotation.
	if err := reconciler.ReconcileSecret(ctx, oidcClient, instance, apiClient); err != nil {
		t.Fatalf("pass 2: unexpected error: %v", err)
	}
	if regenCalls != 1 {
		t.Errorf("expected exactly 1 secret regeneration across both passes, got %d", regenCalls)
	}
	instanceAfter2 := &pocketidinternalv1alpha1.PocketIDInstance{}
	if err := healing.Get(ctx, client.ObjectKey{Name: "test-instance", Namespace: testNamespace}, instanceAfter2); err != nil {
		t.Fatalf("pass 2: get instance: %v", err)
	}
	if instanceAfter2.Status.LastRotatedClientSecret == nil {
		t.Fatal("pass 2: aggregate must self-heal from the durable scheduled annotation")
	}
	want, _ := time.Parse(time.RFC3339, scheduledTS)
	if !instanceAfter2.Status.LastRotatedClientSecret.Time.Equal(want) {
		t.Errorf("healed aggregate %v != scheduled annotation %v", instanceAfter2.Status.LastRotatedClientSecret.Time, want)
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
			EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
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
	// spec.scim set, tracked ID exists, endpoint changed → update
	ctx := context.Background()
	oidcClient := oidcClientWithSCIM(&pocketidinternalv1alpha1.SCIMSpec{
		Endpoint: "https://scim.example.com/v2",
	}, "tracked-scim-id")
	r := newSCIMReconciler(t, oidcClient)
	api := &fakeSCIMAPI{
		existingProvider: &pocketid.SCIMServiceProvider{ID: "tracked-scim-id", Endpoint: "https://old.example.com/scim"},
	}

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

func TestReconcileSCIM_StaleStatusID_UsesCurrentID(t *testing.T) {
	// status.SCIMProviderID is stale; GetOIDCClientSCIMServiceProvider returns a provider
	// with a different ID. The update must use current.ID, and status must be patched.
	ctx := context.Background()
	oidcClient := oidcClientWithSCIM(&pocketidinternalv1alpha1.SCIMSpec{
		Endpoint: "https://scim.example.com/v2",
	}, "stale-id")
	r := newSCIMReconciler(t, oidcClient)
	api := &fakeSCIMAPI{
		existingProvider: &pocketid.SCIMServiceProvider{ID: "real-id", Endpoint: "https://old.example.com/scim"},
	}

	if err := r.ReconcileSCIM(ctx, oidcClient, api); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if api.created != nil {
		t.Error("expected no create call")
	}
	if _, ok := api.updated["stale-id"]; ok {
		t.Error("expected update to use current ID, not stale status ID")
	}
	if _, ok := api.updated["real-id"]; !ok {
		t.Errorf("expected update of real-id, updated map: %v", api.updated)
	}
	if oidcClient.Status.SCIMProviderID != "real-id" {
		t.Errorf("expected status.SCIMProviderID patched to %q, got %q", "real-id", oidcClient.Status.SCIMProviderID)
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

// TestOidcClientPredicate_ManualRotationEnqueues guards the manual-rotation trigger:
// setting the regenerate-client-secret annotation must enqueue a reconcile even though
// annotations do not bump metadata.generation. Without this the rotation would not fire
// until the next periodic resync, so a manual annotation would not "force" a rotation.
func TestOidcClientPredicate_ManualRotationEnqueues(t *testing.T) {
	pred := oidcClientPredicate()

	obj := func(gen int64, annotations map[string]string) *pocketidinternalv1alpha1.PocketIDOIDCClient {
		return &pocketidinternalv1alpha1.PocketIDOIDCClient{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "trek",
				Namespace:   testNamespace,
				Generation:  gen,
				Annotations: annotations,
			},
		}
	}

	tests := []struct {
		name     string
		old, new *pocketidinternalv1alpha1.PocketIDOIDCClient
		want     bool
	}{
		{
			name: "regenerate annotation added without a generation bump",
			old:  obj(2, nil),
			new:  obj(2, map[string]string{regenerateClientSecretAnnotation: "true"}),
			want: true,
		},
		{
			name: "spec change bumps generation",
			old:  obj(2, nil),
			new:  obj(3, nil),
			want: true,
		},
		{
			// Guards against simply dropping the predicate, which would reconcile on
			// every status write and resync (the rate-limiting the predicate prevents).
			name: "no generation or annotation change",
			old:  obj(2, map[string]string{regenerateClientSecretAnnotation: "true"}),
			new:  obj(2, map[string]string{regenerateClientSecretAnnotation: "true"}),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pred.Update(event.UpdateEvent{ObjectOld: tc.old, ObjectNew: tc.new})
			if got != tc.want {
				t.Errorf("predicate.Update() = %v, want %v", got, tc.want)
			}
		})
	}
}
