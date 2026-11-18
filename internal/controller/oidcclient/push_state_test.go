package oidcclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

const (
	grafanaLogoTemplate = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/webp/{{name}}.webp"
	grafanaLogoURL      = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/webp/grafana.webp"
)

// newPushStateOIDCReconciler creates a Reconciler with a fake K8s client including
// the UserGroup index required by aggregateAllowedUserGroupIDs.
func newPushStateOIDCReconciler(scheme *runtime.Scheme, objs ...client.Object) *Reconciler {
	fc := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(objs...).
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
	r := &Reconciler{Client: fc, Scheme: scheme}
	r.EnsureClient(fc)
	return r
}

// --- oidcClientPatch ---

// A field left out of a PATCH keeps its current value in Pocket-ID, so every managed field has
// to go out on every reconcile, empty ones included.
func TestOIDCClientPatch_SendsEveryManagedField(t *testing.T) {
	managed := []string{
		"name", "notes", "backchannelLogoutURL", "launchURL", "isPublic", "isGroupRestricted", "pkceEnabled",
		"requiresReauthentication", "requiresPushedAuthorizationRequests", "skipConsent",
		"accessTokenDurationMinutes", "refreshTokenDurationMinutes", "callbackURLs", "logoutCallbackURLs",
		"credentials",
	}
	full := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "app"},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Name: "App", Description: "notes", BackchannelLogoutURL: "https://app.example.com/bc",
			LaunchURL: "https://app.example.com", IsPublic: true, PKCEEnabled: true,
			RequiresReauthentication: true, RequiresPushedAuthorizationRequests: true, SkipConsent: true,
			AccessTokenDurationMinutes: 5, RefreshTokenDurationMinutes: 10,
			CallbackURLs: []string{"https://app.example.com/cb"}, LogoutCallbackURLs: []string{"https://app.example.com/out"},
		},
	}
	identities := []pid.OIDCClientFederatedIdentityInputDto{{Issuer: new("https://issuer.example.com")}}

	for _, tc := range []struct {
		name       string
		oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient
		restricted bool
		identities []pid.OIDCClientFederatedIdentityInputDto
		want       []string
		wantEmpty  bool
	}{
		{name: "every field set", oidcClient: full, restricted: true, identities: identities, want: managed},
		// Unset callback URLs go out as [], clearing any set in Pocket-ID.
		{name: "every field empty", oidcClient: &pocketidinternalv1alpha1.PocketIDOIDCClient{}, want: managed, wantEmpty: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(oidcClientPatch(tc.oidcClient, tc.restricted, tc.identities))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			got := slices.Sorted(func(yield func(string) bool) {
				for key := range body {
					if !yield(key) {
						return
					}
				}
			})
			if want := slices.Sorted(slices.Values(tc.want)); !slices.Equal(got, want) {
				t.Fatalf("keys = %v, want %v", got, want)
			}
			if !tc.wantEmpty {
				return
			}
			for key, value := range body {
				switch value := value.(type) {
				case nil:
				case bool:
					if value {
						t.Errorf("%s = true, want false", key)
					}
				case float64:
					if value != 0 {
						t.Errorf("%s = %v, want 0", key, value)
					}
				case string:
					if value != "" {
						t.Errorf("%s = %q, want empty", key, value)
					}
				case []any: // callback URLs
					if len(value) != 0 {
						t.Errorf("%s = %v, want []", key, value)
					}
				case map[string]any: // credentials
					if fi, ok := value["federatedIdentities"]; !ok || fi != nil {
						t.Errorf("credentials = %v, want federatedIdentities null", value)
					}
				default:
					t.Errorf("%s = %v, want empty", key, value)
				}
			}
		})
	}
}

// --- Logo URL resolution tests ---

// namedClient builds a bare CR whose metadata.name drives {{name}} substitution.
func namedClient(name string) *pocketidinternalv1alpha1.PocketIDOIDCClient {
	return &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
	}
}

func TestResolveLogoURLs_DeprecatedFieldsTakePrecedence(t *testing.T) {
	r := &Reconciler{DefaultLogoTemplate: "https://cdn.example.com/{{name}}.png"}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-app", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			LogoURL:     "https://explicit.example.com/logo.png",      //nolint:staticcheck // testing the deprecated field
			DarkLogoURL: "https://explicit.example.com/logo-dark.png", //nolint:staticcheck // testing the deprecated field
			Logo:        &pocketidinternalv1alpha1.OIDCClientLogoSpec{AutoGenerate: new(true)},
		},
	}
	logoURL, darkLogoURL := r.resolveLogoURLs(oidcClient)
	if logoURL != "https://explicit.example.com/logo.png" {
		t.Errorf("expected deprecated logoUrl to win, got %q", logoURL)
	}
	if darkLogoURL != "https://explicit.example.com/logo-dark.png" {
		t.Errorf("expected deprecated darkLogoUrl to win, got %q", darkLogoURL)
	}
}

func TestResolveLogoURLs_NameOverride(t *testing.T) {
	r := &Reconciler{}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-app", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{
				AutoGenerate: new(true),
				NameOverride: "custom-icon",
				LogoURL:      "https://cdn.example.com/{{name}}.png",
			},
		},
	}
	logoURL, _ := r.resolveLogoURLs(oidcClient)
	if logoURL != "https://cdn.example.com/custom-icon.png" {
		t.Errorf("expected nameOverride to be used, got %q", logoURL)
	}
}

func TestResolveLogoURLs_EnvVarFallback(t *testing.T) {
	r := &Reconciler{
		DefaultLogoTemplate:     "https://cdn.example.com/{{name}}.png",
		DefaultDarkLogoTemplate: "https://cdn.example.com/{{name}}-dark.png",
	}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{
				AutoGenerate: new(true),
			},
		},
	}
	logoURL, darkLogoURL := r.resolveLogoURLs(oidcClient)
	if logoURL != "https://cdn.example.com/grafana.png" {
		t.Errorf("expected env var fallback, got %q", logoURL)
	}
	if darkLogoURL != "https://cdn.example.com/grafana-dark.png" {
		t.Errorf("expected env var fallback, got %q", darkLogoURL)
	}
}

func TestResolveLogoURLs_NoTemplatesConfigured(t *testing.T) {
	r := &Reconciler{}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{
				AutoGenerate: new(true),
			},
		},
	}
	logoURL, darkLogoURL := r.resolveLogoURLs(oidcClient)
	if logoURL != "" || darkLogoURL != "" {
		t.Errorf("expected no URLs when no templates are configured, got %q %q", logoURL, darkLogoURL)
	}
}

func TestResolveLogoURLs_LightTemplateOnly(t *testing.T) {
	r := &Reconciler{DefaultAutoGenerateLogos: true, DefaultLogoTemplate: grafanaLogoTemplate}
	logoURL, darkLogoURL := r.resolveLogoURLs(namedClient("grafana"))
	if logoURL != grafanaLogoURL {
		t.Errorf("expected the light template to be used, got %q", logoURL)
	}
	if darkLogoURL != "" {
		t.Errorf("expected no dark logo with no dark template, got %q", darkLogoURL)
	}
}

func TestResolveLogoURLs_AutoGenerateFalse(t *testing.T) {
	r := &Reconciler{}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-app", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{
				AutoGenerate: new(false),
			},
		},
	}
	logoURL, darkLogoURL := r.resolveLogoURLs(oidcClient)
	if logoURL != "" || darkLogoURL != "" {
		t.Errorf("expected empty URLs when autoGenerate=false, got %q %q", logoURL, darkLogoURL)
	}
}

func TestResolveLogoURLs_ExplicitURLIgnoresAutoGenerateFalse(t *testing.T) {
	r := &Reconciler{}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-app", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{
				AutoGenerate: new(false),
				LogoURL:      "https://cdn.example.com/{{name}}.png",
			},
		},
	}
	logoURL, darkLogoURL := r.resolveLogoURLs(oidcClient)
	if logoURL != "https://cdn.example.com/my-app.png" {
		t.Errorf("expected explicit logoUrl to be used despite autoGenerate=false, got %q", logoURL)
	}
	if darkLogoURL != "" {
		t.Errorf("expected dark logo to be empty when not set and autoGenerate=false, got %q", darkLogoURL)
	}
}

func TestResolveLogoURLs_NilLogoSpecEnvFalse(t *testing.T) {
	r := &Reconciler{DefaultAutoGenerateLogos: false}
	logoURL, darkLogoURL := r.resolveLogoURLs(namedClient("my-app"))
	if logoURL != "" || darkLogoURL != "" {
		t.Errorf("expected empty URLs when logo spec is nil and env is false, got %q %q", logoURL, darkLogoURL)
	}
}

func TestResolveLogoURLs_NilLogoSpecEnvTrue(t *testing.T) {
	r := &Reconciler{DefaultAutoGenerateLogos: true, DefaultLogoTemplate: grafanaLogoTemplate}
	logoURL, _ := r.resolveLogoURLs(namedClient("grafana"))
	if logoURL != grafanaLogoURL {
		t.Errorf("expected the light template when logo spec is nil and env is true, got %q", logoURL)
	}
}

func TestResolveLogoURLs_PerClientTemplateWithNoDefaults(t *testing.T) {
	r := &Reconciler{DefaultAutoGenerateLogos: true}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-app", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{LogoURL: "https://cdn.example.com/{{name}}.png"},
		},
	}
	logoURL, _ := r.resolveLogoURLs(oidcClient)
	if logoURL != "https://cdn.example.com/my-app.png" {
		t.Errorf("expected the per-client template to be used, got %q", logoURL)
	}
}

func TestResolveLogoURLs_AutoGenerateNilDefaultsToEnvTrue(t *testing.T) {
	r := &Reconciler{DefaultAutoGenerateLogos: true, DefaultLogoTemplate: grafanaLogoTemplate}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{},
		},
	}
	logoURL, _ := r.resolveLogoURLs(oidcClient)
	if logoURL != grafanaLogoURL {
		t.Errorf("expected nil autoGenerate to follow env default true, got %q", logoURL)
	}
}

func TestResolveLogoURLs_AutoGenerateNilDefaultsToEnvFalse(t *testing.T) {
	r := &Reconciler{DefaultAutoGenerateLogos: false}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-app", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{},
		},
	}
	logoURL, darkLogoURL := r.resolveLogoURLs(oidcClient)
	if logoURL != "" || darkLogoURL != "" {
		t.Errorf("expected empty URLs when env default is false, got %q %q", logoURL, darkLogoURL)
	}
}

func TestResolveLogoURLs_ExplicitTrueOverridesEnvFalse(t *testing.T) {
	r := &Reconciler{DefaultAutoGenerateLogos: false, DefaultLogoTemplate: grafanaLogoTemplate}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-app", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{
				AutoGenerate: new(true),
			},
		},
	}
	logoURL, _ := r.resolveLogoURLs(oidcClient)
	if logoURL == "" {
		t.Error("expected explicit autoGenerate=true to override env default false")
	}
}

func TestResolveLogoURLs_PerClientTemplateOverridesEnvVar(t *testing.T) {
	r := &Reconciler{DefaultLogoTemplate: "https://default.example.com/{{name}}.png"}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-app", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{
				AutoGenerate: new(true),
				LogoURL:      "https://custom.example.com/{{name}}.png",
			},
		},
	}
	logoURL, _ := r.resolveLogoURLs(oidcClient)
	if logoURL != "https://custom.example.com/my-app.png" {
		t.Errorf("expected per-client template to override env var, got %q", logoURL)
	}
}

// --- reconcileLogos ---

// logoClient builds a CR resolving light via an explicit logo URL, with appliedLight and
// appliedDark already recorded in status. Callers needing a dark URL set it on the spec.
func logoClient(light, appliedLight, appliedDark string) *pocketidinternalv1alpha1.PocketIDOIDCClient {
	return &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-app", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{AutoGenerate: new(false), LogoURL: light},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			ClientID:    "client-id",
			LogoURL:     appliedLight,
			DarkLogoURL: appliedDark,
		},
	}
}

func TestReconcileLogos_BehaviorTable(t *testing.T) {
	const url = "https://cdn.example.com/logo.png"

	tests := []struct {
		name              string
		resolved, applied string
		serverHasLogo     bool
		failed            bool
		wantPush          bool
		wantApplied       string
		wantDelete        bool
	}{
		{
			name: "unowned side is left alone",
		},
		{
			name:          "uploaded logo is never deleted",
			serverHasLogo: true,
		},
		{
			name:    "applied logo the spec dropped is deleted",
			applied: url, serverHasLogo: true, wantDelete: true,
		},
		{
			name:     "a URL Pocket-ID refused is not retried",
			resolved: url, failed: true,
		},
		{
			name:     "an applied logo the spec replaced with a refused URL is deleted",
			resolved: url, applied: "https://cdn.example.com/old.png", serverHasLogo: true,
			failed: true, wantDelete: true,
		},
		{
			name:     "an applied logo whose own URL is refused is kept",
			resolved: url, applied: url, serverHasLogo: true, failed: true, wantApplied: url,
		},
		{
			name:     "a new URL is pushed",
			resolved: url, wantPush: true, wantApplied: url,
		},
		{
			name:     "a changed URL is pushed",
			resolved: url, applied: "https://cdn.example.com/old.png", serverHasLogo: true,
			wantPush: true, wantApplied: url,
		},
		{
			name:     "an applied logo deleted server-side is re-pushed",
			resolved: url, applied: url, wantPush: true, wantApplied: url,
		},
		{
			name:     "an applied logo still in place is left alone",
			resolved: url, applied: url, serverHasLogo: true, wantApplied: url,
		},
	}

	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run each row on both sides so neither is special-cased.
			for _, light := range []bool{true, false} {
				side := "dark"
				if light {
					side = "light"
				}
				oidcClient := logoClient("", "", "")
				f := newFakeOIDCClient(t, "client-id", "my-app")
				if light {
					oidcClient.Spec.Logo.LogoURL, oidcClient.Status.LogoURL, f.client.HasLogo = tt.resolved, tt.applied, tt.serverHasLogo
				} else {
					oidcClient.Spec.Logo.DarkLogoURL, oidcClient.Status.DarkLogoURL, f.client.HasDarkLogo = tt.resolved, tt.applied, tt.serverHasLogo
				}

				r := newPushStateOIDCReconciler(scheme, oidcClient)
				if tt.failed {
					r.markLogoURLsFailed(tt.resolved)
					r.failedLogoURLsResetAt = time.Now()
				}
				if _, err := r.reconcileLogos(context.Background(), oidcClient, f.api(), f.client); err != nil {
					t.Fatalf("%s: reconcileLogos: %v", side, err)
				}

				var wantPushes, wantCalls []string
				if tt.wantDelete {
					wantCalls = append(wantCalls, "delete logo light="+map[bool]string{true: "true", false: "false"}[light])
				}
				if tt.wantPush {
					wantPushes = []string{side + " " + url}
					wantCalls = append(wantCalls, "PATCH")
				}
				if got := f.logoPatches(); !slices.Equal(got, wantPushes) {
					t.Errorf("%s: pushes = %v, want %v", side, got, wantPushes)
				}
				if !slices.Equal(f.calls, wantCalls) {
					t.Errorf("%s: calls = %v, want %v", side, f.calls, wantCalls)
				}
				applied := oidcClient.Status.DarkLogoURL
				if light {
					applied = oidcClient.Status.LogoURL
				}
				if applied != tt.wantApplied {
					t.Errorf("%s: applied: got %q, want %q", side, applied, tt.wantApplied)
				}
			}
		})
	}
}

func TestLogoReachable(t *testing.T) {
	const url = "https://cdn.example.com/logo.png"

	tests := []struct {
		name              string
		resolved, applied string
		want              *bool
	}{
		{name: "no logo asked for", want: nil},
		{name: "applied is what the spec asks for", resolved: url, applied: url, want: new(true)},
		{name: "refused, old logo still stranded", resolved: url, applied: "https://cdn.example.com/old.png", want: new(false)},
		{name: "refused, stranded logo deleted", resolved: url, want: new(false)},
		{name: "spec dropped a logo the operator applied", applied: url, want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := logoReachable(tt.resolved, tt.applied)
			switch {
			case tt.want == nil && got != nil:
				t.Errorf("got %v, want nil", *got)
			case tt.want != nil && got == nil:
				t.Errorf("got nil, want %v", *tt.want)
			case tt.want != nil && *got != *tt.want:
				t.Errorf("got %v, want %v", *got, *tt.want)
			}
		})
	}
}

func TestLogoDeletePending(t *testing.T) {
	const url = "https://cdn.example.com/logo.png"

	tests := []struct {
		name              string
		resolved, applied string
		failed            bool
		want              bool
	}{
		{
			name:     "a URL still in play strands nothing",
			resolved: url, applied: "https://cdn.example.com/old.png",
		},
		{
			name:     "a refused URL stranding an applied logo",
			resolved: url, applied: "https://cdn.example.com/old.png", failed: true, want: true,
		},
		{
			name:     "a refused URL that is itself the applied one",
			resolved: url, applied: url, failed: true,
		},
		{
			name:     "a refused URL with nothing applied",
			resolved: url, failed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run each row on both sides so neither is special-cased.
			for _, light := range []bool{true, false} {
				oidcClient := logoClient("", "", "")
				if light {
					oidcClient.Spec.Logo.LogoURL, oidcClient.Status.LogoURL = tt.resolved, tt.applied
				} else {
					oidcClient.Spec.Logo.DarkLogoURL, oidcClient.Status.DarkLogoURL = tt.resolved, tt.applied
				}

				r := &Reconciler{}
				if tt.failed {
					r.markLogoURLsFailed(tt.resolved)
				}
				if got := r.logoDeletePending(oidcClient); got != tt.want {
					t.Errorf("light=%v: got %v, want %v", light, got, tt.want)
				}
			}
		})
	}
}

// A client that resolves only a light URL must not disturb an uploaded dark logo.
func TestReconcileLogos_OnlyLightResolvedLeavesUploadedDarkLogo(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClient := logoClient("https://cdn.example.com/logo.png", "", "")
	r := newPushStateOIDCReconciler(scheme, oidcClient)
	f := newFakeOIDCClient(t, "client-id", "my-app")
	f.client.HasDarkLogo = true

	current, err := r.reconcileLogos(context.Background(), oidcClient, f.api(), f.client)
	if err != nil {
		t.Fatalf("reconcileLogos: %v", err)
	}
	if got := f.logoPatches(); !slices.Equal(got, []string{"light https://cdn.example.com/logo.png"}) {
		t.Errorf("expected only the light URL to be pushed, got %v", got)
	}
	if !current.HasLogo || !current.HasDarkLogo {
		t.Errorf("expected the returned client to carry both logos, got %+v", current)
	}
}

func TestMarkLogoURLsFailed_KeysByURL(t *testing.T) {
	r := &Reconciler{}
	r.markLogoURLsFailed("https://cdn.example.com/logo.png")
	if !r.logoURLFailed("https://cdn.example.com/logo.png") {
		t.Error("expected the URL to be recorded as failed")
	}
	if r.logoURLFailed("https://cdn.example.com/other.png") {
		t.Error("a different URL must not inherit the failure")
	}
}

// A URL refused once must be retried after the TTL, so a logo Pocket-ID lost is restored
// without an operator restart.
func TestReconcileLogos_RefusedURLIsRetriedAfterTTL(t *testing.T) {
	const url = "https://cdn.example.com/logo.png"
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClient := logoClient(url, url, "")
	r := newPushStateOIDCReconciler(scheme, oidcClient)
	r.markLogoURLsFailed(url)
	r.failedLogoURLsResetAt = time.Now()

	f := newFakeOIDCClient(t, "client-id", "my-app")
	apiClient := f.api()
	if _, err := r.reconcileLogos(context.Background(), oidcClient, apiClient, f.client); err != nil {
		t.Fatalf("reconcileLogos: %v", err)
	}
	if got := f.logoPatches(); len(got) != 0 {
		t.Errorf("expected the refused URL to stay suppressed, got %v", got)
	}

	r.failedLogoURLsResetAt = time.Now().Add(-failedLogoURLTTL - time.Minute)
	if _, err := r.reconcileLogos(context.Background(), oidcClient, apiClient, f.client); err != nil {
		t.Fatalf("reconcileLogos after TTL: %v", err)
	}
	if got := f.logoPatches(); !slices.Equal(got, []string{"light " + url}) {
		t.Errorf("expected the URL to be retried after the TTL, got %v", got)
	}
	if r.logoURLFailed(url) {
		t.Error("the refusal set should have been dropped")
	}
	if time.Since(r.failedLogoURLsResetAt) > time.Minute {
		t.Error("expected the reset deadline to be restamped, not expired every reconcile")
	}
}

func TestApplyLogoStatus_PersistsAppliedURLs(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "test-client", Namespace: testNamespace},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			LogoURL:     "https://example.com/old.png",
			DarkLogoURL: "https://example.com/old-dark.png",
		},
	}
	r := newPushStateOIDCReconciler(scheme, oidcClient)
	ctx := context.Background()

	// Light logo newly applied, dark logo released back to Pocket-ID.
	plan := logoPlan{appliedLight: "https://example.com/logo.png"}
	if err := r.applyLogoStatus(ctx, oidcClient, plan); err != nil {
		t.Fatalf("applyLogoStatus failed: %v", err)
	}

	fetched := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(oidcClient), fetched); err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if fetched.Status.LogoURL != "https://example.com/logo.png" {
		t.Errorf("expected logoUrl to be recorded, got %q", fetched.Status.LogoURL)
	}
	if fetched.Status.DarkLogoURL != "" {
		t.Errorf("expected darkLogoUrl to be cleared, got %q", fetched.Status.DarkLogoURL)
	}
}

// A deletion that succeeded must be recorded even when the pass later fails, or the next
// one deletes whatever was uploaded in its place.
func TestReconcileLogos_RecordsDeletionWhenTheOtherSideFails(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClient := logoClient("", "https://cdn.example.com/logo.png", "https://cdn.example.com/dark.png")
	r := newPushStateOIDCReconciler(scheme, oidcClient)

	// Light deletes cleanly; dark fails.
	f := newFakeOIDCClient(t, "client-id", "my-app")
	f.fail = failDarkLogoDelete("boom")

	if _, err := r.reconcileLogos(context.Background(), oidcClient, f.api(), f.client); err == nil {
		t.Fatal("expected the dark deletion failure to propagate")
	}

	fetched := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(oidcClient), fetched); err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if fetched.Status.LogoURL != "" {
		t.Errorf("the completed deletion must be persisted, got %q", fetched.Status.LogoURL)
	}
	if fetched.Status.DarkLogoURL != "https://cdn.example.com/dark.png" {
		t.Errorf("the failed deletion must keep its record, got %q", fetched.Status.DarkLogoURL)
	}
}

// Neither failure should hide the other: the delete failure explains the reconcile, and the
// status failure explains why the completed deletion was not recorded.
func TestReconcileLogos_ReportsBothDeleteAndStatusFailures(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClient := logoClient("", "https://cdn.example.com/logo.png", "https://cdn.example.com/dark.png")
	r := newPushStateOIDCReconciler(scheme, oidcClient)
	r.Client = interceptor.NewClient(r.Client.(client.WithWatch), interceptor.Funcs{
		SubResourcePatch: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ client.Patch, _ ...client.SubResourcePatchOption) error {
			return errors.New("simulated status patch failure")
		},
	})

	f := newFakeOIDCClient(t, "client-id", "my-app")
	f.fail = failDarkLogoDelete("delete refused")

	_, err := r.reconcileLogos(context.Background(), oidcClient, f.api(), f.client)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "delete refused") {
		t.Errorf("delete failure missing from %v", err)
	}
	if !strings.Contains(err.Error(), "simulated status patch failure") {
		t.Errorf("status failure missing from %v", err)
	}
}

func failDarkLogoDelete(message string) func(*http.Request, map[string]any) (int, any) {
	return func(r *http.Request, _ map[string]any) (int, any) {
		if r.Method == http.MethodDelete && r.URL.Query().Get("light") == "false" {
			return http.StatusInternalServerError, map[string]string{"code": "internal_error", "error": message}
		}
		return 0, nil
	}
}

// --- aggregateAllowedUserGroupIDs sort order ---

func TestAggregateAllowedUserGroupIDs_OutputIsSorted(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	// Three groups reverse-reference this client via spec.allowedOIDCClients.
	// They are added in non-alphabetical ID order to verify sorting.
	mkGroup := func(name, groupID string) *pocketidinternalv1alpha1.PocketIDUserGroup {
		return &pocketidinternalv1alpha1.PocketIDUserGroup{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
			Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
				AllowedOIDCClients: []pocketidinternalv1alpha1.NamespacedOIDCClientReference{{Name: "sort-client"}},
			},
			Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{GroupID: groupID, Conditions: readyCondition()},
		}
	}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "sort-client", Namespace: testNamespace},
	}

	fc := newAggregationFakeClient(scheme, mkGroup("group-c", "gid-c"), mkGroup("group-a", "gid-a"), mkGroup("group-b", "gid-b"), oidcClient)
	reconciler := &Reconciler{Client: fc, Scheme: scheme}

	ids, err := reconciler.aggregateAllowedUserGroupIDs(ctx, oidcClient, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(ids, []string{"gid-a", "gid-b", "gid-c"}) {
		t.Errorf("expected sorted [gid-a, gid-b, gid-c], got %v", ids)
	}
}

// --- pushOIDCClientState ---

// The spec is written every reconcile, and the client comes back from the write.
func TestPushOIDCClientState_PatchesAndReturnsTheResult(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClientCR := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "update-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			CallbackURLs: []string{"https://new.example.com/cb"},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "update-id"},
	}
	r := newPushStateOIDCReconciler(scheme, oidcClientCR)
	f := newFakeOIDCClient(t, "update-id", "old-name")
	f.client.CallbackURLs = []string{"https://old.example.com/cb"}

	for range 2 {
		current, err := r.pushOIDCClientState(context.Background(), oidcClientCR, f.api())
		if err != nil {
			t.Fatalf("pushOIDCClientState: %v", err)
		}
		if current.Name != "update-client" || !slices.Equal(current.CallbackURLs, oidcClientCR.Spec.CallbackURLs) {
			t.Errorf("expected the written client back, got %+v", current)
		}
	}
	if len(f.patches) != 2 {
		t.Errorf("expected a PATCH every reconcile, got %d", len(f.patches))
	}
}

// Federated identities are owned by the spec: they go out every reconcile, and ones the spec
// no longer lists are cleared.
func TestPushOIDCClientState_FederatedIdentities(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	for _, tc := range []struct {
		name    string
		spec    []pocketidinternalv1alpha1.OIDCClientFederatedIdentity
		wantLen int
		wantKID string // kid of the first key sent, when keys are expected
	}{
		{name: "removed from spec"},
		{name: "in spec", spec: []pocketidinternalv1alpha1.OIDCClientFederatedIdentity{{Issuer: "https://issuer.example.com", Subject: "sa:myapp"}}, wantLen: 1},
		{
			name:    "with keys",
			spec:    []pocketidinternalv1alpha1.OIDCClientFederatedIdentity{{Issuer: "https://issuer.example.com", PublicKeys: []pocketidinternalv1alpha1.OIDCClientPublicKey{inlineKey(keyB)}}},
			wantLen: 1,
			wantKID: "b",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oidcClientCR := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{Name: "cred-client", Namespace: testNamespace},
				Spec:       pocketidinternalv1alpha1.PocketIDOIDCClientSpec{FederatedIdentities: tc.spec},
				Status:     pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "cred-id"},
			}
			r := newPushStateOIDCReconciler(scheme, oidcClientCR)
			f := newFakeOIDCClient(t, "cred-id", "cred-client")

			if _, err := r.pushOIDCClientState(context.Background(), oidcClientCR, f.api()); err != nil {
				t.Fatalf("pushOIDCClientState: %v", err)
			}
			credentials, _ := f.patches[0]["credentials"].(map[string]any)
			identities, _ := credentials["federatedIdentities"].([]any)
			if len(identities) != tc.wantLen {
				t.Fatalf("sent %d federated identities, want %d: %v", len(identities), tc.wantLen, credentials)
			}
			if tc.wantKID != "" {
				first, _ := identities[0].(map[string]any)
				keys, _ := first["publicKeys"].([]any)
				if len(keys) != 1 || keys[0].(map[string]any)["kid"] != tc.wantKID {
					t.Errorf("sent public keys %v, want kid %q", first["publicKeys"], tc.wantKID)
				}
			}
		})
	}
}

// A reference that cannot be resolved must stop the write rather than push the identity without
// its keys, which would make Pocket-ID fall back to the issuer's JWKS URL.
func TestOIDCClientWrites_StopOnUnresolvablePublicKeys(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	oidcClientCR := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "keys-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			ClientID: "keys-id",
			FederatedIdentities: []pocketidinternalv1alpha1.OIDCClientFederatedIdentity{{
				Issuer:     "https://issuer.example.com",
				PublicKeys: []pocketidinternalv1alpha1.OIDCClientPublicKey{configMapKey("absent", "jwks", false)},
			}},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "keys-id"},
	}
	r := newPushStateOIDCReconciler(scheme, oidcClientCR)
	r.APIReader = r.Client

	var writes int
	apiClient := fakeAPI(t, map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, req *http.Request) {
			if req.Method != http.MethodGet {
				writes++
			}
			writeStatus(w, http.StatusNotFound, map[string]string{"code": "not_found"})
		},
	})

	if _, err := r.createOrAdoptOIDCClient(ctx, oidcClientCR, apiClient); !errors.Is(err, errPublicKeys) {
		t.Errorf("create: expected a public key error, got %v", err)
	}
	if _, err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient); !errors.Is(err, errPublicKeys) {
		t.Errorf("update: expected a public key error, got %v", err)
	}
	if writes != 0 {
		t.Errorf("expected no writes, got %d", writes)
	}
}

// Pocket-ID back-channel logs out a restricted client's users outside its groups on every
// groups write, so the groups are written only when they differ, and before restriction is
// turned on.
func TestPushOIDCClientState_AllowedGroupsOrdering(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	groupA := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group-a", Namespace: testNamespace},
		Status:     pocketidinternalv1alpha1.PocketIDUserGroupStatus{GroupID: "gid-a", Conditions: readyCondition()},
	}
	// Only a reverse reference from the group, no spec.allowedUserGroups.
	reverseGroup := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "reverse-group", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			AllowedOIDCClients: []pocketidinternalv1alpha1.NamespacedOIDCClientReference{{Name: "reverse-client"}},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{GroupID: "gid-reverse", Conditions: readyCondition()},
	}

	groupARef := []pocketidinternalv1alpha1.NamespacedUserGroupReference{{Name: "group-a"}}
	for _, tc := range []struct {
		name, clientName string
		groups           []pocketidinternalv1alpha1.NamespacedUserGroupReference
		// The client's state in Pocket-ID before the push.
		restricted bool
		stored     []string
		// sentRestriction is the spec write's isGroupRestricted, nil when left out.
		sentRestriction any
		wantCalls       []string
		wantGroups      int
	}{
		{name: "steady restricted", clientName: "groups-client", groups: groupARef, restricted: true, stored: []string{"gid-a"},
			wantCalls: []string{"PATCH"}, wantGroups: 1},
		{name: "steady unrestricted", clientName: "groups-client", sentRestriction: false,
			wantCalls: []string{"PATCH"}},
		{name: "restricting", clientName: "groups-client", groups: groupARef,
			wantCalls: []string{"PATCH", "groups [gid-a]", "PATCH"}, wantGroups: 1},
		{name: "reverse reference restricts", clientName: "reverse-client",
			wantCalls: []string{"PATCH", "groups [gid-reverse]", "PATCH"}, wantGroups: 1},
		{name: "changing groups", clientName: "groups-client", groups: groupARef, restricted: true, stored: []string{"gid-old"},
			wantCalls: []string{"PATCH", "groups [gid-a]", "PATCH"}, wantGroups: 1},
		{name: "unrestricting", clientName: "groups-client", restricted: true, stored: []string{"gid-old"}, sentRestriction: false,
			wantCalls: []string{"PATCH"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oidcClientCR := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{Name: tc.clientName, Namespace: testNamespace},
				Spec:       pocketidinternalv1alpha1.PocketIDOIDCClientSpec{AllowedUserGroups: tc.groups},
				Status:     pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "groups-id"},
			}
			r := newPushStateOIDCReconciler(scheme, oidcClientCR, groupA, reverseGroup)
			f := newFakeOIDCClient(t, "groups-id", tc.clientName)
			f.client.IsGroupRestricted = tc.restricted
			for _, id := range tc.stored {
				f.client.AllowedUserGroups = append(f.client.AllowedUserGroups, pid.UserGroupMinimalDto{ID: id})
			}

			current, err := r.pushOIDCClientState(context.Background(), oidcClientCR, f.api())
			if err != nil {
				t.Fatalf("pushOIDCClientState: %v", err)
			}
			if !slices.Equal(f.calls, tc.wantCalls) {
				t.Errorf("calls = %v, want %v", f.calls, tc.wantCalls)
			}
			if got := f.patches[0]["isGroupRestricted"]; got != tc.sentRestriction {
				t.Errorf("spec write isGroupRestricted = %v, want %v", got, tc.sentRestriction)
			}
			if wantRestricted := tc.wantGroups > 0; current.IsGroupRestricted != wantRestricted || len(current.AllowedUserGroups) != tc.wantGroups {
				t.Errorf("returned restricted=%v groups=%v, want %v and %d groups",
					current.IsGroupRestricted, current.AllowedUserGroups, wantRestricted, tc.wantGroups)
			}
		})
	}
}

// A 500 on the allowed-groups write is usually transient, so it is retried; anything else is not.
func TestUpdateAllowedGroups_Retries500(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failures  int
		status    int
		wantCalls int
		wantErr   bool
	}{
		{name: "recovers", failures: 2, status: http.StatusInternalServerError, wantCalls: 3},
		{name: "gives up", failures: 3, status: http.StatusInternalServerError, wantCalls: 3, wantErr: true},
		{name: "no retry on other errors", failures: 1, status: http.StatusBadRequest, wantCalls: 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeOIDCClient(t, "client-id", "app")
			calls := 0
			f.fail = func(*http.Request, map[string]any) (int, any) {
				calls++
				if calls <= tc.failures {
					return tc.status, map[string]string{"error": "boom"}
				}
				return 0, nil
			}
			err := updateAllowedGroups(context.Background(), f.api(), pid.OIDCClientID("client-id"), []string{"gid"})
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
			if calls != tc.wantCalls {
				t.Errorf("calls = %d, want %d", calls, tc.wantCalls)
			}
		})
	}
}

// --- Logo push behaviour ---

// Issue #603: autoGenerate=false against a client whose logo was uploaded through the UI
// must leave the logo alone and never record it as the operator's.
func TestPushOIDCClientState_UploadedLogoWithAutoGenerateOffIsLeftAlone(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClientCR := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "sync-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{AutoGenerate: new(false)},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "sync-id"},
	}
	r := newPushStateOIDCReconciler(scheme, oidcClientCR)
	f := newFakeOIDCClient(t, "sync-id", "sync-client")
	f.client.HasLogo, f.client.HasDarkLogo = true, true

	if _, err := r.pushOIDCClientState(context.Background(), oidcClientCR, f.api()); err != nil {
		t.Fatalf("pushOIDCClientState: %v", err)
	}
	if !slices.Equal(f.calls, []string{"PATCH"}) || len(f.logoPatches()) != 0 {
		t.Errorf("an uploaded logo is not the operator's to manage, got calls %v", f.calls)
	}
	if oidcClientCR.Status.LogoURL != "" || oidcClientCR.Status.DarkLogoURL != "" {
		t.Errorf("expected no applied record for an uploaded logo, got %q %q",
			oidcClientCR.Status.LogoURL, oidcClientCR.Status.DarkLogoURL)
	}
}

// A logo Pocket-ID cannot fetch must not hold the client back, and is not retried.
func TestPushOIDCClientState_LogoErrorIsNonFatalAndNotRetried(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClientCR := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "logo-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{LogoURL: "https://cdn.example.com/missing.png"},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "logo-id"},
	}
	r := newPushStateOIDCReconciler(scheme, oidcClientCR)
	f := newFakeOIDCClient(t, "logo-id", "logo-client")
	f.fail = logoRejected("https://cdn.example.com/missing.png", "https://cdn.example.com/other.png")
	apiClient := f.api()

	attempts := func() int {
		n := 0
		for _, call := range f.calls {
			if call == "PATCH" {
				n++
			}
		}
		return n
	}

	if _, err := r.pushOIDCClientState(context.Background(), oidcClientCR, apiClient); err != nil {
		t.Fatalf("expected a logo failure to be non-fatal, got %v", err)
	}
	// Rejected logo PATCHes are answered before being recorded, so only config PATCHes count.
	if attempts() != 1 {
		t.Fatalf("expected one config PATCH, got %v", f.calls)
	}
	if oidcClientCR.Status.LogoURL != "" {
		t.Errorf("a rejected URL must not be recorded as applied, got %q", oidcClientCR.Status.LogoURL)
	}
	if !r.logoURLFailed("https://cdn.example.com/missing.png") {
		t.Fatal("expected the URL to be remembered as failed")
	}

	// Same URL: skipped entirely on the next pass.
	rejected := 0
	f.fail = func(req *http.Request, body map[string]any) (int, any) {
		status, resp := logoRejected("https://cdn.example.com/missing.png", "https://cdn.example.com/other.png")(req, body)
		if status != 0 {
			rejected++
		}
		return status, resp
	}
	if _, err := r.pushOIDCClientState(context.Background(), oidcClientCR, apiClient); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rejected != 0 {
		t.Errorf("expected the failed URL not to be retried, got %d attempts", rejected)
	}

	// A different URL is a different key, so it is tried once.
	oidcClientCR.Spec.Logo.LogoURL = "https://cdn.example.com/other.png"
	if _, err := r.pushOIDCClientState(context.Background(), oidcClientCR, apiClient); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rejected != 1 {
		t.Errorf("expected a changed URL to be attempted once, got %d", rejected)
	}
}

// The default templates resolve a dark URL that dashboard-icons often does not have, so a
// dark failure must leave the light logo owned, applied and retryable.
func TestPushOIDCClientState_DarkLogoFailureLeavesLightLogoIntact(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	const lightURL = "https://cdn.example.com/app.png"
	const darkURL = "https://cdn.example.com/app-dark.png"

	oidcClientCR := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "logo-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{LogoURL: lightURL, DarkLogoURL: darkURL},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "logo-id"},
	}
	r := newPushStateOIDCReconciler(scheme, oidcClientCR)
	f := newFakeOIDCClient(t, "logo-id", "logo-client")
	f.fail = logoRejected(darkURL)
	apiClient := f.api()

	current, err := r.pushOIDCClientState(context.Background(), oidcClientCR, apiClient)
	if err != nil {
		t.Fatalf("expected the dark failure to be non-fatal, got %v", err)
	}
	if got := f.logoPatches(); !slices.Equal(got, []string{"light " + lightURL}) {
		t.Fatalf("expected the light logo to land, got %v", got)
	}
	if !current.HasLogo || current.HasDarkLogo {
		t.Errorf("expected the returned client to carry only the light logo, got %+v", current)
	}
	if oidcClientCR.Status.LogoURL != lightURL {
		t.Errorf("light logo should stay applied, got %q", oidcClientCR.Status.LogoURL)
	}
	if oidcClientCR.Status.DarkLogoURL != "" {
		t.Errorf("rejected dark logo must not be recorded, got %q", oidcClientCR.Status.DarkLogoURL)
	}
	if r.logoURLFailed(lightURL) {
		t.Error("the light URL must not inherit the dark failure")
	}
	if !r.logoURLFailed(darkURL) {
		t.Error("the dark URL should be remembered as failed")
	}

	// Next pass: light is in place and dark is skipped, so no logo is sent at all.
	f.patches = nil
	if _, err := r.pushOIDCClientState(context.Background(), oidcClientCR, apiClient); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := f.logoPatches(); len(got) != 0 {
		t.Errorf("expected no further logo updates, got %v", got)
	}
}
