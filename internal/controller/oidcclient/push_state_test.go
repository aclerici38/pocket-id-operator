package oidcclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const (
	grafanaLogoURL     = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/grafana.png"
	grafanaDarkLogoURL = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/grafana-dark.png"
)

// pocketIDOIDCClientAPIResponse is the JSON shape returned by Pocket-ID OIDC client
// endpoints, used in httptest servers within this package's tests.
type pocketIDOIDCClientAPIResponse struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	CallbackURLs       []string `json:"callbackURLs"`
	LogoutCallbackURLs []string `json:"logoutCallbackURLs"`
	HasLogo            bool     `json:"hasLogo"`
	HasDarkLogo        bool     `json:"hasDarkLogo"`
	IsPublic           bool     `json:"isPublic"`
	IsGroupRestricted  bool     `json:"isGroupRestricted"`
	PkceEnabled        bool     `json:"pkceEnabled"`
	AllowedUserGroups  []any    `json:"allowedUserGroups"`
}

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

// okOIDCClientResponse writes a minimal valid OIDC client JSON response.
func okOIDCClientResponse(w http.ResponseWriter, id, name string) {
	resp := pocketIDOIDCClientAPIResponse{
		ID:                 id,
		Name:               name,
		CallbackURLs:       []string{},
		LogoutCallbackURLs: []string{},
		AllowedUserGroups:  []any{},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// --- OidcClientInput callback URL fallback tests ---

func TestOidcClientInput_CallbackURLFallbackFromCurrent(t *testing.T) {
	// When spec has no callbackURLs, OidcClientInput uses the current server-side URLs.
	reconciler := &Reconciler{}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "test-client", Namespace: testNamespace},
		// No spec.callbackURLs or spec.logoutCallbackURLs
	}
	current := &pocketid.OIDCClient{
		CallbackURLs:       []string{"https://current.example.com/cb"},
		LogoutCallbackURLs: []string{"https://current.example.com/logout"},
	}

	input := reconciler.OidcClientInput(oidcClient, current, "", "")

	if len(input.CallbackURLs) != 1 || input.CallbackURLs[0] != "https://current.example.com/cb" {
		t.Errorf("expected fallback to current callback URLs, got %v", input.CallbackURLs)
	}
	if len(input.LogoutCallbackURLs) != 1 || input.LogoutCallbackURLs[0] != "https://current.example.com/logout" {
		t.Errorf("expected fallback to current logout callback URLs, got %v", input.LogoutCallbackURLs)
	}
}

func TestOidcClientInput_SpecCallbackURLsTakePrecedenceOverCurrent(t *testing.T) {
	// When spec has callbackURLs, they take precedence over current server-side values.
	reconciler := &Reconciler{}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "test-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			CallbackURLs:       []string{"https://spec.example.com/cb"},
			LogoutCallbackURLs: []string{"https://spec.example.com/logout"},
		},
	}
	current := &pocketid.OIDCClient{
		CallbackURLs:       []string{"https://current.example.com/cb"},
		LogoutCallbackURLs: []string{"https://current.example.com/logout"},
	}

	input := reconciler.OidcClientInput(oidcClient, current, "", "")

	if len(input.CallbackURLs) != 1 || input.CallbackURLs[0] != "https://spec.example.com/cb" {
		t.Errorf("expected spec callback URLs to take precedence, got %v", input.CallbackURLs)
	}
	if len(input.LogoutCallbackURLs) != 1 || input.LogoutCallbackURLs[0] != "https://spec.example.com/logout" {
		t.Errorf("expected spec logout callback URLs to take precedence, got %v", input.LogoutCallbackURLs)
	}
}

// --- Logo URL resolution tests ---

func boolPtr(b bool) *bool { return &b }

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
			LogoURL:     "https://explicit.example.com/logo.png",
			DarkLogoURL: "https://explicit.example.com/logo-dark.png",
			Logo:        &pocketidinternalv1alpha1.OIDCClientLogoSpec{AutoGenerate: boolPtr(true)},
		},
	}
	logoURL, darkLogoURL := r.resolveLogoURLs(oidcClient)
	if logoURL != "https://explicit.example.com/logo.png" {
		t.Errorf("expected deprecated logoUrl to win, got %q", logoURL)
	}
	if darkLogoURL != "https://explicit.example.com/logo-dark.png" {
		t.Errorf("expected deprecated darkLogoUrl to win, got %q", darkLogoURL)
	}

	// Verify OidcClientInput passes the resolved URLs through to the payload
	input := r.OidcClientInput(oidcClient, nil, logoURL, darkLogoURL)
	if input.LogoURL != logoURL {
		t.Errorf("expected logoUrl in OidcClientInput, got %q", input.LogoURL)
	}
	if input.DarkLogoURL != darkLogoURL {
		t.Errorf("expected darkLogoUrl in OidcClientInput, got %q", input.DarkLogoURL)
	}
}

func TestResolveLogoURLs_NameOverride(t *testing.T) {
	r := &Reconciler{}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-app", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{
				AutoGenerate: boolPtr(true),
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
				AutoGenerate: boolPtr(true),
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

func TestResolveLogoURLs_HardcodedDefaults(t *testing.T) {
	r := &Reconciler{}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "grafana", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{
				AutoGenerate: boolPtr(true),
			},
		},
	}
	logoURL, darkLogoURL := r.resolveLogoURLs(oidcClient)
	if logoURL != grafanaLogoURL {
		t.Errorf("expected hardcoded default logo template, got %q", logoURL)
	}
	if darkLogoURL != grafanaDarkLogoURL {
		t.Errorf("expected hardcoded default dark logo template, got %q", darkLogoURL)
	}
}

func TestResolveLogoURLs_AutoGenerateFalse(t *testing.T) {
	r := &Reconciler{}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-app", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{
				AutoGenerate: boolPtr(false),
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
				AutoGenerate: boolPtr(false),
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
	r := &Reconciler{DefaultAutoGenerateLogos: true}
	logoURL, darkLogoURL := r.resolveLogoURLs(namedClient("my-app"))
	if logoURL != "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/my-app.png" {
		t.Errorf("expected hardcoded default when logo spec is nil and env is true, got %q", logoURL)
	}
	if darkLogoURL != "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/my-app-dark.png" {
		t.Errorf("expected hardcoded dark default when logo spec is nil and env is true, got %q", darkLogoURL)
	}
}

func TestResolveLogoURLs_AutoGenerateNilDefaultsToEnvTrue(t *testing.T) {
	r := &Reconciler{DefaultAutoGenerateLogos: true}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-app", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{},
		},
	}
	logoURL, _ := r.resolveLogoURLs(oidcClient)
	if logoURL != "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/my-app.png" {
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
	r := &Reconciler{DefaultAutoGenerateLogos: false}
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-app", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Logo: &pocketidinternalv1alpha1.OIDCClientLogoSpec{
				AutoGenerate: boolPtr(true),
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
				AutoGenerate: boolPtr(true),
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

// fakeLogoAPI records logo deletions. The embedded interface leaves every other method nil,
// so an unexpected call panics rather than silently passing.
type fakeLogoAPI struct {
	PocketIDOIDCClientAPI
	deleted []bool         // one entry per delete, true for the light side
	err     error          // fails every delete
	errOn   map[bool]error // fails one side, keyed the same way as deleted
}

func (f *fakeLogoAPI) DeleteOIDCClientLogo(_ context.Context, _ string, light bool) error {
	if f.err != nil {
		return f.err
	}
	if err := f.errOn[light]; err != nil {
		return err
	}
	f.deleted = append(f.deleted, light)
	return nil
}

// logoClient builds a CR resolving light via the deprecated field, with appliedLight and
// appliedDark already recorded in status. Callers needing a dark URL set it on the spec.
func logoClient(light, appliedLight, appliedDark string) *pocketidinternalv1alpha1.PocketIDOIDCClient {
	return &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-app", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			LogoURL: light,
			Logo:    &pocketidinternalv1alpha1.OIDCClientLogoSpec{AutoGenerate: boolPtr(false)},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			LogoURL:     appliedLight,
			DarkLogoURL: appliedDark,
		},
	}
}

func TestReconcileLogos_BehaviorTable(t *testing.T) {
	const url = "https://cdn.example.com/logo.png"

	tests := []struct {
		name                  string
		resolved, applied     string
		serverHasLogo         bool
		failed                bool
		wantPush, wantApplied string
		wantDelete            bool
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
			name:     "a new URL is pushed",
			resolved: url, wantPush: url, wantApplied: url,
		},
		{
			name:     "a changed URL is pushed",
			resolved: url, applied: "https://cdn.example.com/old.png", serverHasLogo: true,
			wantPush: url, wantApplied: url,
		},
		{
			name:     "an applied logo deleted server-side is re-pushed",
			resolved: url, applied: url, wantPush: url, wantApplied: url,
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
			api := &fakeLogoAPI{}

			// Run each row on both sides so neither is special-cased.
			for _, light := range []bool{true, false} {
				oidcClient := logoClient("", "", "")
				current := &pocketid.OIDCClient{ID: "client-id"}
				if light {
					oidcClient.Spec.LogoURL, oidcClient.Status.LogoURL, current.HasLogo = tt.resolved, tt.applied, tt.serverHasLogo
				} else {
					oidcClient.Spec.DarkLogoURL, oidcClient.Status.DarkLogoURL, current.HasDarkLogo = tt.resolved, tt.applied, tt.serverHasLogo
				}

				r := newPushStateOIDCReconciler(scheme, oidcClient)
				if tt.failed {
					r.markLogoURLsFailed(tt.resolved)
				}
				api.deleted = nil
				plan, err := r.reconcileLogos(context.Background(), oidcClient, api, current)
				if err != nil {
					t.Fatalf("light=%v: reconcileLogos: %v", light, err)
				}
				plan.commit()

				push, applied := plan.pushDark, plan.appliedDark
				if light {
					push, applied = plan.pushLight, plan.appliedLight
				}
				if push != tt.wantPush {
					t.Errorf("light=%v: push: got %q, want %q", light, push, tt.wantPush)
				}
				if applied != tt.wantApplied {
					t.Errorf("light=%v: applied: got %q, want %q", light, applied, tt.wantApplied)
				}
				if want := []bool(nil); !tt.wantDelete && !slices.Equal(api.deleted, want) {
					t.Errorf("light=%v: expected no deletions, got %v", light, api.deleted)
				}
				if tt.wantDelete && !slices.Equal(api.deleted, []bool{light}) {
					t.Errorf("light=%v: expected one deletion of that side, got %v", light, api.deleted)
				}
			}
		})
	}
}

// A client that resolves only a light URL must not disturb an uploaded dark logo.
func TestReconcileLogos_OnlyLightResolvedLeavesUploadedDarkLogo(t *testing.T) {
	r := &Reconciler{}
	api := &fakeLogoAPI{}
	oidcClient := logoClient("https://cdn.example.com/logo.png", "", "")
	current := &pocketid.OIDCClient{ID: "client-id", HasDarkLogo: true}

	plan, err := r.reconcileLogos(context.Background(), oidcClient, api, current)
	if err != nil {
		t.Fatalf("reconcileLogos: %v", err)
	}
	if len(api.deleted) != 0 {
		t.Errorf("expected no deletions, got %v", api.deleted)
	}
	if plan.pushDark != "" {
		t.Errorf("expected no dark push, got %q", plan.pushDark)
	}
	if plan.pushLight != "https://cdn.example.com/logo.png" {
		t.Errorf("expected the light URL to be pushed, got %q", plan.pushLight)
	}
}

func TestReconcileLogos_DeleteFailurePropagates(t *testing.T) {
	r := &Reconciler{}
	api := &fakeLogoAPI{err: errors.New("boom")}
	oidcClient := logoClient("", "https://cdn.example.com/logo.png", "")

	if _, err := r.reconcileLogos(context.Background(), oidcClient, api, &pocketid.OIDCClient{ID: "client-id"}); err == nil {
		t.Fatal("expected the delete failure to propagate")
	}
}

func TestMarkLogoURLsFailed_IgnoresEmptyAndKeysByURL(t *testing.T) {
	r := &Reconciler{}
	r.markLogoURLsFailed("", "https://cdn.example.com/logo.png")
	if r.logoURLFailed("") {
		t.Error("an empty URL must not be recorded")
	}
	if !r.logoURLFailed("https://cdn.example.com/logo.png") {
		t.Error("expected the URL to be recorded as failed")
	}
	if r.logoURLFailed("https://cdn.example.com/other.png") {
		t.Error("a different URL must not inherit the failure")
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

	fc := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(oidcClient).
		WithStatusSubresource(oidcClient).
		Build()
	r := &Reconciler{Client: fc, Scheme: scheme}
	r.EnsureClient(fc)

	ctx := context.Background()

	// Light logo newly applied, dark logo released back to Pocket-ID.
	plan := logoPlan{appliedLight: "https://example.com/logo.png"}
	if err := r.applyLogoStatus(ctx, oidcClient, plan); err != nil {
		t.Fatalf("applyLogoStatus failed: %v", err)
	}

	fetched := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
	if err := fc.Get(ctx, client.ObjectKeyFromObject(oidcClient), fetched); err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if fetched.Status.LogoURL != "https://example.com/logo.png" {
		t.Errorf("expected logoUrl to be recorded, got %q", fetched.Status.LogoURL)
	}
	if fetched.Status.DarkLogoURL != "" {
		t.Errorf("expected darkLogoUrl to be cleared, got %q", fetched.Status.DarkLogoURL)
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
	groupC := mkGroup("group-c", "gid-c")
	groupA := mkGroup("group-a", "gid-a")
	groupB := mkGroup("group-b", "gid-b")

	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "sort-client", Namespace: testNamespace},
	}

	fc := newAggregationFakeClient(scheme, groupC, groupA, groupB, oidcClient)
	reconciler := &Reconciler{Client: fc, Scheme: scheme}

	ids, err := reconciler.aggregateAllowedUserGroupIDs(ctx, oidcClient, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("expected 3 IDs, got %v", ids)
	}
	if ids[0] != "gid-a" || ids[1] != "gid-b" || ids[2] != "gid-c" {
		t.Errorf("expected sorted [gid-a, gid-b, gid-c], got %v", ids)
	}
}

// --- pushOIDCClientState tests ---

func TestPushOIDCClientState_SkipsWhenInSync(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClientCR := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "sync-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			CallbackURLs: []string{"https://example.com/cb"},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			ClientID:   "sync-id",
			Conditions: readyCondition(), // already ready → not firstReconcile
		},
	}

	// current matches desired: same name, same callback URLs, no groups, no credentials
	current := &pocketid.OIDCClient{
		ID:           "sync-id",
		Name:         "sync-client",
		CallbackURLs: []string{"https://example.com/cb"},
	}

	r := newPushStateOIDCReconciler(scheme, oidcClientCR)

	// Server that fails on any call — verifies no API calls are made.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("unexpected API call during in-sync pushOIDCClientState")
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if _, err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPushOIDCClientState_UpdatesWhenFieldsChange(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClientCR := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "update-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			CallbackURLs: []string{"https://new.example.com/cb"},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			ClientID:   "update-id",
			Conditions: readyCondition(),
		},
	}
	// current has different callback URLs → update required
	current := &pocketid.OIDCClient{
		ID:           "update-id",
		Name:         "update-client",
		CallbackURLs: []string{"https://old.example.com/cb"},
	}

	r := newPushStateOIDCReconciler(scheme, oidcClientCR)

	updateCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPut && req.URL.Path == "/api/oidc/clients/update-id" {
			updateCalled = true
			okOIDCClientResponse(w, "update-id", "update-client")
			return
		}
		http.NotFound(w, req)
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if _, err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !updateCalled {
		t.Error("expected UpdateOIDCClient to be called when callback URLs differ")
	}
}

func TestPushOIDCClientState_AlwaysPushesWhenCredentialsPresent(t *testing.T) {
	// Even when the visible state is in sync, the presence of credentials forces
	// an UpdateOIDCClient call because they are write-only and can't be compared.
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClientCR := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "cred-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			FederatedIdentities: []pocketidinternalv1alpha1.OIDCClientFederatedIdentity{
				{Issuer: "https://issuer.example.com", Subject: "sa:myapp"},
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			ClientID:   "cred-id",
			Conditions: readyCondition(),
		},
	}
	// current matches desired in all visible fields
	current := &pocketid.OIDCClient{
		ID:   "cred-id",
		Name: "cred-client",
	}

	r := newPushStateOIDCReconciler(scheme, oidcClientCR)

	updateCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPut && req.URL.Path == "/api/oidc/clients/cred-id" {
			updateCalled = true
			okOIDCClientResponse(w, "cred-id", "cred-client")
			return
		}
		http.NotFound(w, req)
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if _, err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !updateCalled {
		t.Error("expected UpdateOIDCClient when credentials are present (write-only fields can't be skipped)")
	}
}

func TestPushOIDCClientState_FirstReconcileClearsCredentials(t *testing.T) {
	// On the first reconcile (no Ready condition) with no credentials in spec,
	// pushOIDCClientState sends an empty FederatedIdentities list to clear any
	// credentials the adopted client may have had.
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClientCR := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "adopt-client", Namespace: testNamespace},
		Spec:       pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			// No FederatedIdentities
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			ClientID: "adopt-id",
			// No conditions → not ready → firstReconcile = true
		},
	}
	current := &pocketid.OIDCClient{
		ID:   "adopt-id",
		Name: "adopt-client",
	}

	r := newPushStateOIDCReconciler(scheme, oidcClientCR)

	updateCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPut && req.URL.Path == "/api/oidc/clients/adopt-id" {
			updateCalled = true
			okOIDCClientResponse(w, "adopt-id", "adopt-client")
			return
		}
		http.NotFound(w, req)
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if _, err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !updateCalled {
		t.Error("expected UpdateOIDCClient on first reconcile to clear any existing credentials")
	}
}

func TestPushOIDCClientState_UpdatesGroupsWhenChanged(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	groupA := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "group-a", Namespace: testNamespace},
		Status:     pocketidinternalv1alpha1.PocketIDUserGroupStatus{GroupID: "gid-a", Conditions: readyCondition()},
	}
	oidcClientCR := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "groups-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{{Name: "group-a"}},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			ClientID:   "groups-id",
			Conditions: readyCondition(),
		},
	}
	// current has no allowed groups → groups differ
	current := &pocketid.OIDCClient{
		ID:                  "groups-id",
		Name:                "groups-client",
		AllowedUserGroupIDs: []string{},
	}

	r := newPushStateOIDCReconciler(scheme, oidcClientCR, groupA)

	groupsUpdateCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodPut && req.URL.Path == "/api/oidc/clients/groups-id":
			okOIDCClientResponse(w, "groups-id", "groups-client")
		case req.Method == http.MethodPut && req.URL.Path == "/api/oidc/clients/groups-id/allowed-user-groups":
			groupsUpdateCalled = true
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, req)
		}
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if _, err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !groupsUpdateCalled {
		t.Error("expected UpdateOIDCClientAllowedGroups to be called when groups differ")
	}
}

func TestPushOIDCClientState_IsGroupRestrictedReflectsAggregation(t *testing.T) {
	// When a UserGroup reverse-references the OIDC client (via spec.allowedOIDCClients),
	// IsGroupRestricted must be set to true even if spec.allowedUserGroups is empty.
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "reverse-group", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			AllowedOIDCClients: []pocketidinternalv1alpha1.NamespacedOIDCClientReference{{Name: "restrict-client"}},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{GroupID: "gid-reverse", Conditions: readyCondition()},
	}
	oidcClientCR := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "restrict-client", Namespace: testNamespace},
		Spec:       pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			// No spec.allowedUserGroups — only a reverse reference from the group
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			ClientID:   "restrict-id",
			Conditions: readyCondition(),
		},
	}
	// current reports no groups → aggregation will produce one group → state differs
	current := &pocketid.OIDCClient{
		ID:                  "restrict-id",
		Name:                "restrict-client",
		AllowedUserGroupIDs: []string{},
	}

	r := newPushStateOIDCReconciler(scheme, oidcClientCR, group)

	groupsUpdateSent := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodPut && req.URL.Path == "/api/oidc/clients/restrict-id":
			okOIDCClientResponse(w, "restrict-id", "restrict-client")
		case req.Method == http.MethodPut && req.URL.Path == "/api/oidc/clients/restrict-id/allowed-user-groups":
			groupsUpdateSent = true
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, req)
		}
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if _, err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !groupsUpdateSent {
		t.Error("expected group update when UserGroup reverse-references the OIDC client")
	}
}

// --- Logo push behaviour ---

// Issue #603: autoGenerate=false against a client whose logo was uploaded through the UI
// used to diff hasLogo forever, re-issuing a PUT that could never converge.
func TestPushOIDCClientState_UploadedLogoWithAutoGenerateOffMakesNoCalls(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClientCR := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "sync-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			CallbackURLs: []string{"https://example.com/cb"},
			Logo:         &pocketidinternalv1alpha1.OIDCClientLogoSpec{AutoGenerate: boolPtr(false)},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			ClientID:   "sync-id",
			Conditions: readyCondition(),
		},
	}
	current := &pocketid.OIDCClient{
		ID:           "sync-id",
		Name:         "sync-client",
		CallbackURLs: []string{"https://example.com/cb"},
		HasLogo:      true,
		HasDarkLogo:  true,
	}

	r := newPushStateOIDCReconciler(scheme, oidcClientCR)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected %s %s: an uploaded logo is not the operator's to manage", r.Method, r.URL.Path)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	updated, err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated {
		t.Error("expected no update")
	}
	if oidcClientCR.Status.LogoURL != "" || oidcClientCR.Status.DarkLogoURL != "" {
		t.Errorf("expected no applied record for an uploaded logo, got %q %q",
			oidcClientCR.Status.LogoURL, oidcClientCR.Status.DarkLogoURL)
	}
}

// A logo Pocket-ID cannot fetch must not hold the client back: the configuration is already
// committed by the time the download runs, and failing here would re-push every resync.
func TestPushOIDCClientState_LogoErrorIsNonFatalAndNotRetried(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	oidcClientCR := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "logo-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			LogoURL: "https://cdn.example.com/missing.png",
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			ClientID:   "logo-id",
			Conditions: readyCondition(),
		},
	}
	current := &pocketid.OIDCClient{ID: "logo-id", Name: "logo-client"}

	r := newPushStateOIDCReconciler(scheme, oidcClientCR)
	var puts int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPut {
			t.Errorf("unexpected %s %s", req.Method, req.URL.Path)
			http.Error(w, "unexpected", http.StatusInternalServerError)
			return
		}
		puts++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "Logo could not be downloaded", "code": "logo_download_failed", "request_id": "req-1",
		})
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if _, err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current); err != nil {
		t.Fatalf("expected a logo failure to be non-fatal, got %v", err)
	}
	if puts != 1 {
		t.Fatalf("expected exactly one PUT, got %d", puts)
	}
	if oidcClientCR.Status.LogoURL != "" {
		t.Errorf("a rejected URL must not be recorded as applied, got %q", oidcClientCR.Status.LogoURL)
	}

	// Same URL: skipped entirely on the next pass.
	if _, err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if puts != 1 {
		t.Errorf("expected the failed URL not to be retried, got %d PUTs", puts)
	}

	// A different URL is a different key, so it is tried once.
	oidcClientCR.Spec.LogoURL = "https://cdn.example.com/other.png"
	if _, err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if puts != 2 {
		t.Errorf("expected a changed URL to be attempted, got %d PUTs", puts)
	}
}

// The default templates resolve a dark URL that dashboard-icons often does not have, so a
// dark failure must leave the light logo owned, applied and retryable.
func TestPushOIDCClientState_DarkLogoFailureLeavesLightLogoIntact(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	const lightURL = "https://cdn.example.com/app.png"
	const darkURL = "https://cdn.example.com/app-dark.png"

	oidcClientCR := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "logo-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			LogoURL:     lightURL,
			DarkLogoURL: darkURL,
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			ClientID:   "logo-id",
			Conditions: readyCondition(),
		},
	}
	current := &pocketid.OIDCClient{ID: "logo-id", Name: "logo-client"}

	r := newPushStateOIDCReconciler(scheme, oidcClientCR)
	var sent []string // darkLogoUrl of each PUT, so the two updates are distinguishable
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(req.Body).Decode(&body)
		dark, _ := body["darkLogoUrl"].(string)
		sent = append(sent, dark)

		if dark == "" { // the light update
			okOIDCClientResponse(w, "logo-id", "logo-client")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "Logo could not be downloaded", "code": "logo_download_failed",
		})
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if _, err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current); err != nil {
		t.Fatalf("expected the dark failure to be non-fatal, got %v", err)
	}
	if len(sent) != 2 || sent[0] != "" || sent[1] != darkURL {
		t.Fatalf("expected one update per side, got %q", sent)
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

	// Next pass: light is in place and dark is skipped, so nothing is sent at all.
	current.HasLogo = true
	sent = nil
	if _, err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sent) != 0 {
		t.Errorf("expected no further updates, got %q", sent)
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
	api := &fakeLogoAPI{errOn: map[bool]error{false: errors.New("boom")}}

	plan, err := r.reconcileLogos(context.Background(), oidcClient, api, &pocketid.OIDCClient{ID: "client-id"})
	if err == nil {
		t.Fatal("expected the dark deletion failure to propagate")
	}
	if plan.appliedLight != "" {
		t.Errorf("light was deleted, so it must be disowned: got %q", plan.appliedLight)
	}
	if plan.appliedDark != "https://cdn.example.com/dark.png" {
		t.Errorf("dark deletion failed, so it stays owned: got %q", plan.appliedDark)
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
	r.EnsureClient(r.Client)

	api := &fakeLogoAPI{errOn: map[bool]error{false: errors.New("delete refused")}}

	_, err := r.reconcileLogos(context.Background(), oidcClient, api, &pocketid.OIDCClient{ID: "client-id"})
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
