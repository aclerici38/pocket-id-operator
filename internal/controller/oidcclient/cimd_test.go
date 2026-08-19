package oidcclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// fakeRefreshAPI records RefreshOIDCClientMetadata calls. The embedded interface leaves every
// other method nil, so an unexpected call panics rather than silently passing.
type fakeRefreshAPI struct {
	PocketIDOIDCClientAPI
	calls []string
	err   error
}

func (f *fakeRefreshAPI) RefreshOIDCClientMetadata(_ context.Context, id string) error {
	f.calls = append(f.calls, id)
	return f.err
}

func cimdClient(annotations map[string]string) *pocketidinternalv1alpha1.PocketIDOIDCClient {
	return &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "my-client",
			Namespace:   testNamespace,
			Annotations: annotations,
		},
	}
}

// annotationOf re-reads the object so the assertion covers the persisted state, not just the
// in-memory copy the helper mutated.
func annotationOf(t *testing.T, r *Reconciler, obj client.Object, key string) (string, bool) {
	t.Helper()
	fresh := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(obj), fresh); err != nil {
		t.Fatalf("get client: %v", err)
	}
	v, ok := fresh.Annotations[key]
	return v, ok
}

func TestRefreshClientMetadata_NoAnnotationIsNoOp(t *testing.T) {
	oidcClient := cimdClient(nil)
	oidcClient.Status.ClientID = "https://apps.example.com/meta.json"
	r := declaredSecretReconciler(t, oidcClient)
	api := &fakeRefreshAPI{}

	if err := r.refreshClientMetadata(context.Background(), oidcClient, api); err != nil {
		t.Fatalf("refreshClientMetadata returned error: %v", err)
	}
	if len(api.calls) != 0 {
		t.Fatalf("expected no refresh call, got %v", api.calls)
	}
}

func TestRefreshClientMetadata_NonTrueAnnotationIsNoOp(t *testing.T) {
	oidcClient := cimdClient(map[string]string{refreshClientMetadataAnnotation: "false"})
	oidcClient.Status.ClientID = "https://apps.example.com/meta.json"
	r := declaredSecretReconciler(t, oidcClient)
	api := &fakeRefreshAPI{}

	if err := r.refreshClientMetadata(context.Background(), oidcClient, api); err != nil {
		t.Fatalf("refreshClientMetadata returned error: %v", err)
	}
	if len(api.calls) != 0 {
		t.Fatalf("expected no refresh call, got %v", api.calls)
	}
	if _, ok := annotationOf(t, r, oidcClient, refreshClientMetadataAnnotation); !ok {
		t.Error("expected a non-\"true\" annotation to be left in place")
	}
}

func TestRefreshClientMetadata_UsesStatusClientID(t *testing.T) {
	oidcClient := cimdClient(map[string]string{refreshClientMetadataAnnotation: "true"})
	oidcClient.Status.ClientID = "https://apps.example.com/adopted.json"
	oidcClient.Spec.ClientID = "https://apps.example.com/spec.json"
	r := declaredSecretReconciler(t, oidcClient)
	api := &fakeRefreshAPI{}

	if err := r.refreshClientMetadata(context.Background(), oidcClient, api); err != nil {
		t.Fatalf("refreshClientMetadata returned error: %v", err)
	}
	if len(api.calls) != 1 || api.calls[0] != "https://apps.example.com/adopted.json" {
		t.Fatalf("expected one refresh of the status client ID, got %v", api.calls)
	}
	if _, ok := annotationOf(t, r, oidcClient, refreshClientMetadataAnnotation); ok {
		t.Error("expected the annotation to be removed")
	}
}

// spec.clientID is deliberately not a fallback: refreshing a client the operator has not
// adopted would act on something outside its management.
func TestRefreshClientMetadata_NotAdoptedErrors(t *testing.T) {
	oidcClient := cimdClient(map[string]string{refreshClientMetadataAnnotation: "true"})
	r := declaredSecretReconciler(t, oidcClient)
	api := &fakeRefreshAPI{}

	oidcClient.Spec.ClientID = "https://apps.example.com/spec.json"

	if err := r.refreshClientMetadata(context.Background(), oidcClient, api); err == nil {
		t.Fatal("expected an error when the client has not been adopted")
	}
	if len(api.calls) != 0 {
		t.Fatalf("expected no refresh call, got %v", api.calls)
	}
}

// The annotation must be cleared even when the refresh is rejected, so a standard client or a
// CIMD-disabled instance does not re-trigger the call on every resync.
func TestRefreshClientMetadata_FailureStillClearsAnnotation(t *testing.T) {
	oidcClient := cimdClient(map[string]string{refreshClientMetadataAnnotation: "true"})
	oidcClient.Status.ClientID = "grafana-id"
	r := declaredSecretReconciler(t, oidcClient)
	api := &fakeRefreshAPI{err: errors.New("client ID metadata documents are not enabled")}

	if err := r.refreshClientMetadata(context.Background(), oidcClient, api); err == nil {
		t.Fatal("expected the refresh error to be returned")
	}
	if _, ok := annotationOf(t, r, oidcClient, refreshClientMetadataAnnotation); ok {
		t.Error("expected the annotation to be removed despite the failure")
	}
}

// The whole point of managing CIMD clients: a spec that disagrees with the metadata
// document on metadata-owned fields must produce no diff, or the operator would push,
// read back the discarded values, and push again on every reconcile.
func TestPreserveMetadataOwnedFields_NoDiffAgainstMetadataOwnedValues(t *testing.T) {
	current := &pocketid.OIDCClient{
		ID:                 "https://apps.example.com/meta.json",
		Name:               "My App",
		CallbackURLs:       []string{"https://apps.example.com/cb"},
		LogoutCallbackURLs: []string{"https://apps.example.com/logout"},
		IsPublic:           true,
		PKCEEnabled:        true,
		ClientType:         pocketid.ClientTypeCIMD,
	}

	// What the operator would build from a CR that leaves every metadata-owned field at
	// its CRD default: a name from metadata.name, no callbacks, isPublic/pkceEnabled false.
	desired := pocketid.OIDCClientInput{
		Name:        "metadata-app",
		Credentials: &pocketid.OIDCClientCredentials{},
	}

	if desired.Equal(current.ToInput()) {
		t.Fatal("test is vacuous: the inputs already matched before preserving")
	}

	preserveMetadataOwnedFields(&desired, current)

	if !desired.Equal(current.ToInput()) {
		t.Errorf("expected no diff after preserving metadata-owned fields\n desired=%+v\n current=%+v", desired, current.ToInput())
	}
	if desired.Credentials != nil {
		t.Error("expected federated credentials to be dropped for a CIMD client")
	}
}

// The writable columns must still drive an update, otherwise adoption would be pointless.
func TestPreserveMetadataOwnedFields_KeepsWritableFields(t *testing.T) {
	current := &pocketid.OIDCClient{
		ID:                         "https://apps.example.com/meta.json",
		Name:                       "My App",
		ClientType:                 pocketid.ClientTypeCIMD,
		SkipConsent:                false,
		AccessTokenDurationMinutes: 60,
		IsGroupRestricted:          false,
	}
	desired := pocketid.OIDCClientInput{
		Name:                       "metadata-app",
		SkipConsent:                true,
		AccessTokenDurationMinutes: 15,
		IsGroupRestricted:          true,
	}

	preserveMetadataOwnedFields(&desired, current)

	if desired.Equal(current.ToInput()) {
		t.Fatal("expected the writable fields to still register as a change")
	}
	if !desired.SkipConsent || desired.AccessTokenDurationMinutes != 15 || !desired.IsGroupRestricted {
		t.Errorf("writable fields were overwritten: %+v", desired)
	}
}

// cimdCurrent is a CIMD client as Pocket-ID reports it: the metadata document owns the
// name, callbacks, and public/PKCE flags, all of which disagree with what a CR produces.
func cimdCurrent() *pocketid.OIDCClient {
	return &pocketid.OIDCClient{
		ID:                          "https://apps.example.com/meta.json",
		Name:                        "My App",
		CallbackURLs:                []string{"https://apps.example.com/cb"},
		LogoutCallbackURLs:          []string{"https://apps.example.com/logout"},
		IsPublic:                    true,
		PKCEEnabled:                 true,
		ClientType:                  pocketid.ClientTypeCIMD,
		AccessTokenDurationMinutes:  60,
		RefreshTokenDurationMinutes: 43200,
	}
}

func cimdClientCR(mutate func(*pocketidinternalv1alpha1.PocketIDOIDCClient)) *pocketidinternalv1alpha1.PocketIDOIDCClient {
	cr := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "metadata-app", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			ClientID:                    "https://apps.example.com/meta.json",
			AccessTokenDurationMinutes:  60,
			RefreshTokenDurationMinutes: 43200,
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			ClientID:   "https://apps.example.com/meta.json",
			ClientType: pocketid.ClientTypeCIMD,
		},
	}
	if mutate != nil {
		mutate(cr)
	}
	return cr
}

// The drift loop this design exists to prevent, asserted through the real reconcile path
// rather than the helper in isolation. This is deliberately the *first* reconcile (no Ready
// condition), which is when the operator would otherwise also push a credentials clear — so
// it covers both the metadata-owned diff and the CIMD credential skip.
func TestPushOIDCClientState_CIMDDoesNotDrift(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	cr := cimdClientCR(nil)
	r := newPushStateOIDCReconciler(scheme, cr)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		t.Errorf("unexpected %s %s: a CIMD client in sync on its writable fields must not be pushed",
			req.Method, req.URL.Path)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	updated, err := r.pushOIDCClientState(ctx, cr, apiClient, cimdCurrent())
	if err != nil {
		t.Fatalf("pushOIDCClientState returned error: %v", err)
	}
	if updated {
		t.Error("expected no update for a CIMD client that differs only on metadata-owned fields")
	}
}

// The counterpart: a writable field must still be pushed, and the payload must carry the
// metadata document's values rather than the CR's, so nothing is clobbered on the way.
func TestPushOIDCClientState_CIMDPushesWritableFields(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	cr := cimdClientCR(func(c *pocketidinternalv1alpha1.PocketIDOIDCClient) {
		c.Spec.SkipConsent = true
		c.Spec.AccessTokenDurationMinutes = 15
		c.Status.Conditions = readyCondition()
	})
	r := newPushStateOIDCReconciler(scheme, cr)

	var body map[string]any
	encodedPath := "/api/oidc/clients/~" + base64.RawURLEncoding.EncodeToString([]byte("https://apps.example.com/meta.json"))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPut || req.URL.EscapedPath() != encodedPath {
			t.Errorf("unexpected %s %s", req.Method, req.URL.EscapedPath())
			http.NotFound(w, req)
			return
		}
		_ = json.NewDecoder(req.Body).Decode(&body)
		okOIDCClientResponse(w, "https://apps.example.com/meta.json", "My App")
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if _, err := r.pushOIDCClientState(ctx, cr, apiClient, cimdCurrent()); err != nil {
		t.Fatalf("pushOIDCClientState returned error: %v", err)
	}

	if body == nil {
		t.Fatal("expected an update when a writable field changed")
	}
	if got, _ := body["skipConsent"].(bool); !got {
		t.Error("expected skipConsent to be pushed")
	}
	if got, _ := body["accessTokenDurationMinutes"].(float64); got != 15 {
		t.Errorf("accessTokenDurationMinutes: got %v, want 15", body["accessTokenDurationMinutes"])
	}
	if got, _ := body["name"].(string); got != "My App" {
		t.Errorf("name must carry the document value, got %q", got)
	}
	if got, _ := body["isPublic"].(bool); !got {
		t.Error("isPublic must carry the document value (true), not the CR default")
	}
}

// A CIMD client's metadata document must declare token_endpoint_auth_method "none", so it
// is always public and the operator must never try to mint or rotate a secret for it.
func TestIsPublicClient_TreatsCIMDAsPublic(t *testing.T) {
	oidcClient := cimdClient(nil)
	if isPublicClient(oidcClient) {
		t.Error("a standard confidential client should not be treated as public")
	}

	oidcClient.Status.ClientType = pocketid.ClientTypeCIMD
	if !isPublicClient(oidcClient) {
		t.Error("a CIMD client must be treated as public regardless of spec.isPublic")
	}
}

// The isPublicClient guard in effect, not just in isolation: a CIMD client leaves
// spec.isPublic false (admission rejects setting it), so without the guard ReconcileSecret
// would take the mint path and try to regenerate a secret on adoption. A nil apiClient
// makes any such call fail loudly instead of passing silently.
func TestReconcileSecret_CIMDClientSkipsSecretMinting(t *testing.T) {
	oidcClient := cimdClientCR(nil)
	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "my-instance", Namespace: testNamespace},
	}
	r := declaredSecretReconciler(t, oidcClient, instance)

	if err := r.ReconcileSecret(context.Background(), oidcClient, instance, nil, nil); err != nil {
		t.Fatalf("ReconcileSecret returned error: %v", err)
	}

	secret := &corev1.Secret{}
	key := types.NamespacedName{Name: r.GetSecretName(oidcClient), Namespace: testNamespace}
	if err := r.Get(context.Background(), key, secret); err != nil {
		t.Fatalf("expected the managed secret to be created: %v", err)
	}
	if _, ok := secret.Data[r.GetSecretKeys(oidcClient).ClientSecret]; ok {
		t.Error("a CIMD client is always public and must never have a client_secret stored")
	}
	if got := string(secret.Data[r.GetSecretKeys(oidcClient).ClientID]); got != oidcClient.Status.ClientID {
		t.Errorf("client_id: got %q, want %q", got, oidcClient.Status.ClientID)
	}
}

func TestReconcileErrorReason_ClassifiesAwaitingCIMD(t *testing.T) {
	if got := reconcileErrorReason(fmt.Errorf("adopt: %w", errAwaitingCIMD)); got != "AwaitingFirstAuthorization" {
		t.Errorf("reason: got %q, want %q", got, "AwaitingFirstAuthorization")
	}
	if got := reconcileErrorReason(errors.New("boom")); got != "ReconcileError" {
		t.Errorf("reason: got %q, want %q", got, "ReconcileError")
	}
}

// The CIMD row only exists after the app's first authorization, so a missing client is a
// waiting state. Falling through to CreateOrAdopt would register a standard client under
// the document URL instead. This also exercises the "~<base64url>" path encoding, since
// the stub only answers the encoded route.
func TestCreateOrAdoptOIDCClient_CIMD(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)

	const metadataURL = "https://apps.example.com/myapp/client-metadata.json"
	encodedPath := "/api/oidc/clients/~" + base64.RawURLEncoding.EncodeToString([]byte(metadataURL))

	for _, tc := range []struct {
		name           string
		materialized   bool
		wantAwaiting   bool
		wantStatusETag string
	}{
		{name: "not yet materialized", materialized: false, wantAwaiting: true},
		{name: "materialized", materialized: true, wantStatusETag: metadataURL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var createAttempted bool
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method == http.MethodPost && req.URL.Path == "/api/oidc/clients" {
					createAttempted = true
					http.Error(w, "must not create", http.StatusBadRequest)
					return
				}
				if req.Method == http.MethodGet && req.URL.Path == encodedPath {
					if !tc.materialized {
						http.NotFound(w, req)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"id":"` + metadataURL + `","name":"My App","clientType":"cimd","allowedUserGroups":[]}`))
					return
				}
				http.NotFound(w, req)
			}))
			defer ts.Close()

			oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{Name: "metadata-app", Namespace: testNamespace},
				Spec:       pocketidinternalv1alpha1.PocketIDOIDCClientSpec{ClientID: metadataURL},
			}
			r := newPushStateOIDCReconciler(scheme, oidcClient)
			apiClient, _ := pocketid.NewClient(ts.URL, "")

			_, err := r.createOrAdoptOIDCClient(ctx, oidcClient, apiClient)

			if createAttempted {
				t.Error("the operator must never create a CIMD client")
			}
			if tc.wantAwaiting {
				if !errors.Is(err, errAwaitingCIMD) {
					t.Fatalf("expected errAwaitingCIMD, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("createOrAdoptOIDCClient returned error: %v", err)
			}
			if oidcClient.Status.ClientID != tc.wantStatusETag {
				t.Errorf("status.clientID: got %q, want %q", oidcClient.Status.ClientID, tc.wantStatusETag)
			}
		})
	}
}

func TestUpdateOIDCClientStatus_RecordsClientType(t *testing.T) {
	oidcClient := cimdClient(nil)
	r := declaredSecretReconciler(t, oidcClient)

	current := &pocketid.OIDCClient{ID: "grafana-id", Name: "grafana", ClientType: "standard"}
	if err := r.UpdateOIDCClientStatus(context.Background(), oidcClient, current); err != nil {
		t.Fatalf("UpdateOIDCClientStatus returned error: %v", err)
	}
	if oidcClient.Status.ClientType != "standard" {
		t.Errorf("status.clientType: got %q, want %q", oidcClient.Status.ClientType, "standard")
	}
}

// A CIMD client is deleted like any other. Pocket-ID has no garbage collection for them —
// removing a URL from the allowlist only stops it resolving, and the row keeps appearing in
// the admin client list — so skipping the delete would strand a record nothing owns. The
// encoded path also has to survive the delete, since the ID is the document URL.
func TestReconcileDelete_DeletesCIMDClient(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	wantPath := "/api/oidc/clients/~" + base64.RawURLEncoding.EncodeToString(
		[]byte("https://apps.example.com/meta.json"))
	var deleted bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodDelete || req.URL.EscapedPath() != wantPath {
			t.Errorf("unexpected %s %s, want DELETE %s", req.Method, req.URL.EscapedPath(), wantPath)
			http.NotFound(w, req)
			return
		}
		deleted = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "external-instance", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			External: &pocketidinternalv1alpha1.ExternalInstanceConfig{
				URL: ts.URL,
				APIKeySecretRef: corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "external-api-key"},
					Key:                  "token",
				},
			},
		},
	}
	apiKeySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "external-api-key", Namespace: testNamespace},
		Data:       map[string][]byte{"token": []byte("a-token")},
	}
	resource := cimdClientCR(func(c *pocketidinternalv1alpha1.PocketIDOIDCClient) {
		c.Finalizers = []string{oidcClientFinalizer}
	})

	r := newPushStateOIDCReconciler(scheme, instance, apiKeySecret, resource)
	r.BaseReconciler.APIReader = r.Client

	if _, err := r.ReconcileDelete(ctx, resource); err != nil {
		t.Fatalf("ReconcileDelete returned error: %v", err)
	}

	if !deleted {
		t.Error("expected the CIMD client to be deleted from Pocket-ID")
	}

	updated := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(resource), updated); err != nil {
		t.Fatalf("get resource: %v", err)
	}
	for _, f := range updated.Finalizers {
		if f == oidcClientFinalizer {
			t.Error("expected the finalizer to be removed after deleting the client")
		}
	}
}
