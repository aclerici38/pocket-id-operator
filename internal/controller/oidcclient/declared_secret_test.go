package oidcclient

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

const declaredSecretValue = "declared-secret-value"

// fakeClientSecretAPI records SetOIDCClientSecret calls. The embedded interface leaves every
// other method nil, so an unexpected call panics rather than silently passing.
type fakeClientSecretAPI struct {
	PocketIDOIDCClientAPI
	calls   []string
	returns string // when non-empty, returned instead of the requested secret
	err     error
}

func (f *fakeClientSecretAPI) SetOIDCClientSecret(_ context.Context, _, secret string) (string, error) {
	f.calls = append(f.calls, secret)
	if f.err != nil {
		return "", f.err
	}
	if f.returns != "" {
		return f.returns, nil
	}
	return secret, nil
}

func declaredSecretReconciler(t *testing.T, objs ...client.Object) *Reconciler {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("add corev1 scheme: %v", err)
	}
	if err := pocketidinternalv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add pocketid scheme: %v", err)
	}
	fc := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).WithStatusSubresource(objs...).Build()
	r := &Reconciler{Client: fc, APIReader: fc, Scheme: s}
	r.EnsureClient(fc)
	return r
}

// declaredClient builds an OIDC client referencing sourceName/sourceKey for its client secret.
func declaredClient(sourceName, sourceKey string) *pocketidinternalv1alpha1.PocketIDOIDCClient {
	return &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-client", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			ClientSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: sourceName},
				Key:                  sourceKey,
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "abc123"},
	}
}

func sourceSecret(name string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Data:       data,
	}
}

func TestValidateClientSecret(t *testing.T) {
	tests := []struct {
		name    string
		secret  string
		wantErr string
	}{
		{name: "exactly minimum length", secret: strings.Repeat("a", 16)},
		{name: "printable ascii with space", secret: "a valid secret !~"},
		{name: "too short", secret: strings.Repeat("a", 15), wantErr: "at least 16 characters"},
		{name: "empty", secret: "", wantErr: "at least 16 characters"},
		{name: "contains tab", secret: "abcdefghijklmno\tp", wantErr: "printable ASCII"},
		{name: "contains newline", secret: "abcdefghijklmno\np", wantErr: "printable ASCII"},
		{name: "contains DEL", secret: "abcdefghijklmno\x7fp", wantErr: "printable ASCII"},
		{name: "contains non-ascii", secret: "abcdefghijklmnopé", wantErr: "printable ASCII"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClientSecret(tt.secret)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestResolveDeclaredClientSecret_Success(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)

	secret, version, err := r.resolveDeclaredClientSecret(context.Background(), oidcClient)
	if err != nil {
		t.Fatalf("resolveDeclaredClientSecret returned error: %v", err)
	}
	if secret != declaredSecretValue {
		t.Fatalf("expected secret %q, got %q", declaredSecretValue, secret)
	}
	if !strings.HasPrefix(version, "app-creds/secret@") {
		t.Fatalf("expected version to identify source name/key, got %q", version)
	}
}

// The version must track the source Secret's revision so an edit triggers a fresh push.
func TestResolveDeclaredClientSecret_VersionChangesWithSource(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)
	ctx := context.Background()

	_, before, err := r.resolveDeclaredClientSecret(ctx, oidcClient)
	if err != nil {
		t.Fatalf("resolveDeclaredClientSecret returned error: %v", err)
	}

	src.Data["secret"] = []byte("a-brand-new-secret-value")
	if err := r.Update(ctx, src); err != nil {
		t.Fatalf("update source secret: %v", err)
	}

	_, after, err := r.resolveDeclaredClientSecret(ctx, oidcClient)
	if err != nil {
		t.Fatalf("resolveDeclaredClientSecret returned error: %v", err)
	}
	if before == after {
		t.Fatalf("expected version to change after source edit, got %q both times", before)
	}
}

func TestResolveDeclaredClientSecret_Errors(t *testing.T) {
	tests := []struct {
		name       string
		refName    string
		refKey     string
		sourceName string
		data       map[string][]byte
		wantErr    string
	}{
		{
			name: "source secret missing", refName: "absent", refKey: "secret",
			sourceName: "app-creds", data: map[string][]byte{"secret": []byte(declaredSecretValue)},
			wantErr: "get client secret absent",
		},
		{
			name: "key missing", refName: "app-creds", refKey: "wrong-key",
			sourceName: "app-creds", data: map[string][]byte{"secret": []byte(declaredSecretValue)},
			wantErr: "missing key wrong-key",
		},
		{
			name: "value fails validation", refName: "app-creds", refKey: "secret",
			sourceName: "app-creds", data: map[string][]byte{"secret": []byte("too-short")},
			wantErr: "at least 16 characters",
		},
		{
			// Pointing at the operator's own output Secret would make the client secret
			// self-referential; reject it rather than lock in a generated value.
			name: "references operator-managed secret", refName: "my-client-oidc-credentials", refKey: "client_secret",
			sourceName: "my-client-oidc-credentials", data: map[string][]byte{"client_secret": []byte(declaredSecretValue)},
			wantErr: "must not reference the operator-managed secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oidcClient := declaredClient(tt.refName, tt.refKey)
			r := declaredSecretReconciler(t, oidcClient, sourceSecret(tt.sourceName, tt.data))

			_, _, err := r.resolveDeclaredClientSecret(context.Background(), oidcClient)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestSyncDeclaredClientSecret_PushesAndRecordsVersion(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)
	api := &fakeClientSecretAPI{}

	if err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api); err != nil {
		t.Fatalf("SyncDeclaredClientSecret returned error: %v", err)
	}
	if len(api.calls) != 1 || api.calls[0] != declaredSecretValue {
		t.Fatalf("expected one push of the declared secret, got %v", api.calls)
	}
	if oidcClient.Status.ClientSecretSourceVersion == "" {
		t.Fatal("expected status.clientSecretSourceVersion to be recorded")
	}

	// The recorded version must be persisted, not just set in memory.
	persisted := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "my-client", Namespace: testNamespace}, persisted); err != nil {
		t.Fatalf("get oidc client: %v", err)
	}
	if persisted.Status.ClientSecretSourceVersion != oidcClient.Status.ClientSecretSourceVersion {
		t.Fatalf("expected persisted version %q, got %q",
			oidcClient.Status.ClientSecretSourceVersion, persisted.Status.ClientSecretSourceVersion)
	}
}

func TestSyncDeclaredClientSecret_SkipsWhenSourceUnchanged(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)
	api := &fakeClientSecretAPI{}
	ctx := context.Background()

	if err := r.SyncDeclaredClientSecret(ctx, oidcClient, api); err != nil {
		t.Fatalf("first sync returned error: %v", err)
	}
	if err := r.SyncDeclaredClientSecret(ctx, oidcClient, api); err != nil {
		t.Fatalf("second sync returned error: %v", err)
	}

	if len(api.calls) != 1 {
		t.Fatalf("expected the unchanged source to be pushed once, got %d pushes", len(api.calls))
	}
}

func TestSyncDeclaredClientSecret_RepushesWhenSourceChanges(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)
	api := &fakeClientSecretAPI{}
	ctx := context.Background()

	if err := r.SyncDeclaredClientSecret(ctx, oidcClient, api); err != nil {
		t.Fatalf("first sync returned error: %v", err)
	}

	const rotated = "a-brand-new-secret-value"
	src.Data["secret"] = []byte(rotated)
	if err := r.Update(ctx, src); err != nil {
		t.Fatalf("update source secret: %v", err)
	}

	if err := r.SyncDeclaredClientSecret(ctx, oidcClient, api); err != nil {
		t.Fatalf("second sync returned error: %v", err)
	}
	if len(api.calls) != 2 || api.calls[1] != rotated {
		t.Fatalf("expected the edited source to be pushed, got %v", api.calls)
	}
}

func TestSyncDeclaredClientSecret_NoRefIsNoOp(t *testing.T) {
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-client", Namespace: testNamespace},
		Status:     pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "abc123"},
	}
	r := declaredSecretReconciler(t, oidcClient)
	api := &fakeClientSecretAPI{}

	if err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api); err != nil {
		t.Fatalf("SyncDeclaredClientSecret returned error: %v", err)
	}
	if len(api.calls) != 0 {
		t.Fatalf("expected no push without a clientSecretRef, got %v", api.calls)
	}
}

// Removing the ref must clear the recorded version so re-adding it pushes again rather than
// matching a stale revision.
func TestSyncDeclaredClientSecret_RefRemovedClearsVersion(t *testing.T) {
	oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-client", Namespace: testNamespace},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
			ClientID:                  "abc123",
			ClientSecretSourceVersion: "app-creds/secret@42",
		},
	}
	r := declaredSecretReconciler(t, oidcClient)

	if err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, &fakeClientSecretAPI{}); err != nil {
		t.Fatalf("SyncDeclaredClientSecret returned error: %v", err)
	}
	if oidcClient.Status.ClientSecretSourceVersion != "" {
		t.Fatalf("expected version to be cleared, got %q", oidcClient.Status.ClientSecretSourceVersion)
	}
}

func TestSyncDeclaredClientSecret_SkipsBeforeClientExists(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	oidcClient.Status.ClientID = ""
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)
	api := &fakeClientSecretAPI{}

	if err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api); err != nil {
		t.Fatalf("SyncDeclaredClientSecret returned error: %v", err)
	}
	if len(api.calls) != 0 {
		t.Fatalf("expected no push before the client exists, got %v", api.calls)
	}
}

// A Pocket-ID older than v2.12.0 ignores the request body and generates a random secret. That
// must fail loudly, and must not be recorded as a successful push.
func TestSyncDeclaredClientSecret_RejectsGeneratedSecret(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)
	api := &fakeClientSecretAPI{returns: "something-pocket-id-generated"}

	err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api)
	if err == nil || !strings.Contains(err.Error(), "v2.12.0") {
		t.Fatalf("expected an error naming the required pocket-id version, got %v", err)
	}
	if oidcClient.Status.ClientSecretSourceVersion != "" {
		t.Fatalf("expected no version recorded on failure, got %q", oidcClient.Status.ClientSecretSourceVersion)
	}
}

func TestSyncDeclaredClientSecret_PropagatesAPIError(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)
	api := &fakeClientSecretAPI{err: errors.New("boom")}

	err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected the API error to propagate, got %v", err)
	}
	if oidcClient.Status.ClientSecretSourceVersion != "" {
		t.Fatalf("expected no version recorded on failure, got %q", oidcClient.Status.ClientSecretSourceVersion)
	}
}

// A missing source must surface as an error, never as a silent fallback to a generated secret.
func TestSyncDeclaredClientSecret_MissingSourceDoesNotMint(t *testing.T) {
	oidcClient := declaredClient("absent", "secret")
	r := declaredSecretReconciler(t, oidcClient)
	api := &fakeClientSecretAPI{}

	if err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api); err == nil {
		t.Fatal("expected an error when the source secret is missing")
	}
	if len(api.calls) != 0 {
		t.Fatalf("expected no push when the source is missing, got %v", api.calls)
	}
}

func TestReconcileClientSecretData_DeclaredSecretIsMirrored(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)
	keys := r.GetSecretKeys(oidcClient)
	secretData := map[string][]byte{}

	// apiClient is nil: the declarative path must never reach the regenerate call.
	rotatedAt, scheduled, err := r.reconcileClientSecretData(
		context.Background(), oidcClient, nil, nil, r.GetSecretName(oidcClient), keys, secretData)
	if err != nil {
		t.Fatalf("reconcileClientSecretData returned error: %v", err)
	}
	if rotatedAt != nil || scheduled {
		t.Fatalf("expected no rotation, got rotatedAt=%v scheduled=%v", rotatedAt, scheduled)
	}
	if got := string(secretData[keys.ClientSecret]); got != declaredSecretValue {
		t.Fatalf("expected declared secret to be mirrored, got %q", got)
	}
}

func TestReconcileClientSecretData_DeclaredSecretRespectsStoreClientSecret(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	oidcClient.Spec.Secret = &pocketidinternalv1alpha1.OIDCClientSecretSpec{StoreClientSecret: boolPtr(false)}
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)
	keys := r.GetSecretKeys(oidcClient)
	secretData := map[string][]byte{}

	if _, _, err := r.reconcileClientSecretData(
		context.Background(), oidcClient, nil, nil, r.GetSecretName(oidcClient), keys, secretData); err != nil {
		t.Fatalf("reconcileClientSecretData returned error: %v", err)
	}
	if _, exists := secretData[keys.ClientSecret]; exists {
		t.Fatal("expected no client_secret key when storeClientSecret is false")
	}
}

// The regenerate annotation must be fully ignored while a secret is declared: honouring it would
// replace the declared value with a generated one.
func TestReconcileClientSecretData_DeclaredSecretIgnoresRegenerateAnnotation(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	oidcClient.Annotations = map[string]string{regenerateClientSecretAnnotation: "true"}
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)
	keys := r.GetSecretKeys(oidcClient)
	secretData := map[string][]byte{}

	// A nil apiClient makes any regeneration attempt fail loudly instead of passing silently.
	rotatedAt, _, err := r.reconcileClientSecretData(
		context.Background(), oidcClient, nil, nil, r.GetSecretName(oidcClient), keys, secretData)
	if err != nil {
		t.Fatalf("reconcileClientSecretData returned error: %v", err)
	}
	if rotatedAt != nil {
		t.Fatal("expected the regenerate annotation to be ignored for a declared secret")
	}
	if got := string(secretData[keys.ClientSecret]); got != declaredSecretValue {
		t.Fatalf("expected the declared secret to be kept, got %q", got)
	}
}

// pendingInitialMint exists to let a freshly created client mint its first secret. A declared
// secret must win over it so no generated value is ever pushed.
func TestReconcileClientSecretData_DeclaredSecretSuppressesInitialMint(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)
	r.pendingInitialMint = map[types.NamespacedName]bool{
		client.ObjectKeyFromObject(oidcClient): true,
	}
	keys := r.GetSecretKeys(oidcClient)
	secretData := map[string][]byte{}

	rotatedAt, _, err := r.reconcileClientSecretData(
		context.Background(), oidcClient, nil, nil, r.GetSecretName(oidcClient), keys, secretData)
	if err != nil {
		t.Fatalf("reconcileClientSecretData returned error: %v", err)
	}
	if rotatedAt != nil {
		t.Fatal("expected no mint for a declared secret")
	}
	if got := string(secretData[keys.ClientSecret]); got != declaredSecretValue {
		t.Fatalf("expected the declared secret to be stored, got %q", got)
	}
}

func TestReconcileClientSecretData_DeclaredSecretPropagatesResolveError(t *testing.T) {
	oidcClient := declaredClient("absent", "secret")
	r := declaredSecretReconciler(t, oidcClient)
	keys := r.GetSecretKeys(oidcClient)

	_, _, err := r.reconcileClientSecretData(
		context.Background(), oidcClient, nil, nil, r.GetSecretName(oidcClient), keys, map[string][]byte{})
	if err == nil {
		t.Fatal("expected an error when the source secret is missing")
	}
}

// An externally deleted client is recreated without a secret, so the recorded version must be
// dropped or the declared secret would never be re-pushed.
func TestClearClientStatus_ClearsClientSecretSourceVersion(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	oidcClient.Status.ClientSecretSourceVersion = "app-creds/secret@42"
	r := declaredSecretReconciler(t, oidcClient)

	if err := r.clearClientStatus(context.Background(), oidcClient); err != nil {
		t.Fatalf("clearClientStatus returned error: %v", err)
	}
	if oidcClient.Status.ClientID != "" || oidcClient.Status.ClientSecretSourceVersion != "" {
		t.Fatalf("expected cleared status, got clientID=%q version=%q",
			oidcClient.Status.ClientID, oidcClient.Status.ClientSecretSourceVersion)
	}
}
