package oidcclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const declaredSecretValue = "declared-secret-value"

// fakeSecretServer keeps a client's secret set the way Pocket-ID does — creates append, deletes
// remove — so the push and the retirement that follows it can both be asserted.
type fakeSecretServer struct {
	calls     []string // values asked for by each create, "" for a generated one
	deleted   []string // IDs of deleted secrets
	secrets   []pid.OIDCClientSecretDto
	returns   string   // when non-empty, stored instead of the requested value
	generated []string // values to hand out for generated mints, in order
	err       error    // fails every create
	deleteErr error    // fails every delete
	nextID    int
	api       *pocketid.Client
}

// serve returns a client for the server, started on first use.
func (f *fakeSecretServer) serve(t testing.TB) *pocketid.Client {
	if f.api != nil {
		return f.api
	}
	fail := func(w http.ResponseWriter, err error) {
		writeStatus(w, http.StatusInternalServerError, map[string]string{"code": "internal_error", "error": err.Error()})
	}
	f.api = fakeAPI(t, map[string]http.HandlerFunc{
		"POST /api/admin/oidc/clients/{id}/secrets": func(w http.ResponseWriter, r *http.Request) {
			var body pid.OIDCClientSecretCreateDto
			decodeBody(t, r, &body)
			requested := ""
			if body.Secret != nil {
				requested = *body.Secret
			}
			f.calls = append(f.calls, requested)
			if f.err != nil {
				fail(w, f.err)
				return
			}
			stored := requested
			switch {
			case f.returns != "":
				stored = f.returns
			case requested == "" && len(f.generated) > 0:
				// Generated mints take their value from the queue, so a test can force a prefix collision.
				stored, f.generated = f.generated[0], f.generated[1:]
			case requested == "":
				stored = fmt.Sprintf("generated-secret-%d", f.nextID+1)
			}
			f.nextID++
			created := pid.OIDCClientSecretDto{
				ID:        fmt.Sprintf("created-%d", f.nextID),
				Prefix:    pocketid.SecretPrefix(stored),
				CreatedAt: time.Now(),
				IsActive:  true,
			}
			f.secrets = append(f.secrets, created)
			writeStatus(w, http.StatusCreated, pid.OIDCClientSecretCreatedDto{
				ID: created.ID, Prefix: created.Prefix, CreatedAt: created.CreatedAt, IsActive: true, Secret: stored,
			})
		},
		"DELETE /api/admin/oidc/clients/{id}/secrets/{secretId}": func(w http.ResponseWriter, r *http.Request) {
			if f.deleteErr != nil {
				fail(w, f.deleteErr)
				return
			}
			id := r.PathValue("secretId")
			f.deleted = append(f.deleted, id)
			f.secrets = slices.DeleteFunc(f.secrets, func(s pid.OIDCClientSecretDto) bool { return s.ID == id })
			w.WriteHeader(http.StatusNoContent)
		},
	})
	return f.api
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

// declaredSecretsAtCap fills a client with secrets that all carry the declared value's prefix, the
// shape repeated pushes of one value produce.
func declaredSecretsAtCap() []pid.OIDCClientSecretDto {
	secrets := make([]pid.OIDCClientSecretDto, 0, pocketid.MaxOIDCClientSecrets)
	for i := range pocketid.MaxOIDCClientSecrets {
		secrets = append(secrets, pid.OIDCClientSecretDto{
			ID:        fmt.Sprintf("held-%d", i),
			Prefix:    pocketid.SecretPrefix(declaredSecretValue),
			CreatedAt: time.Now().Add(-time.Duration(i) * time.Hour),
			IsActive:  true,
		})
	}
	return secrets
}

// A declared value can always be pushed again from the referenced Secret, so a full client is not a
// dead end the way it would be for a generated one: the oldest is retired and the push proceeds.
func TestSyncDeclaredClientSecret_PushesThroughAFullClient(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)
	atCap := declaredSecretsAtCap()
	api := &fakeSecretServer{secrets: atCap}

	if err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api.serve(t), atCap); err != nil {
		t.Fatalf("SyncDeclaredClientSecret: %v", err)
	}
	if len(api.calls) != 1 {
		t.Fatalf("expected the push to go through, got %d creates", len(api.calls))
	}
	// The oldest goes to free a slot, then retirement takes the rest.
	if api.deleted[0] != fmt.Sprintf("held-%d", pocketid.MaxOIDCClientSecrets-1) {
		t.Fatalf("expected the oldest secret retired first, got %v", api.deleted)
	}
	if len(api.secrets) != 1 {
		t.Fatalf("expected only the pushed secret to remain, got %+v", api.secrets)
	}
}

// Both halves of the push depend on retiring secrets, so a Pocket-ID that will not delete has to
// stop the reconcile rather than press on: making room and cleaning up afterwards are the only
// things keeping the client under Pocket-ID's limit.
func TestSyncDeclaredClientSecret_StopsWhenRetirementFails(t *testing.T) {
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})

	t.Run("making room", func(t *testing.T) {
		oidcClient := declaredClient("app-creds", "secret")
		r := declaredSecretReconciler(t, oidcClient, src)
		atCap := declaredSecretsAtCap()
		api := &fakeSecretServer{deleteErr: errors.New("pocket-id unavailable"), secrets: atCap}

		if err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api.serve(t), atCap); err == nil {
			t.Fatal("expected the push to stop when no slot could be freed")
		}
		if len(api.calls) != 0 {
			t.Fatalf("expected no create at a full client, got %v", api.calls)
		}
	})

	t.Run("cleaning up", func(t *testing.T) {
		oidcClient := declaredClient("app-creds", "secret")
		r := declaredSecretReconciler(t, oidcClient, src)
		api := &fakeSecretServer{
			deleteErr: errors.New("pocket-id unavailable"),
			secrets:   []pid.OIDCClientSecretDto{secretWithPrefix("superseded", "zzzz", time.Hour)},
		}

		if err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api.serve(t), api.secrets); err == nil {
			t.Fatal("expected the failed retirement to be reported")
		}
	})
}

// Making room at a full client deletes before the replacement exists, so the copy holding the
// declared value is the last thing to go: a create that then failed would otherwise leave the
// client unable to authenticate until a later reconcile pushed it back.
func TestSyncDeclaredClientSecret_FullClientKeepsTheLiveCopy(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)

	// The declared copy is the oldest, so an oldest-first rule alone would take it first.
	secrets := []pid.OIDCClientSecretDto{
		secretWithPrefix("live", pocketid.SecretPrefix(declaredSecretValue), 90*24*time.Hour),
	}
	for i := range pocketid.MaxOIDCClientSecrets - 1 {
		secrets = append(secrets, secretWithPrefix("other-"+string(rune('a'+i)), "zzzz", time.Duration(i)*time.Hour))
	}
	api := &fakeSecretServer{err: errors.New("pocket-id unavailable"), secrets: secrets}

	if err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api.serve(t), secrets); err == nil {
		t.Fatal("expected the failed create to be reported")
	}
	// The create failed, so whatever was retired to make room is not coming back this reconcile.
	if slices.Contains(api.deleted, "live") {
		t.Fatalf("the declared value's copy must survive a create that fails, retired %v", api.deleted)
	}
}

// Until the source revision is recorded, every reconcile pushes again. Skipping retirement on each
// of those is what fills the client's slots, so the failure is reported only after cleanup has run.
func TestSyncDeclaredClientSecret_RetiresEvenWhenTheVersionWriteFails(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconcilerWithFailingStatus(t, oidcClient, src)
	api := &fakeSecretServer{secrets: []pid.OIDCClientSecretDto{
		secretWithPrefix("superseded", "zzzz", time.Hour),
	}}

	err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api.serve(t), api.secrets)
	if err == nil {
		t.Fatal("expected the failed status write to be reported")
	}
	if len(api.secrets) != 1 {
		t.Fatalf("the copy each retry leaves behind must be retired, held %+v", api.secrets)
	}
}

// The same failure repeated: without cleanup this is what walks a client into Pocket-ID's limit.
func TestSyncDeclaredClientSecret_RepeatedVersionFailuresDoNotAccumulate(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconcilerWithFailingStatus(t, oidcClient, src)
	api := &fakeSecretServer{}

	for i := range 5 {
		// Each reconcile re-reads the resource, so a version the previous attempt failed to
		// persist is not carried into this one.
		oidcClient.Status.ClientSecretSourceVersion = ""

		if err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api.serve(t), api.secrets); err == nil {
			t.Fatalf("reconcile %d: expected the failed status write to be reported", i)
		}
		if len(api.secrets) != 1 {
			t.Fatalf("reconcile %d: expected one secret to be held, got %+v", i, api.secrets)
		}
	}
}

// declaredSecretReconcilerWithFailingStatus rejects every PocketIDOIDCClient status write, standing
// in for a transient API failure at the moment a push is recorded.
func declaredSecretReconcilerWithFailingStatus(t *testing.T, objs ...client.Object) *Reconciler {
	t.Helper()
	r := declaredSecretReconciler(t, objs...)
	failing := interceptor.NewClient(r.Client.(client.WithWatch), interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, c client.Client, _ string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			if _, ok := obj.(*pocketidinternalv1alpha1.PocketIDOIDCClient); ok {
				return fmt.Errorf("simulated status patch failure")
			}
			return c.Status().Patch(ctx, obj, patch, opts...)
		},
	})
	r.Client = failing
	r.APIReader = failing
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
	api := &fakeSecretServer{}

	if err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api.serve(t), nil); err != nil {
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
	api := &fakeSecretServer{}
	ctx := context.Background()

	if err := r.SyncDeclaredClientSecret(ctx, oidcClient, api.serve(t), nil); err != nil {
		t.Fatalf("first sync returned error: %v", err)
	}
	if err := r.SyncDeclaredClientSecret(ctx, oidcClient, api.serve(t), api.secrets); err != nil {
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
	api := &fakeSecretServer{}
	ctx := context.Background()

	if err := r.SyncDeclaredClientSecret(ctx, oidcClient, api.serve(t), nil); err != nil {
		t.Fatalf("first sync returned error: %v", err)
	}

	const rotated = "a-brand-new-secret-value"
	src.Data["secret"] = []byte(rotated)
	if err := r.Update(ctx, src); err != nil {
		t.Fatalf("update source secret: %v", err)
	}

	if err := r.SyncDeclaredClientSecret(ctx, oidcClient, api.serve(t), api.secrets); err != nil {
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
	api := &fakeSecretServer{}

	if err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api.serve(t), nil); err != nil {
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

	if err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, (&fakeSecretServer{}).serve(t), nil); err != nil {
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
	api := &fakeSecretServer{}

	if err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api.serve(t), nil); err != nil {
		t.Fatalf("SyncDeclaredClientSecret returned error: %v", err)
	}
	if len(api.calls) != 0 {
		t.Fatalf("expected no push before the client exists, got %v", api.calls)
	}
}

// A different value coming back means the cluster and Pocket-ID disagree about the credential.
// That must fail loudly, and must not be recorded as a successful push.
func TestSyncDeclaredClientSecret_RejectsGeneratedSecret(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)
	api := &fakeSecretServer{returns: "something-pocket-id-generated"}

	err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api.serve(t), nil)
	if err == nil || !strings.Contains(err.Error(), "generated client secret") {
		t.Fatalf("expected an error reporting the mismatch, got %v", err)
	}
	if oidcClient.Status.ClientSecretSourceVersion != "" {
		t.Fatalf("expected no version recorded on failure, got %q", oidcClient.Status.ClientSecretSourceVersion)
	}
}

func TestSyncDeclaredClientSecret_PropagatesAPIError(t *testing.T) {
	oidcClient := declaredClient("app-creds", "secret")
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)
	api := &fakeSecretServer{err: errors.New("boom")}

	err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api.serve(t), nil)
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
	api := &fakeSecretServer{}

	if err := r.SyncDeclaredClientSecret(context.Background(), oidcClient, api.serve(t), nil); err == nil {
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
		context.Background(), oidcClient, nil, nil, nil, r.GetSecretName(oidcClient), keys, secretData)
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
	oidcClient.Spec.Secret = &pocketidinternalv1alpha1.OIDCClientSecretSpec{StoreClientSecret: new(false)}
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)
	keys := r.GetSecretKeys(oidcClient)
	secretData := map[string][]byte{}

	if _, _, err := r.reconcileClientSecretData(
		context.Background(), oidcClient, nil, nil, nil, r.GetSecretName(oidcClient), keys, secretData); err != nil {
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
		context.Background(), oidcClient, nil, nil, nil, r.GetSecretName(oidcClient), keys, secretData)
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
	r.pendingInitialMint = map[types.NamespacedName]*pid.OIDCClientSecretCreatedDto{
		client.ObjectKeyFromObject(oidcClient): nil,
	}
	keys := r.GetSecretKeys(oidcClient)
	secretData := map[string][]byte{}

	rotatedAt, _, err := r.reconcileClientSecretData(
		context.Background(), oidcClient, nil, nil, nil, r.GetSecretName(oidcClient), keys, secretData)
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
		context.Background(), oidcClient, nil, nil, nil, r.GetSecretName(oidcClient), keys, map[string][]byte{})
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

// The push retires what it replaces without waiting on the credentials Secret, since the declared
// value's durability is the referenced Secret's concern.
func TestSyncDeclaredClientSecret_RetiresTheReplacedSecret(t *testing.T) {
	ctx := context.Background()
	oidcClient := declaredClient("app-creds", "secret")
	oidcClient.Status.ClientID = "client-123"
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)

	previous := pid.OIDCClientSecretDto{
		ID:        "previous",
		Prefix:    "oldp",
		CreatedAt: time.Now().Add(-24 * time.Hour),
		IsActive:  true,
	}
	api := &fakeSecretServer{secrets: []pid.OIDCClientSecretDto{previous}}

	if err := r.SyncDeclaredClientSecret(ctx, oidcClient, api.serve(t), []pid.OIDCClientSecretDto{previous}); err != nil {
		t.Fatalf("SyncDeclaredClientSecret: %v", err)
	}
	if len(api.calls) != 1 || api.calls[0] != declaredSecretValue {
		t.Fatalf("expected the declared value to be pushed once, got %v", api.calls)
	}
	if len(api.deleted) != 1 || api.deleted[0] != "previous" {
		t.Fatalf("expected the replaced secret to be retired, got %v", api.deleted)
	}
}

// An unchanged source pushes nothing, but must still finish a retirement the overlap was holding.
func TestSyncDeclaredClientSecret_FinishesRetirementWithoutPushing(t *testing.T) {
	ctx := context.Background()
	oidcClient := declaredClient("app-creds", "secret")
	oidcClient.Status.ClientID = "client-123"
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)

	current := pid.OIDCClientSecretDto{
		ID:        "current",
		Prefix:    pocketid.SecretPrefix(declaredSecretValue),
		CreatedAt: time.Now().Add(-2 * time.Hour),
		IsActive:  true,
	}
	superseded := pid.OIDCClientSecretDto{ID: "superseded", Prefix: "oldp", CreatedAt: time.Now().Add(-24 * time.Hour), IsActive: true}
	held := []pid.OIDCClientSecretDto{superseded, current}
	api := &fakeSecretServer{secrets: held}

	if err := r.SyncDeclaredClientSecret(ctx, oidcClient, api.serve(t), held); err != nil {
		t.Fatalf("SyncDeclaredClientSecret: %v", err)
	}
	if len(api.calls) != 1 {
		t.Fatalf("expected the first reconcile to push, got %v", api.calls)
	}

	api.calls = nil
	api.deleted = nil
	api.secrets = []pid.OIDCClientSecretDto{superseded, current}
	if err := r.SyncDeclaredClientSecret(ctx, oidcClient, api.serve(t), api.secrets); err != nil {
		t.Fatalf("SyncDeclaredClientSecret second pass: %v", err)
	}
	if len(api.calls) != 0 {
		t.Fatalf("expected no push for an unchanged declared secret, got %v", api.calls)
	}
	if len(api.deleted) != 1 || api.deleted[0] != "superseded" {
		t.Fatalf("expected the held retirement to finish, got %v", api.deleted)
	}
}

// A declared secret deleted out-of-band leaves the client unable to authenticate, so an unchanged
// source is pushed again to restore it.
func TestSyncDeclaredClientSecret_RestoresDeletedSecret(t *testing.T) {
	ctx := context.Background()
	oidcClient := declaredClient("app-creds", "secret")
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)
	api := &fakeSecretServer{}

	if err := r.SyncDeclaredClientSecret(ctx, oidcClient, api.serve(t), nil); err != nil {
		t.Fatalf("first sync returned error: %v", err)
	}

	// Every secret gone from Pocket-ID, source revision unchanged.
	api.secrets = nil
	if err := r.SyncDeclaredClientSecret(ctx, oidcClient, api.serve(t), nil); err != nil {
		t.Fatalf("second sync returned error: %v", err)
	}
	if len(api.calls) != 2 || api.calls[1] != declaredSecretValue {
		t.Fatalf("expected the declared value to be pushed again, got %v", api.calls)
	}
}

// Secrets sharing the declared value's prefix are unresolvable but present. Reading that as a
// deletion would add another secret every reconcile.
func TestSyncDeclaredClientSecret_PrefixCollisionDoesNotRepush(t *testing.T) {
	ctx := context.Background()
	oidcClient := declaredClient("app-creds", "secret")
	src := sourceSecret("app-creds", map[string][]byte{"secret": []byte(declaredSecretValue)})
	r := declaredSecretReconciler(t, oidcClient, src)

	prefix := pocketid.SecretPrefix(declaredSecretValue)
	collides := []pid.OIDCClientSecretDto{
		{ID: "a", Prefix: prefix, CreatedAt: time.Now().Add(-time.Hour), IsActive: true},
		{ID: "b", Prefix: prefix, CreatedAt: time.Now().Add(-time.Hour), IsActive: true},
	}
	api := &fakeSecretServer{secrets: collides}

	if err := r.SyncDeclaredClientSecret(ctx, oidcClient, api.serve(t), collides); err != nil {
		t.Fatalf("first sync returned error: %v", err)
	}
	pushesAfterFirst := len(api.calls)

	if err := r.SyncDeclaredClientSecret(ctx, oidcClient, api.serve(t), api.secrets); err != nil {
		t.Fatalf("second sync returned error: %v", err)
	}
	if len(api.calls) != pushesAfterFirst {
		t.Fatalf("expected no further push while the declared value is present, got %v", api.calls)
	}
}
