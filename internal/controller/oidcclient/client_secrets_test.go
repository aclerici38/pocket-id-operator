package oidcclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const storedSecretValue = "stored-secret-value"

func secretWithPrefix(id, prefix string, age time.Duration) pocketid.OIDCClientSecret {
	return pocketid.OIDCClientSecret{
		ID:        id,
		Prefix:    prefix,
		CreatedAt: time.Now().Add(-age),
		IsActive:  true,
	}
}

// expiredSecret marks a secret Pocket-ID no longer accepts. The operator never asks for an expiry,
// so this only happens when one is set out of band.
func expiredSecret(secret pocketid.OIDCClientSecret) pocketid.OIDCClientSecret {
	secret.IsActive = false
	return secret
}

// observedSecretFor returns the steady-state secret set for a client whose stored credential is
// value: present, with nothing to retire.
func observedSecretFor(value string) []pocketid.OIDCClientSecret {
	return []pocketid.OIDCClientSecret{{
		ID:        "existing-" + value,
		Prefix:    pocketid.SecretPrefix(value),
		CreatedAt: time.Now().Add(-24 * time.Hour),
		IsActive:  true,
	}}
}

func TestResolveClientSecret(t *testing.T) {
	prefix := pocketid.SecretPrefix(storedSecretValue)
	if prefix != "stor" {
		t.Fatalf("unexpected prefix %q", prefix)
	}

	tests := []struct {
		name     string
		statusID string
		stored   string
		secrets  []pocketid.OIDCClientSecret
		wantID   string
	}{
		{
			name:    "matches the secret carrying the stored value's prefix",
			stored:  storedSecretValue,
			secrets: []pocketid.OIDCClientSecret{secretWithPrefix("other", "abcd", 0), secretWithPrefix("ours", prefix, 0)},
			wantID:  "ours",
		},
		{
			name:    "adopts the lone prefixless secret left by the upgrade",
			stored:  storedSecretValue,
			secrets: []pocketid.OIDCClientSecret{secretWithPrefix("migrated", "", time.Hour)},
			wantID:  "migrated",
		},
		{
			name:    "adopts the migrated secret even beside one an admin added",
			stored:  storedSecretValue,
			secrets: []pocketid.OIDCClientSecret{secretWithPrefix("migrated", "", time.Hour), secretWithPrefix("admin", "zzzz", 0)},
			wantID:  "migrated",
		},
		{
			name:     "breaks a prefix collision with the recorded ID",
			statusID: "ours",
			stored:   storedSecretValue,
			secrets:  []pocketid.OIDCClientSecret{secretWithPrefix("ours", prefix, 0), secretWithPrefix("collides", prefix, 0)},
			wantID:   "ours",
		},
		{
			name:    "refuses to guess between colliding prefixes",
			stored:  storedSecretValue,
			secrets: []pocketid.OIDCClientSecret{secretWithPrefix("a", prefix, 0), secretWithPrefix("b", prefix, 0)},
			wantID:  "",
		},
		{
			name:    "ignores an expired secret that shares the prefix",
			stored:  storedSecretValue,
			secrets: []pocketid.OIDCClientSecret{expiredSecret(secretWithPrefix("stale", prefix, time.Hour)), secretWithPrefix("ours", prefix, 0)},
			wantID:  "ours",
		},
		{
			name:    "reports nothing when the only match expired",
			stored:  storedSecretValue,
			secrets: []pocketid.OIDCClientSecret{expiredSecret(secretWithPrefix("ours", prefix, time.Hour))},
			wantID:  "",
		},
		{
			name:    "reports nothing when the stored value matches none",
			stored:  storedSecretValue,
			secrets: []pocketid.OIDCClientSecret{secretWithPrefix("other", "abcd", 0)},
			wantID:  "",
		},
		{
			name:    "reports nothing without a stored value",
			secrets: []pocketid.OIDCClientSecret{secretWithPrefix("other", "abcd", 0)},
			wantID:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveClientSecret(tt.statusID, tt.stored, tt.secrets)
			switch {
			case tt.wantID == "" && got != nil:
				t.Fatalf("expected no match, got %q", got.ID)
			case tt.wantID != "" && got == nil:
				t.Fatalf("expected %q, got no match", tt.wantID)
			case tt.wantID != "" && got.ID != tt.wantID:
				t.Fatalf("expected %q, got %q", tt.wantID, got.ID)
			}
		})
	}
}

// clientSecretPresent decides whether a credential needs replacing, so it must tolerate the
// ambiguity resolveClientSecret refuses: a value that cannot be pinned to one secret is still a
// value that works, and replacing it would mint another secret on every reconcile.
func TestClientSecretPresent(t *testing.T) {
	prefix := pocketid.SecretPrefix(storedSecretValue)

	tests := []struct {
		name    string
		secrets []pocketid.OIDCClientSecret
		want    bool
	}{
		{
			name:    "present when a secret carries the prefix",
			secrets: []pocketid.OIDCClientSecret{secretWithPrefix("other", "abcd", 0), secretWithPrefix("ours", prefix, 0)},
			want:    true,
		},
		{
			name:    "present when secrets share the prefix and none can be singled out",
			secrets: []pocketid.OIDCClientSecret{secretWithPrefix("a", prefix, 0), secretWithPrefix("b", prefix, 0)},
			want:    true,
		},
		{
			name:    "present when a prefixless secret could still be it",
			secrets: []pocketid.OIDCClientSecret{secretWithPrefix("migrated", "", time.Hour)},
			want:    true,
		},
		{
			name:    "absent once the matching secret expires",
			secrets: []pocketid.OIDCClientSecret{expiredSecret(secretWithPrefix("ours", prefix, time.Hour))},
			want:    false,
		},
		{
			name:    "absent when nothing matches",
			secrets: []pocketid.OIDCClientSecret{secretWithPrefix("other", "abcd", 0)},
			want:    false,
		},
		{
			name:    "absent when the client holds no secrets",
			secrets: nil,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clientSecretPresent(storedSecretValue, tt.secrets); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

// retentionFakeClient builds the cluster the retention tests reconcile against.
func retentionFakeClient(t *testing.T, objs ...client.Object) (client.WithWatch, *runtime.Scheme) {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("add corev1 scheme: %v", err)
	}
	if err := pocketidinternalv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add pocketid scheme: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).WithStatusSubresource(objs...).Build(), s
}

// retentionReconciler builds a reconciler whose client status the retention step can patch.
func retentionReconciler(t *testing.T, objs ...client.Object) *Reconciler {
	t.Helper()
	fc, s := retentionFakeClient(t, objs...)
	return &Reconciler{Client: fc, APIReader: fc, Scheme: s}
}

func retentionClient(overlap *metav1.Duration) *pocketidinternalv1alpha1.PocketIDOIDCClient {
	return &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "my-client", Namespace: testNamespace},
		Spec:       pocketidinternalv1alpha1.PocketIDOIDCClientSpec{ClientSecretOverlap: overlap},
		Status:     pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "client-123"},
	}
}

func TestReconcileClientSecretRetention_RetiresEverythingElse(t *testing.T) {
	oidcClient := retentionClient(nil)
	r := retentionReconciler(t, oidcClient)
	prefix := pocketid.SecretPrefix(storedSecretValue)
	api := &fakeClientSecretAPI{secrets: []pocketid.OIDCClientSecret{
		secretWithPrefix("old", "aaaa", 30*24*time.Hour),
		secretWithPrefix("older", "bbbb", 60*24*time.Hour),
		secretWithPrefix("ours", prefix, 0),
	}}

	if err := r.reconcileClientSecretRetention(context.Background(), oidcClient, api, api.secrets, nil, storedSecretValue); err != nil {
		t.Fatalf("reconcileClientSecretRetention: %v", err)
	}

	// Oldest first, so a run cut short leaves the newest superseded secret alive longest.
	if len(api.deleted) != 2 || api.deleted[0] != "older" || api.deleted[1] != "old" {
		t.Fatalf("expected older then old to be retired, got %v", api.deleted)
	}
	if oidcClient.Status.ClientSecretID != "ours" {
		t.Fatalf("expected the resolved secret to be recorded, got %q", oidcClient.Status.ClientSecretID)
	}
}

func TestReconcileClientSecretRetention_HoldsSupersededSecretForOverlap(t *testing.T) {
	oidcClient := retentionClient(&metav1.Duration{Duration: time.Hour})
	r := retentionReconciler(t, oidcClient)
	prefix := pocketid.SecretPrefix(storedSecretValue)
	// The replacement is 10 minutes old, so the hour of overlap has not run out.
	api := &fakeClientSecretAPI{secrets: []pocketid.OIDCClientSecret{
		secretWithPrefix("superseded", "aaaa", 30*24*time.Hour),
		secretWithPrefix("ours", prefix, 10*time.Minute),
	}}

	if err := r.reconcileClientSecretRetention(context.Background(), oidcClient, api, api.secrets, nil, storedSecretValue); err != nil {
		t.Fatalf("reconcileClientSecretRetention: %v", err)
	}
	if len(api.deleted) != 0 {
		t.Fatalf("expected the superseded secret to be held for the overlap, retired %v", api.deleted)
	}

	// Once the replacement is older than the overlap, the secret it superseded goes.
	api.secrets[1] = secretWithPrefix("ours", prefix, 90*time.Minute)
	if err := r.reconcileClientSecretRetention(context.Background(), oidcClient, api, api.secrets, nil, storedSecretValue); err != nil {
		t.Fatalf("reconcileClientSecretRetention after overlap: %v", err)
	}
	if len(api.deleted) != 1 || api.deleted[0] != "superseded" {
		t.Fatalf("expected the superseded secret to be retired once the overlap elapsed, got %v", api.deleted)
	}
}

// Measuring from the age of the retired secret instead would make any rotation interval longer
// than the overlap retire immediately.
func TestReconcileClientSecretRetention_OverlapMeasuredFromReplacement(t *testing.T) {
	oidcClient := retentionClient(&metav1.Duration{Duration: time.Hour})
	r := retentionReconciler(t, oidcClient)
	prefix := pocketid.SecretPrefix(storedSecretValue)
	api := &fakeClientSecretAPI{secrets: []pocketid.OIDCClientSecret{
		secretWithPrefix("superseded", "aaaa", 30*24*time.Hour),
		secretWithPrefix("ours", prefix, time.Minute),
	}}

	if err := r.reconcileClientSecretRetention(context.Background(), oidcClient, api, api.secrets, nil, storedSecretValue); err != nil {
		t.Fatalf("reconcileClientSecretRetention: %v", err)
	}
	if len(api.deleted) != 0 {
		t.Fatalf("a 30-day-old superseded secret must still get the full overlap, retired %v", api.deleted)
	}
}

func TestReconcileClientSecretRetention_LeavesSecretsAloneWhenUnidentifiable(t *testing.T) {
	oidcClient := retentionClient(nil)
	r := retentionReconciler(t, oidcClient)
	api := &fakeClientSecretAPI{secrets: []pocketid.OIDCClientSecret{
		secretWithPrefix("a", "aaaa", time.Hour),
		secretWithPrefix("b", "bbbb", time.Hour),
	}}

	if err := r.reconcileClientSecretRetention(context.Background(), oidcClient, api, api.secrets, nil, storedSecretValue); err != nil {
		t.Fatalf("reconcileClientSecretRetention: %v", err)
	}
	if len(api.deleted) != 0 {
		t.Fatalf("expected nothing retired when the stored value matches no secret, got %v", api.deleted)
	}
}

// The adopted client whose secret is managed outside the operator: nothing to protect, so its
// secrets are left alone.
func TestReconcileClientSecretRetention_NoStoredValueRetiresNothing(t *testing.T) {
	oidcClient := retentionClient(nil)
	r := retentionReconciler(t, oidcClient)
	api := &fakeClientSecretAPI{secrets: []pocketid.OIDCClientSecret{secretWithPrefix("external", "aaaa", time.Hour)}}

	if err := r.reconcileClientSecretRetention(context.Background(), oidcClient, api, api.secrets, nil, ""); err != nil {
		t.Fatalf("reconcileClientSecretRetention: %v", err)
	}
	if len(api.deleted) != 0 || len(api.calls) != 0 {
		t.Fatalf("expected no writes without a stored value, deleted %v", api.deleted)
	}
}

// Creating a secret is the one moment the operator knows which one is its own, so a mint is taken
// at its word. Here the prefix points at both and status still names the secret being replaced, so
// matching by prefix would retire the credential just stored.
func TestReconcileClientSecretRetention_TrustsTheMintedSecret(t *testing.T) {
	oidcClient := retentionClient(nil)
	oidcClient.Status.ClientSecretID = "superseded"
	r := retentionReconciler(t, oidcClient)
	prefix := pocketid.SecretPrefix(storedSecretValue)
	observed := []pocketid.OIDCClientSecret{secretWithPrefix("superseded", prefix, time.Hour)}
	minted := secretWithPrefix("replacement", prefix, 0)
	api := &fakeClientSecretAPI{secrets: append(slices.Clone(observed), minted)}

	if err := r.reconcileClientSecretRetention(context.Background(), oidcClient, api, observed, &minted, storedSecretValue); err != nil {
		t.Fatalf("reconcileClientSecretRetention: %v", err)
	}
	if len(api.deleted) != 1 || api.deleted[0] != "superseded" {
		t.Fatalf("expected only the superseded secret to be retired, got %v", api.deleted)
	}
	if oidcClient.Status.ClientSecretID != "replacement" {
		t.Fatalf("expected the mint to be recorded, got %q", oidcClient.Status.ClientSecretID)
	}
}

func TestMakeRoomForClientSecret(t *testing.T) {
	prefix := pocketid.SecretPrefix(storedSecretValue)

	atCap := func() []pocketid.OIDCClientSecret {
		secrets := []pocketid.OIDCClientSecret{secretWithPrefix("ours", prefix, 0)}
		for i := range pocketid.MaxOIDCClientSecrets - 1 {
			secrets = append(secrets, secretWithPrefix("stale-"+string(rune('a'+i)), "aaaa", time.Duration(i+1)*time.Hour))
		}
		return secrets
	}

	t.Run("retires the oldest superseded secret to make room", func(t *testing.T) {
		oidcClient := retentionClient(&metav1.Duration{Duration: time.Hour})
		r := retentionReconciler(t, oidcClient)
		secrets := atCap()
		api := &fakeClientSecretAPI{secrets: secrets}
		current := resolveClientSecret("", storedSecretValue, secrets)

		if err := r.makeRoomForClientSecret(context.Background(), oidcClient, api, current, secrets); err != nil {
			t.Fatalf("makeRoomForClientSecret: %v", err)
		}
		// One is enough to get under the cap, and the overlap does not protect a secret that
		// would otherwise block the replacement outright.
		if len(api.deleted) != 1 {
			t.Fatalf("expected exactly one retirement, got %v", api.deleted)
		}
		if api.deleted[0] == "ours" {
			t.Fatal("the live credential must survive, since the create that follows may fail")
		}
	})

	t.Run("does nothing below the cap", func(t *testing.T) {
		oidcClient := retentionClient(nil)
		r := retentionReconciler(t, oidcClient)
		secrets := []pocketid.OIDCClientSecret{secretWithPrefix("ours", prefix, 0)}
		api := &fakeClientSecretAPI{secrets: secrets}

		if err := r.makeRoomForClientSecret(context.Background(), oidcClient, api, &secrets[0], secrets); err != nil {
			t.Fatalf("makeRoomForClientSecret: %v", err)
		}
		if len(api.deleted) != 0 {
			t.Fatalf("expected no retirement below the cap, got %v", api.deleted)
		}
	})
}

// retentionInstance is the minimum ReconcileSecret needs to build the credentials Secret.
func retentionInstance() *pocketidinternalv1alpha1.PocketIDInstance {
	return &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "test-instance", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			AppURL:        "http://test.example.com",
			EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
		},
	}
}

// credentialsSecret is the Secret a client that has already been reconciled once would have.
func credentialsSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "my-client-oidc-credentials", Namespace: testNamespace},
		Data:       map[string][]byte{"client_id": []byte("client-123"), "client_secret": []byte(storedSecretValue)},
	}
}

// Upgrading to v2.14.0 moves each client's single secret into the new set under an ID the operator
// has never seen. Treating that as a missing credential would rotate every confidential client in
// the cluster the moment the operator rolls out, bypassing every rotation gate.
func TestReconcileSecret_AdoptsMigratedSecretWithoutRotating(t *testing.T) {
	ctx := context.Background()
	oidcClient := retentionClient(nil)
	instance := retentionInstance()
	existing := credentialsSecret()
	r := retentionReconciler(t, oidcClient, instance, existing)

	creates := 0
	ts := clientSecretServer(t, "must-not-be-minted", &creates)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	// The migrated secret is the one Pocket-ID carried over, so it has no prefix to match on.
	observed := []pocketid.OIDCClientSecret{secretWithPrefix("migrated", "", 90*24*time.Hour)}
	if err := r.ReconcileSecret(ctx, oidcClient, instance, apiClient, observed); err != nil {
		t.Fatalf("ReconcileSecret: %v", err)
	}
	if creates != 0 {
		t.Fatalf("expected no secret to be minted on the first reconcile after the upgrade, got %d", creates)
	}

	stored := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(existing), stored); err != nil {
		t.Fatalf("get credentials secret: %v", err)
	}
	if got := string(stored.Data["client_secret"]); got != storedSecretValue {
		t.Fatalf("expected the existing credential to be kept, got %q", got)
	}
	if oidcClient.Status.ClientSecretID != "migrated" {
		t.Fatalf("expected the migrated secret to be adopted, got %q", oidcClient.Status.ClientSecretID)
	}
	if _, ok := stored.Annotations[lastRotatedAtAnnotation]; ok {
		t.Error("adoption must not record a rotation")
	}
}

// A stored value matching none of the client's secrets authenticates nothing, so it is replaced
// even with no rotation scheduled.
func TestReconcileSecret_MintsWhenStoredSecretNoLongerExists(t *testing.T) {
	ctx := context.Background()
	oidcClient := retentionClient(nil)
	instance := retentionInstance()
	r := retentionReconciler(t, oidcClient, instance, credentialsSecret())

	creates := 0
	ts := clientSecretServer(t, "minted-secret", &creates)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	observed := []pocketid.OIDCClientSecret{secretWithPrefix("someone-elses", "zzzz", time.Hour)}
	if err := r.ReconcileSecret(ctx, oidcClient, instance, apiClient, observed); err != nil {
		t.Fatalf("ReconcileSecret: %v", err)
	}
	if creates != 1 {
		t.Fatalf("expected the missing credential to be replaced once, got %d creates", creates)
	}

	stored := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Name: "my-client-oidc-credentials", Namespace: testNamespace}, stored); err != nil {
		t.Fatalf("get credentials secret: %v", err)
	}
	if got := string(stored.Data["client_secret"]); got != "minted-secret" {
		t.Fatalf("expected the replacement to be stored, got %q", got)
	}
}

// The self-heal asks whether the stored value is still present, not which secret it is. Two
// secrets sharing its prefix cannot be told apart, but one of them works — replacing it would mint
// a secret every reconcile, forever, and walk the client into Pocket-ID's cap.
func TestReconcileSecret_KeepsAnAmbiguousButPresentSecret(t *testing.T) {
	ctx := context.Background()
	oidcClient := retentionClient(nil)
	instance := retentionInstance()
	r := retentionReconciler(t, oidcClient, instance, credentialsSecret())

	creates := 0
	ts := clientSecretServer(t, "must-not-be-minted", &creates)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	prefix := pocketid.SecretPrefix(storedSecretValue)
	observed := []pocketid.OIDCClientSecret{secretWithPrefix("a", prefix, time.Hour), secretWithPrefix("b", prefix, 0)}
	if err := r.ReconcileSecret(ctx, oidcClient, instance, apiClient, observed); err != nil {
		t.Fatalf("ReconcileSecret: %v", err)
	}
	if creates != 0 {
		t.Fatalf("expected a present credential to be kept, got %d creates", creates)
	}

	stored := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Name: "my-client-oidc-credentials", Namespace: testNamespace}, stored); err != nil {
		t.Fatalf("get credentials secret: %v", err)
	}
	if got := string(stored.Data["client_secret"]); got != storedSecretValue {
		t.Fatalf("expected the existing credential to be kept, got %q", got)
	}
}

// An expiry set out of band leaves a secret Pocket-ID rejects. It still occupies a slot and still
// carries the stored value's prefix, so nothing but its active flag says the client is broken.
func TestReconcileSecret_MintsWhenTheStoredSecretExpired(t *testing.T) {
	ctx := context.Background()
	oidcClient := retentionClient(nil)
	instance := retentionInstance()
	r := retentionReconciler(t, oidcClient, instance, credentialsSecret())

	creates := 0
	ts := clientSecretServer(t, "minted-secret", &creates)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	observed := []pocketid.OIDCClientSecret{expiredSecret(secretWithPrefix("ours", pocketid.SecretPrefix(storedSecretValue), time.Hour))}
	if err := r.ReconcileSecret(ctx, oidcClient, instance, apiClient, observed); err != nil {
		t.Fatalf("ReconcileSecret: %v", err)
	}
	if creates != 1 {
		t.Fatalf("expected the expired credential to be replaced once, got %d creates", creates)
	}

	stored := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Name: "my-client-oidc-credentials", Namespace: testNamespace}, stored); err != nil {
		t.Fatalf("get credentials secret: %v", err)
	}
	if got := string(stored.Data["client_secret"]); got != "minted-secret" {
		t.Fatalf("expected the replacement to be stored, got %q", got)
	}
}

// collidingSecretServer answers like Pocket-ID for a client that already holds existingID, and
// mints secrets sharing its prefix so the tie-break between them is what decides the outcome.
func collidingSecretServer(t *testing.T, existingID, prefix, minted string, deleted *[]string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	ids := []string{existingID}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPost:
			ids = append(ids, "created-"+minted)
			writeCreatedClientSecret(w, minted)
		case http.MethodDelete:
			id := path.Base(r.URL.Path)
			*deleted = append(*deleted, id)
			ids = slices.DeleteFunc(ids, func(existing string) bool { return existing == id })
			w.WriteHeader(http.StatusNoContent)
		default:
			entries := make([]string, 0, len(ids))
			for _, id := range ids {
				entries = append(entries, fmt.Sprintf(`{"id":%q,"prefix":%q,"isActive":true}`, id, prefix))
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, "[%s]", strings.Join(entries, ","))
		}
	}))
}

// retentionReconcilerWithFailingStatus rejects every PocketIDOIDCClient status write, standing in
// for a transient API failure at the moment a mint is recorded.
func retentionReconcilerWithFailingStatus(t *testing.T, objs ...client.Object) *Reconciler {
	t.Helper()
	fc, scheme := retentionFakeClient(t, objs...)
	failing := interceptor.NewClient(fc, interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, c client.Client, _ string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			if _, ok := obj.(*pocketidinternalv1alpha1.PocketIDOIDCClient); ok {
				return fmt.Errorf("simulated status patch failure")
			}
			return c.Status().Patch(ctx, obj, patch, opts...)
		},
	})
	return &Reconciler{Client: failing, APIReader: failing, Scheme: scheme}
}

// The tie-break is only durable if the status write lands. A mint whose ID could not be recorded is
// abandoned rather than stored: keeping it would leave the next reconcile resolving to the secret
// it replaced and retiring the live credential, which nothing afterwards could detect or undo.
func TestReconcileSecret_AbandonsAMintItCannotRecord(t *testing.T) {
	ctx := context.Background()

	oidcClient := retentionClient(nil)
	oidcClient.Status.ClientSecretID = "superseded"
	oidcClient.Annotations = map[string]string{regenerateClientSecretAnnotation: "true"}
	instance := retentionInstance()
	r := retentionReconcilerWithFailingStatus(t, oidcClient, instance, credentialsSecret())

	var deleted []string
	ts := collidingSecretServer(t, "superseded", pocketid.SecretPrefix(storedSecretValue), "stored-secret-replacement", &deleted)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	observed := []pocketid.OIDCClientSecret{secretWithPrefix("superseded", pocketid.SecretPrefix(storedSecretValue), time.Hour)}
	if err := r.ReconcileSecret(ctx, oidcClient, instance, apiClient, observed); err == nil {
		t.Fatal("expected ReconcileSecret to fail when the client secret ID cannot be recorded")
	}
	if len(deleted) != 0 {
		t.Fatalf("expected nothing to be retired against an unrecorded mint, got %v", deleted)
	}

	stored := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Name: "my-client-oidc-credentials", Namespace: testNamespace}, stored); err != nil {
		t.Fatalf("get credentials secret: %v", err)
	}
	if got := string(stored.Data["client_secret"]); got != storedSecretValue {
		t.Fatalf("expected the working credential to be left in place, got %q", got)
	}
}

// A replacement can share the prefix of the secret it supersedes, and then the prefix alone points
// at both. Recording the new secret's ID before retirement runs is what stops it resolving to the
// older one and deleting the credential that was just stored, which no later reconcile could undo.
func TestReconcileSecret_RotationSurvivesAPrefixCollision(t *testing.T) {
	ctx := context.Background()
	const mintedValue = "stored-secret-replacement" // shares storedSecretValue's prefix

	oidcClient := retentionClient(nil)
	oidcClient.Status.ClientSecretID = "superseded"
	oidcClient.Annotations = map[string]string{regenerateClientSecretAnnotation: "true"}
	instance := retentionInstance()
	r := retentionReconciler(t, oidcClient, instance, credentialsSecret())

	var deleted []string
	ts := collidingSecretServer(t, "superseded", pocketid.SecretPrefix(storedSecretValue), mintedValue, &deleted)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	observed := []pocketid.OIDCClientSecret{secretWithPrefix("superseded", pocketid.SecretPrefix(storedSecretValue), time.Hour)}
	if err := r.ReconcileSecret(ctx, oidcClient, instance, apiClient, observed); err != nil {
		t.Fatalf("ReconcileSecret: %v", err)
	}

	if !slices.Equal(deleted, []string{"superseded"}) {
		t.Fatalf("expected only the superseded secret to be retired, got %v", deleted)
	}
	if want := "created-" + mintedValue; oidcClient.Status.ClientSecretID != want {
		t.Fatalf("expected status to name the replacement %q, got %q", want, oidcClient.Status.ClientSecretID)
	}

	stored := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Name: "my-client-oidc-credentials", Namespace: testNamespace}, stored); err != nil {
		t.Fatalf("get credentials secret: %v", err)
	}
	if got := string(stored.Data["client_secret"]); got != mintedValue {
		t.Fatalf("expected the replacement to be stored, got %q", got)
	}
}

// Deleting every secret leaves the client unable to authenticate. The operator owns its secrets,
// so it mints a replacement rather than leaving it broken.
func TestReconcileSecret_MintsWhenAllSecretsDeleted(t *testing.T) {
	ctx := context.Background()
	oidcClient := retentionClient(nil)
	oidcClient.Status.ClientSecretID = "deleted-out-of-band"
	instance := retentionInstance()
	r := retentionReconciler(t, oidcClient, instance, credentialsSecret())

	creates := 0
	ts := clientSecretServer(t, "minted-secret", &creates)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if err := r.ReconcileSecret(ctx, oidcClient, instance, apiClient, nil); err != nil {
		t.Fatalf("ReconcileSecret: %v", err)
	}
	if creates != 1 {
		t.Fatalf("expected a replacement to be minted for a client with no secrets, got %d creates", creates)
	}

	stored := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Name: "my-client-oidc-credentials", Namespace: testNamespace}, stored); err != nil {
		t.Fatalf("get credentials secret: %v", err)
	}
	if got := string(stored.Data["client_secret"]); got != "minted-secret" {
		t.Fatalf("expected the replacement to be stored, got %q", got)
	}
}

// The one case the operator must not replace, however the Pocket-ID side looks.
func TestReconcileSecret_StoreClientSecretDisabledNeverMintsOverDeletedSecret(t *testing.T) {
	ctx := context.Background()
	oidcClient := retentionClient(nil)
	oidcClient.Spec.Secret = &pocketidinternalv1alpha1.OIDCClientSecretSpec{StoreClientSecret: boolPtr(false)}
	instance := retentionInstance()
	r := retentionReconciler(t, oidcClient, instance, credentialsSecret())

	creates := 0
	ts := clientSecretServer(t, "must-not-be-minted", &creates)
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if err := r.ReconcileSecret(ctx, oidcClient, instance, apiClient, nil); err != nil {
		t.Fatalf("ReconcileSecret: %v", err)
	}
	if creates != 0 {
		t.Fatalf("expected an externally-managed secret to be left alone, got %d creates", creates)
	}

	stored := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Name: "my-client-oidc-credentials", Namespace: testNamespace}, stored); err != nil {
		t.Fatalf("get credentials secret: %v", err)
	}
	if got := string(stored.Data["client_secret"]); got != storedSecretValue {
		t.Fatalf("expected the existing value to be carried forward, got %q", got)
	}
}

// Retirement follows the durable write, so by the time ReconcileSecret returns the previous secret
// is gone and the new one is in the Secret.
func TestReconcileSecret_RotationRetiresThePreviousSecret(t *testing.T) {
	ctx := context.Background()
	oidcClient := retentionClient(nil)
	oidcClient.Annotations = map[string]string{regenerateClientSecretAnnotation: "true"}
	instance := retentionInstance()
	r := retentionReconciler(t, oidcClient, instance, credentialsSecret())

	// The secret whose value is in the credentials Secret, so the rotation has something to
	// supersede.
	previous := secretWithPrefix("previous", pocketid.SecretPrefix(storedSecretValue), 24*time.Hour)
	var deleted []string
	held := []pocketid.OIDCClientSecret{previous}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodPost:
			held = append(held, secretWithPrefix("created-rotated-secret", pocketid.SecretPrefix("rotated-secret"), 0))
			writeCreatedClientSecret(w, "rotated-secret")
		case http.MethodDelete:
			id := path.Base(req.URL.Path)
			deleted = append(deleted, id)
			held = slices.DeleteFunc(held, func(s pocketid.OIDCClientSecret) bool { return s.ID == id })
			w.WriteHeader(http.StatusNoContent)
		default:
			entries := make([]string, 0, len(held))
			for _, secret := range held {
				entries = append(entries, fmt.Sprintf(`{"id":%q,"prefix":%q,"isActive":true}`, secret.ID, secret.Prefix))
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, "[%s]", strings.Join(entries, ","))
		}
	}))
	defer ts.Close()
	apiClient, _ := pocketid.NewClient(ts.URL, "")

	if err := r.ReconcileSecret(ctx, oidcClient, instance, apiClient, []pocketid.OIDCClientSecret{previous}); err != nil {
		t.Fatalf("ReconcileSecret: %v", err)
	}

	stored := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Name: "my-client-oidc-credentials", Namespace: testNamespace}, stored); err != nil {
		t.Fatalf("get credentials secret: %v", err)
	}
	if got := string(stored.Data["client_secret"]); got != "rotated-secret" {
		t.Fatalf("expected the rotated value to be stored, got %q", got)
	}
	if len(deleted) != 1 || deleted[0] != "previous" {
		t.Fatalf("expected the previous secret to be retired, got %v", deleted)
	}
	if oidcClient.Status.ClientSecretID != "created-rotated-secret" {
		t.Fatalf("expected the new secret to be recorded, got %q", oidcClient.Status.ClientSecretID)
	}
}
