package user

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid/pocketidtest"
)

const (
	expiresAt  = "2030-01-01T00:00:00Z"
	renewedAt  = "2031-01-01T00:00:00Z"
	keysPath   = "/api/api-keys"
	key1Path   = "/api/api-keys/key-1"
	renew1Path = "/api/api-keys/key-1/renew"
)

// fakeKeys serves the user's API keys from keys, recording each write and failing them with writeStatus if set.
type fakeKeys struct {
	keys        map[string]pocketid.APIKey
	writes      []string
	writeStatus int
}

func newFakeKeys(t *testing.T, writeStatus int, keys ...pocketid.APIKey) (*pocketid.Client, *fakeKeys) {
	f := &fakeKeys{keys: map[string]pocketid.APIKey{}, writeStatus: writeStatus}
	for _, key := range keys {
		f.keys[key.ID] = key
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+keysPath, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data":       slices.Collect(maps.Values(f.keys)),
			"pagination": map[string]int{"totalPages": 1},
		})
	})
	mux.HandleFunc("POST "+keysPath, f.write(http.StatusCreated, func(key pocketid.APIKey, _ string) any {
		key.ID = "key-new"
		f.keys[key.ID] = key
		return pocketid.APIKeyWithToken{APIKey: key, Token: "new-token"}
	}))
	mux.HandleFunc("PUT /api/api-keys/{id}", f.write(http.StatusOK, func(body pocketid.APIKey, id string) any {
		key := f.keys[id]
		key.Name, key.Description, key.Scopes = body.Name, body.Description, body.Scopes
		f.keys[id] = key
		return key
	}))
	mux.HandleFunc("POST /api/api-keys/{id}/renew", f.write(http.StatusOK, func(body pocketid.APIKey, id string) any {
		key := f.keys[id]
		key.ExpiresAt = body.ExpiresAt
		f.keys[id] = key
		return pocketid.APIKeyWithToken{APIKey: key, Token: "renewed-token"}
	}))
	mux.HandleFunc("DELETE /api/api-keys/{id}", f.write(http.StatusNoContent, func(_ pocketid.APIKey, id string) any {
		delete(f.keys, id)
		return nil
	}))

	return pocketidtest.NewClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !serveSession(w, r) {
			mux.ServeHTTP(w, r)
		}
	})), f
}

func (f *fakeKeys) write(status int, apply func(body pocketid.APIKey, id string) any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.writes = append(f.writes, r.Method+" "+r.URL.Path)
		if f.writeStatus != 0 {
			w.WriteHeader(f.writeStatus)
			return
		}
		var body pocketid.APIKey
		_ = json.NewDecoder(r.Body).Decode(&body)
		resp := apply(body, r.PathValue("id"))
		w.WriteHeader(status)
		if resp != nil {
			_ = json.NewEncoder(w).Encode(resp)
		}
	}
}

// serveSession answers the session flow around API key requests.
func serveSession(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/api/users/user-1/one-time-access-token":
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"one-time-token"}`))
	case "/api/one-time-access-token/one-time-token":
		http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "session-value"})
	case "/api/webauthn/logout":
		w.WriteHeader(http.StatusNoContent)
	default:
		return false
	}
	return true
}

func newAPIKeyReconciler(user *pocketidinternalv1alpha1.PocketIDUser, objs ...client.Object) (*Reconciler, client.Client) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(append(objs, user)...).WithStatusSubresource(user).Build()
	r := &Reconciler{Client: fc, APIReader: fc, Scheme: scheme}
	r.EnsureClient(fc)
	return r, fc
}

func TestReconcileAPIKeys(t *testing.T) {
	spec := pocketidinternalv1alpha1.APIKeySpec{Name: "key", ExpiresAt: expiresAt, Description: "desc", Scopes: []string{"account:read"}}
	stored := pocketid.APIKey{ID: "key-1", Name: "key", Description: "desc", ExpiresAt: expiresAt, LastUsedAt: "2026-11-01T00:00:00Z", Scopes: []string{"account:read"}}
	tracked := pocketidinternalv1alpha1.APIKeyStatus{Name: "key", ID: "key-1", ExpiresAt: expiresAt, SecretName: "user-key-key"}
	withStatus := func(s pocketidinternalv1alpha1.APIKeyStatus, edit func(*pocketidinternalv1alpha1.APIKeyStatus)) []pocketidinternalv1alpha1.APIKeyStatus {
		edit(&s)
		return []pocketidinternalv1alpha1.APIKeyStatus{s}
	}

	tests := []struct {
		name        string
		spec        func(*pocketidinternalv1alpha1.APIKeySpec)
		status      []pocketidinternalv1alpha1.APIKeyStatus
		stored      []pocketid.APIKey
		writeStatus int
		wantWrites  []string
		wantStatus  []pocketidinternalv1alpha1.APIKeyStatus
		wantToken   string
		wantErr     bool
	}{
		{
			name:       "creates a key Pocket-ID doesn't have",
			wantWrites: []string{"POST " + keysPath},
			wantStatus: withStatus(tracked, func(s *pocketidinternalv1alpha1.APIKeyStatus) { s.ID = "key-new" }),
			wantToken:  "new-token",
		},
		{
			name:        "records nothing when Pocket-ID rejects the key",
			writeStatus: http.StatusBadRequest,
			wantWrites:  []string{"POST " + keysPath},
			wantErr:     true,
		},
		{
			name:       "recreates a key deleted outside the operator",
			status:     []pocketidinternalv1alpha1.APIKeyStatus{tracked},
			wantWrites: []string{"POST " + keysPath},
			wantStatus: withStatus(tracked, func(s *pocketidinternalv1alpha1.APIKeyStatus) { s.ID = "key-new" }),
			wantToken:  "new-token",
		},
		{
			name:       "leaves a key in sync alone and records its last use",
			status:     []pocketidinternalv1alpha1.APIKeyStatus{tracked},
			stored:     []pocketid.APIKey{stored},
			wantStatus: withStatus(tracked, func(s *pocketidinternalv1alpha1.APIKeyStatus) { s.LastUsedAt = stored.LastUsedAt }),
		},
		{
			name:       "ignores scope order",
			spec:       func(s *pocketidinternalv1alpha1.APIKeySpec) { s.Scopes = []string{"users:read", "account:read"} },
			status:     []pocketidinternalv1alpha1.APIKeyStatus{tracked},
			stored:     []pocketid.APIKey{{ID: "key-1", Name: "key", Description: "desc", ExpiresAt: expiresAt, Scopes: []string{"account:read", "users:read"}}},
			wantStatus: []pocketidinternalv1alpha1.APIKeyStatus{tracked},
		},
		{
			name:       "updates drifted scopes in place",
			spec:       func(s *pocketidinternalv1alpha1.APIKeySpec) { s.Scopes = []string{"account:read", "users:read"} },
			status:     []pocketidinternalv1alpha1.APIKeyStatus{tracked},
			stored:     []pocketid.APIKey{stored},
			wantWrites: []string{"PUT " + key1Path},
			wantStatus: withStatus(tracked, func(s *pocketidinternalv1alpha1.APIKeyStatus) { s.LastUsedAt = stored.LastUsedAt }),
		},
		{
			name:       "updates a drifted description in place",
			spec:       func(s *pocketidinternalv1alpha1.APIKeySpec) { s.Description = "changed" },
			status:     []pocketidinternalv1alpha1.APIKeyStatus{tracked},
			stored:     []pocketid.APIKey{stored},
			wantWrites: []string{"PUT " + key1Path},
			wantStatus: withStatus(tracked, func(s *pocketidinternalv1alpha1.APIKeyStatus) { s.LastUsedAt = stored.LastUsedAt }),
		},
		{
			name:        "reports an update Pocket-ID refuses",
			spec:        func(s *pocketidinternalv1alpha1.APIKeySpec) { s.Scopes = []string{"users:read"} },
			status:      []pocketidinternalv1alpha1.APIKeyStatus{tracked},
			stored:      []pocketid.APIKey{stored},
			writeStatus: http.StatusBadRequest,
			wantWrites:  []string{"PUT " + key1Path},
			wantStatus:  []pocketidinternalv1alpha1.APIKeyStatus{tracked},
			wantErr:     true,
		},
		{
			name:       "renews a key whose explicit expiry changed",
			spec:       func(s *pocketidinternalv1alpha1.APIKeySpec) { s.ExpiresAt = renewedAt },
			status:     []pocketidinternalv1alpha1.APIKeyStatus{tracked},
			stored:     []pocketid.APIKey{stored},
			wantWrites: []string{"POST " + renew1Path},
			wantStatus: withStatus(tracked, func(s *pocketidinternalv1alpha1.APIKeyStatus) {
				s.ExpiresAt, s.LastUsedAt = renewedAt, stored.LastUsedAt
			}),
			wantToken: "renewed-token",
		},
		{
			name:       "keeps the expiry Pocket-ID chose when none is set",
			spec:       func(s *pocketidinternalv1alpha1.APIKeySpec) { s.ExpiresAt = "" },
			status:     []pocketidinternalv1alpha1.APIKeyStatus{tracked},
			stored:     []pocketid.APIKey{stored},
			wantStatus: withStatus(tracked, func(s *pocketidinternalv1alpha1.APIKeyStatus) { s.LastUsedAt = stored.LastUsedAt }),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			keySpec := spec
			keySpec.Scopes = slices.Clone(spec.Scopes)
			if tt.spec != nil {
				tt.spec(&keySpec)
			}
			user := &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{Name: "user", Namespace: "default"},
				Spec:       pocketidinternalv1alpha1.PocketIDUserSpec{APIKeys: []pocketidinternalv1alpha1.APIKeySpec{keySpec}},
				Status:     pocketidinternalv1alpha1.PocketIDUserStatus{UserID: "user-1", APIKeys: tt.status},
			}
			r, fc := newAPIKeyReconciler(user)
			apiClient, keys := newFakeKeys(t, tt.writeStatus, tt.stored...)

			err := r.reconcileAPIKeys(ctx, user, apiClient, "default", "instance")
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !slices.Equal(keys.writes, tt.wantWrites) {
				t.Errorf("writes = %v, want %v", keys.writes, tt.wantWrites)
			}
			if _, checked := r.apiKeysChecked.Load(user.UID); checked == tt.wantErr {
				t.Errorf("keys checked = %v, want %v", checked, !tt.wantErr)
			}
			if !reflect.DeepEqual(user.Status.APIKeys, tt.wantStatus) {
				t.Errorf("status.apiKeys = %+v, want %+v", user.Status.APIKeys, tt.wantStatus)
			}

			secret := &corev1.Secret{}
			err = fc.Get(ctx, types.NamespacedName{Name: "user-key-key", Namespace: "default"}, secret)
			if tt.wantToken == "" {
				if !errors.IsNotFound(err) {
					t.Errorf("expected no token secret to be written, got err=%v", err)
				}
				return
			}
			if got := string(secret.Data[APIKeySecretKey]); err != nil || got != tt.wantToken {
				t.Errorf("token secret = %q (err=%v), want %q", got, err, tt.wantToken)
			}
		})
	}
}

func TestReconcileAPIKeys_RevokesKeyWhoseTokenWasNotSaved(t *testing.T) {
	stored := pocketid.APIKey{ID: "key-1", Name: "key", ExpiresAt: expiresAt}
	tests := []struct {
		name       string
		stored     []pocketid.APIKey
		wantWrites []string
	}{
		{name: "created", wantWrites: []string{"POST " + keysPath, "DELETE /api/api-keys/key-new"}},
		{name: "renewed", stored: []pocketid.APIKey{stored}, wantWrites: []string{"POST " + renew1Path, "DELETE " + key1Path}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{Name: "user", Namespace: "default"},
				Spec:       pocketidinternalv1alpha1.PocketIDUserSpec{APIKeys: []pocketidinternalv1alpha1.APIKeySpec{{Name: "key", ExpiresAt: renewedAt}}},
				Status:     pocketidinternalv1alpha1.PocketIDUserStatus{UserID: "user-1", APIKeys: []pocketidinternalv1alpha1.APIKeyStatus{{Name: "key", ID: "key-1"}}},
			}
			r, fc := newAPIKeyReconciler(user)
			r.Client = interceptor.NewClient(fc.(client.WithWatch), interceptor.Funcs{
				Apply: func(context.Context, client.WithWatch, runtime.ApplyConfiguration, ...client.ApplyOption) error {
					return stderrors.New("apply refused")
				},
			})
			apiClient, keys := newFakeKeys(t, 0, tt.stored...)

			if err := r.reconcileAPIKeys(t.Context(), user, apiClient, "default", "instance"); err == nil {
				t.Fatal("expected an error")
			}
			if !slices.Equal(keys.writes, tt.wantWrites) {
				t.Errorf("writes = %v, want %v", keys.writes, tt.wantWrites)
			}
			if len(keys.keys) != 0 {
				t.Errorf("keys left in Pocket-ID = %v, want none", keys.keys)
			}
		})
	}
}

func TestReconcileAPIKeys_SkipsSessionOnceConverged(t *testing.T) {
	spec := []pocketidinternalv1alpha1.APIKeySpec{{Name: "key", Scopes: []string{"account:read"}}}
	tracked := []pocketidinternalv1alpha1.APIKeyStatus{{Name: "key", ID: "key-1"}}
	ready := func(status metav1.ConditionStatus, generation int64) []metav1.Condition {
		return []metav1.Condition{{Type: "Ready", Status: status, ObservedGeneration: generation}}
	}

	tests := []struct {
		name        string
		spec        []pocketidinternalv1alpha1.APIKeySpec
		status      []pocketidinternalv1alpha1.APIKeyStatus
		conditions  []metav1.Condition
		unchecked   bool
		wantSession bool
	}{
		{name: "without keys", conditions: ready(metav1.ConditionFalse, 1), unchecked: true},
		{name: "when the current spec was reconciled", spec: spec, status: tracked, conditions: ready(metav1.ConditionTrue, 2)},
		{name: "not when this process hasn't checked the keys yet", spec: spec, status: tracked, conditions: ready(metav1.ConditionTrue, 2), unchecked: true, wantSession: true},
		{name: "not when the spec changed since", spec: spec, status: tracked, conditions: ready(metav1.ConditionTrue, 1), wantSession: true},
		{name: "not when the last reconcile failed", spec: spec, status: tracked, conditions: ready(metav1.ConditionFalse, 2), wantSession: true},
		{name: "not when a key was never created", spec: spec, conditions: ready(metav1.ConditionTrue, 2), wantSession: true},
		{name: "not when every key was removed from the spec", status: tracked, conditions: ready(metav1.ConditionTrue, 2), wantSession: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{Name: "user", Namespace: "default", Generation: 2},
				Spec:       pocketidinternalv1alpha1.PocketIDUserSpec{APIKeys: tt.spec},
				Status:     pocketidinternalv1alpha1.PocketIDUserStatus{UserID: "user-1", APIKeys: tt.status, Conditions: tt.conditions},
			}
			r, _ := newAPIKeyReconciler(user)
			if !tt.unchecked {
				r.apiKeysChecked.Store(user.UID, struct{}{})
			}
			var gotSession bool
			apiClient := pocketidtest.NewClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				gotSession = true
				w.WriteHeader(http.StatusTooManyRequests)
			}))

			_ = r.reconcileAPIKeys(t.Context(), user, apiClient, "default", "instance")
			if gotSession != tt.wantSession {
				t.Errorf("session started = %v, want %v", gotSession, tt.wantSession)
			}
		})
	}
}

func TestReconcileAPIKeys_RemovedKey(t *testing.T) {
	tests := []struct {
		name        string
		status      pocketidinternalv1alpha1.APIKeyStatus
		labels      map[string]string
		writeStatus int
		wantWrites  []string
		wantKept    bool
		wantErr     bool
	}{
		{
			name:       "forgets the key once revoked",
			status:     pocketidinternalv1alpha1.APIKeyStatus{Name: "removed", ID: "key-1", SecretName: "removed-key"},
			labels:     map[string]string{common.ManagedByLabelKey: common.ManagedByLabelValue},
			wantWrites: []string{"DELETE " + key1Path},
		},
		{
			name:        "keeps the key for a retry when revoking fails",
			status:      pocketidinternalv1alpha1.APIKeyStatus{Name: "removed", ID: "key-1", SecretName: "removed-key"},
			labels:      map[string]string{common.ManagedByLabelKey: common.ManagedByLabelValue},
			writeStatus: http.StatusBadRequest,
			wantWrites:  []string{"DELETE " + key1Path},
			wantKept:    true,
			wantErr:     true,
		},
		// A key recorded without an ID, as v2 secretRef keys were, was never created by the operator and has nothing to revoke.
		{
			name:   "forgets a key without an ID and keeps its unmanaged secret",
			status: pocketidinternalv1alpha1.APIKeyStatus{Name: "legacy", SecretName: "removed-key"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			user := &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{Name: "user", Namespace: "default"},
				Status: pocketidinternalv1alpha1.PocketIDUserStatus{
					UserID:  "user-1",
					APIKeys: []pocketidinternalv1alpha1.APIKeyStatus{tt.status},
				},
			}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "removed-key", Namespace: "default", Labels: tt.labels}}
			r, fc := newAPIKeyReconciler(user, secret)
			apiClient, keys := newFakeKeys(t, tt.writeStatus, pocketid.APIKey{ID: "key-1", Name: "removed"})

			err := r.reconcileAPIKeys(ctx, user, apiClient, "default", "instance")
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !slices.Equal(keys.writes, tt.wantWrites) {
				t.Errorf("writes = %v, want %v", keys.writes, tt.wantWrites)
			}
			if got := len(user.Status.APIKeys) == 1; got != tt.wantKept {
				t.Errorf("status.apiKeys = %v, want kept=%v", user.Status.APIKeys, tt.wantKept)
			}
			err = fc.Get(ctx, types.NamespacedName{Name: "removed-key", Namespace: "default"}, &corev1.Secret{})
			wantSecret := tt.wantKept || tt.labels == nil
			if wantSecret != (err == nil) || (!wantSecret && !errors.IsNotFound(err)) {
				t.Errorf("secret kept = %v (err=%v), want %v", err == nil, err, wantSecret)
			}
		})
	}
}
