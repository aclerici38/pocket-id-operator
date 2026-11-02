package user

import (
	"net/http"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid/pocketidtest"
)

func TestReconcileAPIKeys_RemovedKey(t *testing.T) {
	tests := []struct {
		name         string
		deleteStatus int
		wantErr      bool
	}{
		{name: "forgets the key once revoked", deleteStatus: http.StatusNoContent},
		{name: "keeps the key for a retry when revoking fails", deleteStatus: http.StatusBadRequest, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			scheme := runtime.NewScheme()
			_ = pocketidinternalv1alpha1.AddToScheme(scheme)
			_ = corev1.AddToScheme(scheme)

			user := &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{Name: "user", Namespace: "default"},
				Status: pocketidinternalv1alpha1.PocketIDUserStatus{
					UserID:  "user-1",
					APIKeys: []pocketidinternalv1alpha1.APIKeyStatus{{Name: "removed", ID: "key-1", SecretName: "removed-key"}},
				},
			}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				Name:      "removed-key",
				Namespace: "default",
				Labels:    map[string]string{common.ManagedByLabelKey: common.ManagedByLabelValue},
			}}
			fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(user, secret).WithStatusSubresource(user).Build()
			r := &Reconciler{Client: fc, APIReader: fc, Scheme: scheme}
			r.EnsureClient(fc)

			apiClient := pocketidtest.NewClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/users/user-1/one-time-access-token":
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"token":"one-time-token"}`))
				case "/api/one-time-access-token/one-time-token":
					http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "session-value"})
				case "/api/api-keys/key-1":
					w.WriteHeader(tt.deleteStatus)
				case "/api/webauthn/logout":
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected request to %s", r.URL.Path)
				}
			}))

			err := r.reconcileAPIKeys(ctx, user, apiClient, "default", "instance")
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}

			wantKeys := 0
			if tt.wantErr {
				wantKeys = 1
			}
			if len(user.Status.APIKeys) != wantKeys {
				t.Errorf("status.apiKeys = %v, want %d entries", user.Status.APIKeys, wantKeys)
			}
			err = fc.Get(ctx, types.NamespacedName{Name: "removed-key", Namespace: "default"}, &corev1.Secret{})
			if tt.wantErr && err != nil {
				t.Errorf("expected the secret to be kept, got err=%v", err)
			}
			if !tt.wantErr && !errors.IsNotFound(err) {
				t.Errorf("expected the secret to be deleted, got err=%v", err)
			}
		})
	}
}
