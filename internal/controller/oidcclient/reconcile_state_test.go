package oidcclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
)

// reconcileCalls records what a single Reconcile asked of Pocket-ID.
type reconcileCalls struct {
	mu          sync.Mutex
	grantPushed bool
	clientGETs  int
}

func (c *reconcileCalls) snapshot() (grantPushed bool, clientGETs int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.grantPushed, c.clientGETs
}

// reconcileFixture builds a reconciler whose whole dependency chain — instance, API key,
// referenced API and a fake Pocket-ID — is satisfied, so Reconcile can run end to end.
// The fake client renames itself on the write, so status can only carry the new name if
// the reconcile read the write back.
func reconcileFixture(t *testing.T, oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient) (*Reconciler, *reconcileCalls) {
	t.Helper()

	calls := &reconcileCalls{}
	name := "app-before-write"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.mu.Lock()
		defer calls.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/api/oidc/clients/client-1":
			calls.clientGETs++
			okOIDCClientResponse(w, "client-1", name)
		case req.Method == http.MethodPut && req.URL.Path == "/api/oidc/clients/client-1":
			name = "app-after-write"
			okOIDCClientResponse(w, "client-1", name)
		case req.URL.Path == "/api/oidc/clients/client-1/scim-service-provider":
			http.NotFound(w, req)
		case req.Method == http.MethodGet && req.URL.Path == "/api/api-access/client-1/apis":
			_, _ = w.Write([]byte(`[]`))
		case req.Method == http.MethodPut && req.URL.Path == "/api/apis/api-1/clients/client-1":
			calls.grantPushed = true
			_, _ = w.Write([]byte(`{"clientAccess":false,"userDelegatedAccess":true,"clientPermissionIds":[],"userDelegatedPermissionIds":["p-read"]}`))
		default:
			t.Errorf("unstubbed request: %s %s", req.Method, req.URL.Path)
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(ts.Close)

	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "pid", Namespace: testNamespace},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			External: &pocketidinternalv1alpha1.ExternalInstanceConfig{
				URL: ts.URL,
				APIKeySecretRef: corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "pid-api-key"},
					Key:                  "api-key",
				},
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDInstanceStatus{
			Conditions: []metav1.Condition{{
				Type: "Ready", Status: metav1.ConditionTrue, Reason: "Ready",
				LastTransitionTime: metav1.Now(),
			}},
		},
	}
	apiKeySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "pid-api-key", Namespace: testNamespace},
		Data:       map[string][]byte{"api-key": []byte("token")},
	}

	s := runtime.NewScheme()
	if err := pocketidinternalv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("corev1 AddToScheme: %v", err)
	}

	api := readyAPI([]pocketidinternalv1alpha1.ObservedAPIPermission{{ID: "p-read", Key: "read:orders"}})
	api.Namespace = testNamespace

	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(instance, apiKeySecret, api, oidcClient).
		WithStatusSubresource(instance, api, oidcClient).
		WithIndex(&pocketidinternalv1alpha1.PocketIDUserGroup{}, common.UserGroupAllowedOIDCClientIndexKey,
			func(client.Object) []string { return nil }).
		Build()

	return &Reconciler{
		Client:         c,
		APIReader:      c,
		Scheme:         s,
		BaseReconciler: common.BaseReconciler{Client: c, APIReader: c},
	}, calls
}

// adoptedClient is already created in Pocket-ID and already finalized, so Reconcile goes
// straight to the fetch/push/read-back path.
func adoptedClient(generation int64) *pocketidinternalv1alpha1.PocketIDOIDCClient {
	return &pocketidinternalv1alpha1.PocketIDOIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "app",
			Namespace:  testNamespace,
			Generation: generation,
			Finalizers: []string{oidcClientFinalizer},
		},
		Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
			Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{Enabled: ptr.To(false)},
			APIAccess: []pocketidinternalv1alpha1.OIDCClientAPIAccess{{
				APIRef:               pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders"},
				DelegatedPermissions: []string{"read:orders"},
			}},
		},
		Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{ClientID: "client-1"},
	}
}

// Ready stamps observedGeneration, so anything gating on it — a GitOps sync check, a
// dependent controller, a human reading kubectl get — reads Ready as "this generation is
// live in Pocket-ID". One reconcile must therefore push the generation's state, read the
// write back into status, and only then report Ready.
func TestReconcile_ReadyOnlyAfterStateIsPushedAndObserved(t *testing.T) {
	ctx := context.Background()
	oidcClient := adoptedClient(2)
	r, calls := reconcileFixture(t, oidcClient)

	result, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(oidcClient)})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	grantPushed, clientGETs := calls.snapshot()
	if !grantPushed {
		t.Error("expected the generation's API access to be pushed")
	}
	if clientGETs != 2 {
		t.Errorf("expected the write to be read back in the same pass, got %d client GETs", clientGETs)
	}

	var got pocketidinternalv1alpha1.PocketIDOIDCClient
	if err := r.Get(ctx, client.ObjectKeyFromObject(oidcClient), &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status.Name != "app-after-write" {
		t.Errorf("status should carry the post-write state, got %q", got.Status.Name)
	}
	if !readyForGeneration(&got, 2) {
		t.Errorf("expected Ready=True observing generation 2, got %+v", got.Status.Conditions)
	}

	// A follow-up reconcile is what used to let Ready run ahead of the push. Settling on the
	// resync interval instead keeps every generation's Ready backed by an observed write.
	if result.RequeueAfter < common.ResyncInterval {
		t.Errorf("expected the pass to settle on the resync interval, got %v", result.RequeueAfter)
	}
}

func readyForGeneration(oidcClient *pocketidinternalv1alpha1.PocketIDOIDCClient, generation int64) bool {
	for _, cond := range oidcClient.Status.Conditions {
		if cond.Type == "Ready" {
			return cond.Status == metav1.ConditionTrue && cond.ObservedGeneration == generation
		}
	}
	return false
}
