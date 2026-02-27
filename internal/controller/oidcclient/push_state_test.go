package oidcclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
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

	input := reconciler.OidcClientInput(oidcClient, current)

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

	input := reconciler.OidcClientInput(oidcClient, current)

	if len(input.CallbackURLs) != 1 || input.CallbackURLs[0] != "https://spec.example.com/cb" {
		t.Errorf("expected spec callback URLs to take precedence, got %v", input.CallbackURLs)
	}
	if len(input.LogoutCallbackURLs) != 1 || input.LogoutCallbackURLs[0] != "https://spec.example.com/logout" {
		t.Errorf("expected spec logout callback URLs to take precedence, got %v", input.LogoutCallbackURLs)
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

	ids, err := reconciler.aggregateAllowedUserGroupIDs(ctx, oidcClient)
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

	if err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current); err != nil {
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

	if err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current); err != nil {
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

	if err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current); err != nil {
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

	if err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current); err != nil {
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

	if err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current); err != nil {
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

	if err := r.pushOIDCClientState(ctx, oidcClientCR, apiClient, current); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !groupsUpdateSent {
		t.Error("expected group update when UserGroup reverse-references the OIDC client")
	}
}
