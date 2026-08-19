package pocketid

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const allowedUserGroupsPath = "/api/oidc/clients/test-id/allowed-user-groups"

// oidcClientResponse is the JSON shape returned by pocket-id for OIDC client endpoints.
type oidcClientResponse struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	CallbackURLs       []string `json:"callbackURLs"`
	LogoutCallbackURLs []string `json:"logoutCallbackURLs"`
	HasLogo            bool     `json:"hasLogo"`
	HasDarkLogo        bool     `json:"hasDarkLogo"`
	IsPublic           bool     `json:"isPublic"`
	IsGroupRestricted  bool     `json:"isGroupRestricted"`
	PkceEnabled        bool     `json:"pkceEnabled"`
	ClientType         string   `json:"clientType"`
	AllowedUserGroups  []any    `json:"allowedUserGroups"`

	AccessTokenDurationMinutes  int64 `json:"accessTokenDurationMinutes"`
	RefreshTokenDurationMinutes int64 `json:"refreshTokenDurationMinutes"`
}

// Pocket-ID always returns a concrete token lifetime, so the read mapping has to
// pick it up for ToInput to compare it against the spec.
func TestGetOIDCClient_ReadsTokenDurations(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/oidc/clients/test-id" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(oidcClientResponse{
			ID:                          "test-id",
			Name:                        "test-client",
			AllowedUserGroups:           []any{},
			AccessTokenDurationMinutes:  15,
			RefreshTokenDurationMinutes: 1440,
		})
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	got, err := client.GetOIDCClient(context.Background(), "test-id")
	if err != nil {
		t.Fatalf("GetOIDCClient: %v", err)
	}
	if got.AccessTokenDurationMinutes != 15 {
		t.Errorf("AccessTokenDurationMinutes: got %d, want 15", got.AccessTokenDurationMinutes)
	}
	if got.RefreshTokenDurationMinutes != 1440 {
		t.Errorf("RefreshTokenDurationMinutes: got %d, want 1440", got.RefreshTokenDurationMinutes)
	}
}

// clientType decides which fields the operator may push, so both read paths used for
// adoption have to carry it through.
func TestOIDCClientReads_CarryClientType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		cimd := oidcClientResponse{
			ID:                "https://apps.example.com/meta.json",
			Name:              "metadata-app",
			ClientType:        ClientTypeCIMD,
			AllowedUserGroups: []any{},
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/oidc/clients/test-id":
			_ = json.NewEncoder(w).Encode(cimd)
		case "/api/oidc/clients":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []oidcClientResponse{cimd}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	got, err := client.GetOIDCClient(context.Background(), "test-id")
	if err != nil {
		t.Fatalf("GetOIDCClient: %v", err)
	}
	if !got.IsCIMD() {
		t.Errorf("GetOIDCClient clientType: got %q, want %q", got.ClientType, ClientTypeCIMD)
	}

	listed, err := client.ListOIDCClients(context.Background(), "")
	if err != nil {
		t.Fatalf("ListOIDCClients: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("expected 1 listed client, got %d", len(listed))
	}
	if !listed[0].IsCIMD() {
		t.Errorf("ListOIDCClients clientType: got %q, want %q", listed[0].ClientType, ClientTypeCIMD)
	}
}

// A CIMD client ID is a full https URL. Raw, its slashes become extra path segments and
// gin never matches the route, so Pocket-ID takes it base64url-encoded behind a "~" and
// decodes it in middleware. Every client-ID path param has to go through that encoding.
func TestClientIDPathParam_EncodesMetadataDocumentURLs(t *testing.T) {
	const metadataURL = "https://apps.example.com/myapp/client-metadata.json"
	want := "~" + base64.RawURLEncoding.EncodeToString([]byte(metadataURL))

	if got := clientIDPathParam(metadataURL); got != want {
		t.Errorf("clientIDPathParam(%q) = %q, want %q", metadataURL, got, want)
	}
	if got := clientIDPathParam("grafana"); got != "grafana" {
		t.Errorf("an ordinary client ID must pass through untouched, got %q", got)
	}
}

// LooksLikeCIMDID has to agree with the CRD's CEL rules and upstream's
// fosite.LooksLikeCIMDURL, both of which require the https scheme. A looser test (any
// "://") would route a mistyped "http://" client ID down the adopt-only path, where it
// waits forever for a client Pocket-ID will never materialize, while admission had already
// waved through the metadata-owned fields the CEL rules exist to reject.
func TestLooksLikeCIMDID_RequiresHTTPSScheme(t *testing.T) {
	for id, want := range map[string]bool{
		"https://apps.example.com/myapp/client-metadata.json": true,
		"http://apps.example.com/myapp/client-metadata.json":  false,
		"ftp://apps.example.com/meta.json":                    false,
		"grafana":                                             false,
		"my-client.id_2":                                      false,
	} {
		if got := LooksLikeCIMDID(id); got != want {
			t.Errorf("LooksLikeCIMDID(%q) = %v, want %v", id, got, want)
		}
	}
}

// Exercises the encoding through the real request path: the stub only answers the encoded
// route, so a regression in any client-ID path param shows up as a 404 here.
func TestOIDCClientOperations_UseEncodedPathForMetadataDocumentIDs(t *testing.T) {
	const metadataURL = "https://apps.example.com/myapp/client-metadata.json"
	encoded := "~" + base64.RawURLEncoding.EncodeToString([]byte(metadataURL))

	seen := map[string]bool{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")

		// API access lives on its own route prefix, so it needs encoding independently of
		// the /api/oidc/clients ones.
		if path == "/api/api-access/"+encoded+"/apis" {
			seen[r.Method+" api-access"] = true
			_ = json.NewEncoder(w).Encode([]any{})
			return
		}
		if path == "/api/apis/api-1/clients/"+encoded {
			seen[r.Method+" api-clients"] = true
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"userDelegatedAccess":        true,
				"userDelegatedPermissionIds": []string{"perm-1"},
			})
			return
		}

		prefix := "/api/oidc/clients/" + encoded
		if !strings.HasPrefix(path, prefix) {
			http.NotFound(w, r)
			return
		}
		suffix := strings.TrimPrefix(path, prefix)
		seen[r.Method+" "+suffix] = true
		switch {
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case suffix == "/secrets" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "secret-1", "prefix": "a-de", "secret": "a-declared-secret-value", "isActive": true,
			})
		case suffix == "/secrets":
			_ = json.NewEncoder(w).Encode([]any{map[string]any{"id": "secret-1", "isActive": true}})
		case suffix == "/scim-service-provider":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "scim-1", "endpoint": "https://scim.example.com"})
		default:
			_ = json.NewEncoder(w).Encode(oidcClientResponse{
				ID: metadataURL, Name: "My App", ClientType: ClientTypeCIMD, AllowedUserGroups: []any{},
			})
		}
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx := context.Background()

	if _, err := client.GetOIDCClient(ctx, metadataURL); err != nil {
		t.Errorf("GetOIDCClient: %v", err)
	}
	if err := client.RefreshOIDCClientMetadata(ctx, metadataURL); err != nil {
		t.Errorf("RefreshOIDCClientMetadata: %v", err)
	}
	if _, err := client.UpdateOIDCClient(ctx, metadataURL, OIDCClientInput{Name: "My App"}); err != nil {
		t.Errorf("UpdateOIDCClient: %v", err)
	}
	if err := client.UpdateOIDCClientAllowedGroups(ctx, metadataURL, []string{"g1"}); err != nil {
		t.Errorf("UpdateOIDCClientAllowedGroups: %v", err)
	}
	// ReconcileSCIM calls this on the first reconcile of every client, SCIM spec or not,
	// so it is on the adoption path for every CIMD client.
	if _, err := client.GetOIDCClientSCIMServiceProvider(ctx, metadataURL); err != nil {
		t.Errorf("GetOIDCClientSCIMServiceProvider: %v", err)
	}
	if _, _, err := client.CreateOIDCClientSecret(ctx, metadataURL, "a-declared-secret-value"); err != nil {
		t.Errorf("CreateOIDCClientSecret: %v", err)
	}
	if err := client.DeleteOIDCClientSecret(ctx, metadataURL, "secret-1"); err != nil {
		t.Errorf("DeleteOIDCClientSecret: %v", err)
	}
	// Reachable for CIMD: admission allows apiAccess.delegatedPermissions on one.
	if _, err := client.ListAPIClientGrants(ctx, metadataURL); err != nil {
		t.Errorf("ListAPIClientGrants: %v", err)
	}
	if _, err := client.SetAPIClientGrant(ctx, "api-1", metadataURL, APIClientGrant{
		UserDelegatedAccess:        true,
		UserDelegatedPermissionIDs: []string{"perm-1"},
	}); err != nil {
		t.Errorf("SetAPIClientGrant: %v", err)
	}
	if err := client.RemoveAPIClientGrant(ctx, "api-1", metadataURL); err != nil {
		t.Errorf("RemoveAPIClientGrant: %v", err)
	}
	if err := client.DeleteOIDCClient(ctx, metadataURL); err != nil {
		t.Errorf("DeleteOIDCClient: %v", err)
	}

	for _, want := range []string{
		"GET ", "POST /refresh", "PUT ", "PUT /allowed-user-groups", "DELETE ",
		"GET /scim-service-provider", "POST /secrets", "DELETE /secrets/secret-1",
		"GET api-access", "PUT api-clients", "DELETE api-clients",
	} {
		if !seen[want] {
			t.Errorf("no request reached the encoded route for %q (seen: %v)", want, seen)
		}
	}
}

func TestRefreshOIDCClientMetadata_PostsToRefreshEndpoint(t *testing.T) {
	var calls int

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/oidc/clients/test-id/refresh" {
			http.NotFound(w, r)
			return
		}
		calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(oidcClientResponse{
			ID:                "test-id",
			Name:              "metadata-app",
			ClientType:        ClientTypeCIMD,
			AllowedUserGroups: []any{},
		})
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := client.RefreshOIDCClientMetadata(context.Background(), "test-id"); err != nil {
		t.Fatalf("RefreshOIDCClientMetadata: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 call to the refresh endpoint, got %d", calls)
	}
}

func TestRefreshOIDCClientMetadata_PropagatesError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := client.RefreshOIDCClientMetadata(context.Background(), "test-id"); err == nil {
		t.Fatal("expected an error when the refresh is rejected")
	}
}

func TestUpdateOIDCClient_SendsCallbackURLsAsProvided(t *testing.T) {
	var sentCallbackURLs, sentLogoutCallbackURLs []string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/api/oidc/clients/test-id":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)

			sentCallbackURLs = jsonStringSlice(body, "callbackURLs")
			sentLogoutCallbackURLs = jsonStringSlice(body, "logoutCallbackURLs")

			resp := oidcClientResponse{
				ID:                 "test-id",
				Name:               "test-client",
				CallbackURLs:       sentCallbackURLs,
				LogoutCallbackURLs: sentLogoutCallbackURLs,
				AllowedUserGroups:  []any{},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.UpdateOIDCClient(context.Background(), "test-id", OIDCClientInput{
		Name:               "test-client",
		CallbackURLs:       []string{"https://new.example.com/callback"},
		LogoutCallbackURLs: []string{"https://new.example.com/logout"},
	})
	if err != nil {
		t.Fatalf("UpdateOIDCClient: %v", err)
	}

	if len(sentCallbackURLs) != 1 || sentCallbackURLs[0] != "https://new.example.com/callback" {
		t.Errorf("expected callback URLs [https://new.example.com/callback], got %v", sentCallbackURLs)
	}
	if len(sentLogoutCallbackURLs) != 1 || sentLogoutCallbackURLs[0] != "https://new.example.com/logout" {
		t.Errorf("expected logout callback URLs [https://new.example.com/logout], got %v", sentLogoutCallbackURLs)
	}
}

func TestUpdateOIDCClient_SendsRequiresPushedAuthorizationRequests(t *testing.T) {
	var body map[string]any

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/oidc/clients/test-id" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(oidcClientResponse{ID: "test-id", Name: "test-client", AllowedUserGroups: []any{}})
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.UpdateOIDCClient(context.Background(), "test-id", OIDCClientInput{
		Name:                                "test-client",
		RequiresPushedAuthorizationRequests: true,
	})
	if err != nil {
		t.Fatalf("UpdateOIDCClient: %v", err)
	}

	if got, _ := body["requiresPushedAuthorizationRequests"].(bool); !got {
		t.Errorf("expected requiresPushedAuthorizationRequests true in payload, got %v", body["requiresPushedAuthorizationRequests"])
	}
}

func TestUpdateOIDCClient_SendsFederatedIdentityReplayProtection(t *testing.T) {
	var body map[string]any

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/oidc/clients/test-id" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(oidcClientResponse{ID: "test-id", Name: "test-client", AllowedUserGroups: []any{}})
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.UpdateOIDCClient(context.Background(), "test-id", OIDCClientInput{
		Name: "test-client",
		Credentials: &OIDCClientCredentials{
			FederatedIdentities: []OIDCClientFederatedIdentity{{
				Issuer:           "https://issuer.example.com",
				ReplayProtection: true,
			}},
		},
	})
	if err != nil {
		t.Fatalf("UpdateOIDCClient: %v", err)
	}

	identity := firstFederatedIdentity(t, body)
	if got, _ := identity["replayProtection"].(bool); !got {
		t.Errorf("expected replayProtection true in payload, got %v", identity["replayProtection"])
	}
}

func TestUpdateOIDCClientAllowedGroups_RetriesOn500(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == allowedUserGroupsPath {
			attempts++
			if attempts < 3 {
				// Simulate a DB deadlock 500 on the first two attempts.
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := c.UpdateOIDCClientAllowedGroups(context.Background(), "test-id", []string{"group-1"}); err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts (2 failures + 1 success), got %d", attempts)
	}
}

func TestUpdateOIDCClientAllowedGroups_ReturnsErrAfterAllRetries(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == allowedUserGroupsPath {
			attempts++
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := c.UpdateOIDCClientAllowedGroups(context.Background(), "test-id", []string{"group-1"}); err == nil {
		t.Fatal("expected error after exhausting all retries, got nil")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestUpdateOIDCClientAllowedGroups_NoRetryOnNon500(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == allowedUserGroupsPath {
			attempts++
			// 400 Bad Request — should not be retried.
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := c.UpdateOIDCClientAllowedGroups(context.Background(), "test-id", []string{"group-1"}); err == nil {
		t.Fatal("expected error for 400 response, got nil")
	}
	if attempts != 1 {
		t.Errorf("expected exactly 1 attempt for non-500 error, got %d", attempts)
	}
}

// --- OIDCClient.ToInput() ---

func TestOIDCClientToInput_MapsAllFields(t *testing.T) {
	c := &OIDCClient{
		ID:                                  "should-be-excluded",
		Name:                                "test-client",
		CallbackURLs:                        []string{"https://a.example.com/cb"},
		LogoutCallbackURLs:                  []string{"https://a.example.com/logout"},
		LaunchURL:                           "https://app.example.com",
		HasLogo:                             true,
		HasDarkLogo:                         true,
		IsPublic:                            true,
		IsGroupRestricted:                   true,
		PKCEEnabled:                         true,
		RequiresReauthentication:            true,
		RequiresPushedAuthorizationRequests: true,
		AccessTokenDurationMinutes:          15,
		RefreshTokenDurationMinutes:         1440,
		AllowedUserGroupIDs:                 []string{"group-1"},
	}
	input := c.ToInput()
	if input.Name != "test-client" {
		t.Errorf("Name: got %q, want %q", input.Name, "test-client")
	}
	if len(input.CallbackURLs) != 1 || input.CallbackURLs[0] != "https://a.example.com/cb" {
		t.Errorf("CallbackURLs: got %v", input.CallbackURLs)
	}
	if len(input.LogoutCallbackURLs) != 1 || input.LogoutCallbackURLs[0] != "https://a.example.com/logout" {
		t.Errorf("LogoutCallbackURLs: got %v", input.LogoutCallbackURLs)
	}
	if input.LaunchURL != "https://app.example.com" {
		t.Errorf("LaunchURL: got %q", input.LaunchURL)
	}
	if !input.HasLogo {
		t.Error("HasLogo: expected true")
	}
	if !input.HasDarkLogo {
		t.Error("HasDarkLogo: expected true")
	}
	if !input.IsPublic {
		t.Error("IsPublic: expected true")
	}
	if !input.IsGroupRestricted {
		t.Error("IsGroupRestricted: expected true")
	}
	if !input.PKCEEnabled {
		t.Error("PKCEEnabled: expected true")
	}
	if !input.RequiresReauthentication {
		t.Error("RequiresReauthentication: expected true")
	}
	if !input.RequiresPushedAuthorizationRequests {
		t.Error("RequiresPushedAuthorizationRequests: expected true")
	}
	if input.AccessTokenDurationMinutes != 15 {
		t.Errorf("AccessTokenDurationMinutes: got %d, want 15", input.AccessTokenDurationMinutes)
	}
	if input.RefreshTokenDurationMinutes != 1440 {
		t.Errorf("RefreshTokenDurationMinutes: got %d, want 1440", input.RefreshTokenDurationMinutes)
	}
	// Fields excluded from ToInput: ID, LogoURL, DarkLogoURL, Credentials
	if input.ID != nil {
		t.Error("ID: expected nil")
	}
	if input.LogoURL != "" {
		t.Errorf("LogoURL: expected empty, got %q", input.LogoURL)
	}
	if input.DarkLogoURL != "" {
		t.Errorf("DarkLogoURL: expected empty, got %q", input.DarkLogoURL)
	}
	if input.Credentials != nil {
		t.Error("Credentials: expected nil")
	}
}

// --- User.ToInput() ---

func TestUserToInput_MapsAllFields(t *testing.T) {
	u := &User{
		ID:          "user-id",
		Username:    "alice",
		FirstName:   "Alice",
		LastName:    "Smith",
		Email:       "alice@example.com",
		DisplayName: "Alice Smith",
		IsAdmin:     true,
		Disabled:    true,
		Locale:      "en",
	}
	input := u.ToInput()
	if input.ID != "user-id" {
		t.Errorf("ID: got %q", input.ID)
	}
	if input.Username != "alice" {
		t.Errorf("Username: got %q", input.Username)
	}
	if input.FirstName != "Alice" {
		t.Errorf("FirstName: got %q", input.FirstName)
	}
	if input.LastName != "Smith" {
		t.Errorf("LastName: got %q", input.LastName)
	}
	if input.Email != "alice@example.com" {
		t.Errorf("Email: got %q", input.Email)
	}
	if input.DisplayName != "Alice Smith" {
		t.Errorf("DisplayName: got %q", input.DisplayName)
	}
	if !input.IsAdmin {
		t.Error("IsAdmin: expected true")
	}
	if !input.Disabled {
		t.Error("Disabled: expected true")
	}
	if input.Locale != "en" {
		t.Errorf("Locale: got %q", input.Locale)
	}
}

// --- UserInput.Equal() ---

func TestUserInputEqual_IgnoresID(t *testing.T) {
	base := UserInput{Username: "alice", FirstName: "Alice", Email: "alice@example.com"}

	withID := base
	withID.ID = "18f3c2f6-2c4b-4f26-9d1c-4b7f6e0a1b2c"

	otherID := base
	otherID.ID = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"

	if !base.Equal(withID) {
		t.Error("expected inputs differing only by ID to be equal")
	}
	if !withID.Equal(otherID) {
		t.Error("expected inputs with different IDs but identical fields to be equal")
	}
	if !withID.Equal(withID) {
		t.Error("expected an input to equal itself")
	}
}

func TestUserInputEqual_DetectsFieldChanges(t *testing.T) {
	base := UserInput{
		ID:          "18f3c2f6-2c4b-4f26-9d1c-4b7f6e0a1b2c",
		Username:    "alice",
		FirstName:   "Alice",
		LastName:    "Smith",
		Email:       "alice@example.com",
		DisplayName: "Alice Smith",
		IsAdmin:     true,
		Disabled:    true,
		Locale:      "en",
	}

	mutations := map[string]func(*UserInput){
		"Username":      func(i *UserInput) { i.Username = "bob" },
		"FirstName":     func(i *UserInput) { i.FirstName = "Bob" },
		"LastName":      func(i *UserInput) { i.LastName = "Jones" },
		"Email":         func(i *UserInput) { i.Email = "bob@example.com" },
		"DisplayName":   func(i *UserInput) { i.DisplayName = "Bob Jones" },
		"IsAdmin":       func(i *UserInput) { i.IsAdmin = false },
		"Disabled":      func(i *UserInput) { i.Disabled = false },
		"Locale":        func(i *UserInput) { i.Locale = "de" },
		"EmailVerified": func(i *UserInput) { i.EmailVerified = true },
	}

	for field, mutate := range mutations {
		t.Run(field, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if base.Equal(changed) {
				t.Errorf("expected a change to %s to be detected", field)
			}
		})
	}
}

// --- CreateUser ID propagation ---

func TestCreateUser_SendsDeclarativeID(t *testing.T) {
	const declaredID = "18f3c2f6-2c4b-4f26-9d1c-4b7f6e0a1b2c"

	var sentBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/users" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&sentBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": declaredID, "username": "alice"})
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	user, err := client.CreateUser(context.Background(), UserInput{ID: declaredID, Username: "alice"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if sentBody["id"] != declaredID {
		t.Errorf("expected request body id %q, got %v", declaredID, sentBody["id"])
	}
	if user.ID != declaredID {
		t.Errorf("expected returned user ID %q, got %q", declaredID, user.ID)
	}
}

func TestCreateUser_OmitsEmptyID(t *testing.T) {
	var sentBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/users" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&sentBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "generated-by-pocket-id", "username": "alice"})
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	user, err := client.CreateUser(context.Background(), UserInput{Username: "alice"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Pocket-ID rejects an empty id (binding "omitempty,uuid"), so it must not be sent at all.
	if _, present := sentBody["id"]; present {
		t.Errorf("expected id to be omitted from the request body, got %v", sentBody["id"])
	}
	if user.ID != "generated-by-pocket-id" {
		t.Errorf("expected the autogenerated ID to be returned, got %q", user.ID)
	}
}

func TestUpdateUser_NeverSendsID(t *testing.T) {
	var sentBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/users/uid-alice" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&sentBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "uid-alice", "username": "alice"})
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Pocket-ID takes the user ID from the URL and ignores it in the body on update.
	input := UserInput{ID: "18f3c2f6-2c4b-4f26-9d1c-4b7f6e0a1b2c", Username: "alice"}
	if _, err := client.UpdateUser(context.Background(), "uid-alice", input); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	if _, present := sentBody["id"]; present {
		t.Errorf("expected id to be omitted from the update body, got %v", sentBody["id"])
	}
}

// --- User custom claims ---

// Custom claims come back on the user read paths, and the controller diffs against
// them, so dropping them would make every reconcile push the same claims again.
func TestGetUser_ReadsCustomClaims(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/users/uid-alice" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":       "uid-alice",
			"username": "alice",
			"customClaims": []map[string]string{
				{"key": "department", "value": "engineering"},
			},
		})
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	user, err := client.GetUser(context.Background(), "uid-alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}

	want := []CustomClaim{{Key: "department", Value: "engineering"}}
	if !CustomClaimsEqual(user.CustomClaims, want) {
		t.Errorf("CustomClaims: got %v, want %v", user.CustomClaims, want)
	}
}

func TestUpdateUserCustomClaims_PutsFullSetToUserEndpoint(t *testing.T) {
	var sentBody []map[string]string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/custom-claims/user/uid-alice" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&sentBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sentBody)
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	claims := []CustomClaim{{Key: "department", Value: "engineering"}, {Key: "level", Value: "3"}}
	got, err := client.UpdateUserCustomClaims(context.Background(), "uid-alice", claims)
	if err != nil {
		t.Fatalf("UpdateUserCustomClaims: %v", err)
	}

	if len(sentBody) != 2 || sentBody[0]["key"] != "department" || sentBody[1]["value"] != "3" {
		t.Errorf("request body: got %v", sentBody)
	}
	if !CustomClaimsEqual(got, claims) {
		t.Errorf("returned claims: got %v, want %v", got, claims)
	}
}

// An empty set is how the operator clears claims, so it has to reach the API as an
// empty JSON array rather than null.
func TestUpdateUserCustomClaims_SendsEmptyArrayToClearClaims(t *testing.T) {
	var rawBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/custom-claims/user/uid-alice" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		rawBody = strings.TrimSpace(string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	got, err := client.UpdateUserCustomClaims(context.Background(), "uid-alice", nil)
	if err != nil {
		t.Fatalf("UpdateUserCustomClaims: %v", err)
	}

	if rawBody != "[]" {
		t.Errorf("request body: got %q, want %q", rawBody, "[]")
	}
	if got != nil {
		t.Errorf("returned claims: got %v, want nil", got)
	}
}

// --- UserGroup.ToInput() ---

func TestUserGroupToInput_MapsAllFields(t *testing.T) {
	g := &UserGroup{
		ID:           "group-id",
		Name:         "my-group",
		FriendlyName: "My Group",
		UserIDs:      []string{"u1", "u2"},
		CustomClaims: []CustomClaim{{Key: "k1", Value: "v1"}},
	}
	input := g.ToInput()
	if input.Name != "my-group" {
		t.Errorf("Name: got %q", input.Name)
	}
	if input.FriendlyName != "My Group" {
		t.Errorf("FriendlyName: got %q", input.FriendlyName)
	}
	if len(input.UserIDs) != 2 || input.UserIDs[0] != "u1" || input.UserIDs[1] != "u2" {
		t.Errorf("UserIDs: got %v", input.UserIDs)
	}
	if len(input.CustomClaims) != 1 || input.CustomClaims[0].Key != "k1" || input.CustomClaims[0].Value != "v1" {
		t.Errorf("CustomClaims: got %v", input.CustomClaims)
	}
}

// --- OIDCClientInput.Equal() ---

func TestOIDCClientInputEqual_IdenticalInputsAreEqual(t *testing.T) {
	a := OIDCClientInput{Name: "test", CallbackURLs: []string{"https://a.example.com/cb"}, HasLogo: true}
	b := a
	if !a.Equal(b) {
		t.Error("expected identical inputs to be equal")
	}
}

func TestOIDCClientInputEqual_DifferentNameNotEqual(t *testing.T) {
	a := OIDCClientInput{Name: "a"}
	b := OIDCClientInput{Name: "b"}
	if a.Equal(b) {
		t.Error("expected different names to not be equal")
	}
}

func TestOIDCClientInputEqual_DifferentPushedAuthorizationRequestsNotEqual(t *testing.T) {
	a := OIDCClientInput{Name: "test", RequiresPushedAuthorizationRequests: true}
	b := OIDCClientInput{Name: "test"}
	if a.Equal(b) {
		t.Error("expected different RequiresPushedAuthorizationRequests to not be equal")
	}
}

func TestOIDCClientInputEqual_DifferentTokenDurationsNotEqual(t *testing.T) {
	a := OIDCClientInput{Name: "test", AccessTokenDurationMinutes: 15, RefreshTokenDurationMinutes: 1440}
	if a.Equal(OIDCClientInput{Name: "test", AccessTokenDurationMinutes: 60, RefreshTokenDurationMinutes: 1440}) {
		t.Error("expected different AccessTokenDurationMinutes to not be equal")
	}
	if a.Equal(OIDCClientInput{Name: "test", AccessTokenDurationMinutes: 15, RefreshTokenDurationMinutes: 43200}) {
		t.Error("expected different RefreshTokenDurationMinutes to not be equal")
	}
}

func TestOIDCClientInputEqual_CallbackURLOrderMatters(t *testing.T) {
	// CallbackURLs use orderedEqual — different order is not equal.
	a := OIDCClientInput{CallbackURLs: []string{"https://a.example.com/cb", "https://b.example.com/cb"}}
	b := OIDCClientInput{CallbackURLs: []string{"https://b.example.com/cb", "https://a.example.com/cb"}}
	if a.Equal(b) {
		t.Error("expected different callback URL order to not be equal")
	}
}

func TestOIDCClientInputEqual_LogoutCallbackURLOrderMatters(t *testing.T) {
	a := OIDCClientInput{LogoutCallbackURLs: []string{"https://a.example.com/logout", "https://b.example.com/logout"}}
	b := OIDCClientInput{LogoutCallbackURLs: []string{"https://b.example.com/logout", "https://a.example.com/logout"}}
	if a.Equal(b) {
		t.Error("expected different logout callback URL order to not be equal")
	}
}

func TestOIDCClientInputEqual_SameCallbackURLOrderIsEqual(t *testing.T) {
	a := OIDCClientInput{CallbackURLs: []string{"https://a.example.com/cb", "https://b.example.com/cb"}}
	b := OIDCClientInput{CallbackURLs: []string{"https://a.example.com/cb", "https://b.example.com/cb"}}
	if !a.Equal(b) {
		t.Error("expected same callback URLs in same order to be equal")
	}
}

func TestOIDCClientInputEqual_BothEmptyCallbackURLsEqual(t *testing.T) {
	a := OIDCClientInput{Name: "test"}
	b := OIDCClientInput{Name: "test"}
	if !a.Equal(b) {
		t.Error("expected both-empty callback URLs to be equal")
	}
}

func TestOIDCClientInputEqual_LogoURLIgnoredInComparison(t *testing.T) {
	// LogoURL and DarkLogoURL are write-only; excluded from Equal.
	a := OIDCClientInput{Name: "test", LogoURL: "https://logo.example.com", DarkLogoURL: "https://dark.example.com"}
	b := OIDCClientInput{Name: "test"}
	if !a.Equal(b) {
		t.Error("expected LogoURL/DarkLogoURL to be ignored in Equal")
	}
}

func TestOIDCClientInputEqual_CredentialsIgnoredInComparison(t *testing.T) {
	// Credentials are write-only; excluded from Equal.
	a := OIDCClientInput{
		Name: "test",
		Credentials: &OIDCClientCredentials{
			FederatedIdentities: []OIDCClientFederatedIdentity{{Issuer: "https://issuer.example.com"}},
		},
	}
	b := OIDCClientInput{Name: "test"}
	if !a.Equal(b) {
		t.Error("expected Credentials to be ignored in Equal")
	}
}

// --- SortedEqual() ---

func TestSortedEqual_SameElementsDifferentOrder(t *testing.T) {
	if !SortedEqual([]string{"b", "a"}, []string{"a", "b"}) {
		t.Error("expected different-order slices with same elements to be equal")
	}
}

func TestSortedEqual_BothNil(t *testing.T) {
	if !SortedEqual(nil, nil) {
		t.Error("expected nil == nil")
	}
}

func TestSortedEqual_EmptyEqualsNil(t *testing.T) {
	if !SortedEqual([]string{}, nil) {
		t.Error("expected empty slice == nil")
	}
}

func TestSortedEqual_DifferentElementsNotEqual(t *testing.T) {
	if SortedEqual([]string{"a"}, []string{"b"}) {
		t.Error("expected different elements to not be equal")
	}
}

func TestSortedEqual_DifferentLengthsNotEqual(t *testing.T) {
	if SortedEqual([]string{"a", "b"}, []string{"a"}) {
		t.Error("expected different lengths to not be equal")
	}
}

// --- CustomClaimsEqual() ---

func TestCustomClaimsEqual_SameClaimsDifferentOrder(t *testing.T) {
	a := []CustomClaim{{Key: "b", Value: "2"}, {Key: "a", Value: "1"}}
	b := []CustomClaim{{Key: "a", Value: "1"}, {Key: "b", Value: "2"}}
	if !CustomClaimsEqual(a, b) {
		t.Error("expected claims in different order to be equal")
	}
}

func TestCustomClaimsEqual_BothNil(t *testing.T) {
	if !CustomClaimsEqual(nil, nil) {
		t.Error("expected nil == nil")
	}
}

func TestCustomClaimsEqual_EmptyEqualsNil(t *testing.T) {
	if !CustomClaimsEqual([]CustomClaim{}, nil) {
		t.Error("expected empty == nil")
	}
}

func TestCustomClaimsEqual_DifferentValueNotEqual(t *testing.T) {
	a := []CustomClaim{{Key: "k", Value: "v1"}}
	b := []CustomClaim{{Key: "k", Value: "v2"}}
	if CustomClaimsEqual(a, b) {
		t.Error("expected different values to not be equal")
	}
}

func TestCustomClaimsEqual_DifferentKeyNotEqual(t *testing.T) {
	a := []CustomClaim{{Key: "k1", Value: "v"}}
	b := []CustomClaim{{Key: "k2", Value: "v"}}
	if CustomClaimsEqual(a, b) {
		t.Error("expected different keys to not be equal")
	}
}

func TestCustomClaimsEqual_ExtraKeyNotEqual(t *testing.T) {
	a := []CustomClaim{{Key: "k1", Value: "v"}, {Key: "k2", Value: "v"}}
	b := []CustomClaim{{Key: "k1", Value: "v"}}
	if CustomClaimsEqual(a, b) {
		t.Error("expected extra key to not be equal")
	}
}

// jsonStringSlice extracts a []string from a JSON-decoded map.
// firstFederatedIdentity returns credentials.federatedIdentities[0] from a
// decoded OIDC client write payload.
func firstFederatedIdentity(t *testing.T, body map[string]any) map[string]any {
	t.Helper()

	credentials, ok := body["credentials"].(map[string]any)
	if !ok {
		t.Fatalf("expected credentials object in payload, got %v", body["credentials"])
	}
	identities, ok := credentials["federatedIdentities"].([]any)
	if !ok || len(identities) == 0 {
		t.Fatalf("expected a federated identity in payload, got %v", credentials["federatedIdentities"])
	}
	identity, ok := identities[0].(map[string]any)
	if !ok {
		t.Fatalf("expected federated identity object, got %v", identities[0])
	}
	return identity
}

func jsonStringSlice(m map[string]any, key string) []string {
	raw, ok := m[key]
	if !ok || raw == nil {
		return nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// TLS-terminating instances are reached over HTTPS with a certificate the system
// trust store does not know, so the caller-supplied config has to reach the
// transport that actually performs requests.
func TestWithTLSConfig_UsesSuppliedTrustStore(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"currentVersion":"2.14.0"}`))
	}))
	defer ts.Close()

	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}

	client, err := NewClient(ts.URL, "", WithTLSConfig(tlsConfig))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// httptest's certificate is issued for example.com, so the handshake only
	// succeeds if both RootCAs and ServerName made it through.
	if _, err := client.GetCurrentVersion(context.Background()); err != nil {
		t.Fatalf("GetCurrentVersion over TLS: %v", err)
	}
}

func TestWithTLSConfig_RejectsUntrustedCertificate(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"currentVersion":"2.14.0"}`))
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if _, err := client.GetCurrentVersion(context.Background()); err == nil {
		t.Fatal("expected the default trust store to reject the test certificate")
	}
}

func TestWithTLSConfig_NilIsNoOp(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"currentVersion":"2.14.0"}`))
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "", WithTLSConfig(nil))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.httpClient != nil {
		t.Error("a nil config must leave the default transport in place")
	}
	if _, err := client.GetCurrentVersion(context.Background()); err != nil {
		t.Fatalf("GetCurrentVersion: %v", err)
	}
}
