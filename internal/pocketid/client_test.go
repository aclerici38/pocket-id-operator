package pocketid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	AllowedUserGroups  []any    `json:"allowedUserGroups"`
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
		ID:                       "should-be-excluded",
		Name:                     "test-client",
		CallbackURLs:             []string{"https://a.example.com/cb"},
		LogoutCallbackURLs:       []string{"https://a.example.com/logout"},
		LaunchURL:                "https://app.example.com",
		HasLogo:                  true,
		HasDarkLogo:              true,
		IsPublic:                 true,
		IsGroupRestricted:        true,
		PKCEEnabled:              true,
		RequiresReauthentication: true,
		AllowedUserGroupIDs:      []string{"group-1"},
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
