package pocketid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
