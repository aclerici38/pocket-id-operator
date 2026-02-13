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

func TestUpdateOIDCClient_SkipsGetWhenBothURLsProvided(t *testing.T) {
	getCalled := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/oidc/clients/test-id":
			getCalled = true
			resp := oidcClientResponse{
				ID:                 "test-id",
				Name:               "test-client",
				CallbackURLs:       []string{"https://old.example.com/callback"},
				LogoutCallbackURLs: []string{"https://old.example.com/logout"},
				AllowedUserGroups:  []any{},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPut && r.URL.Path == "/api/oidc/clients/test-id":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)

			resp := oidcClientResponse{
				ID:                 "test-id",
				Name:               "test-client",
				CallbackURLs:       jsonStringSlice(body, "callbackURLs"),
				LogoutCallbackURLs: jsonStringSlice(body, "logoutCallbackURLs"),
				AllowedUserGroups:  []any{},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Both URLs provided — should NOT issue a GET to fetch existing state
	_, err = client.UpdateOIDCClient(context.Background(), "test-id", OIDCClientInput{
		Name:               "test-client",
		CallbackURLs:       []string{"https://new.example.com/callback"},
		LogoutCallbackURLs: []string{"https://new.example.com/logout"},
	})
	if err != nil {
		t.Fatalf("UpdateOIDCClient: %v", err)
	}

	if getCalled {
		t.Error("GET should not be called when both callback URL lists are provided in spec")
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
