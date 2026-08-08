package pocketid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/aclerici38/pocket-id-go-client/v2/models"
)

// Every field on the OIDC client write DTOs is operator-managed, so a field the
// mapping in client.go forgets to populate leaves its key out of the request
// body entirely. These tests send an input with every field set and assert the
// serialized payload covers the generated DTOs, so a field added by a client
// regen fails here instead of silently never being pushed.

func TestCreateOIDCClient_PayloadCoversWriteDTO(t *testing.T) {
	body := captureOIDCClientWrite(t, http.MethodPost, "/api/oidc/clients", func(c *Client, input OIDCClientInput) error {
		_, err := c.CreateOIDCClient(context.Background(), input)
		return err
	})

	assertDTOFieldsSet(t, models.GithubComPocketIDPocketIDBackendInternalDtoOidcClientCreateDto{}, body, "")
	assertFederatedIdentityFieldsSet(t, body)
}

func TestUpdateOIDCClient_PayloadCoversWriteDTO(t *testing.T) {
	body := captureOIDCClientWrite(t, http.MethodPut, "/api/oidc/clients/test-id", func(c *Client, input OIDCClientInput) error {
		_, err := c.UpdateOIDCClient(context.Background(), "test-id", input)
		return err
	})

	assertDTOFieldsSet(t, models.GithubComPocketIDPocketIDBackendInternalDtoOidcClientUpdateDto{}, body, "")
	assertFederatedIdentityFieldsSet(t, body)
}

// captureOIDCClientWrite calls write against a stub server and returns the
// decoded request body it sent.
func captureOIDCClientWrite(t *testing.T, method, path string, write func(*Client, OIDCClientInput) error) map[string]any {
	t.Helper()

	var body map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method || r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		if method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
		}
		_ = json.NewEncoder(w).Encode(oidcClientResponse{ID: "test-id", Name: "test-client", AllowedUserGroups: []any{}})
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	id := "test-id"
	input := OIDCClientInput{
		ID:                                  &id,
		Name:                                "test-client",
		Description:                         "a test client",
		CallbackURLs:                        []string{"https://example.com/callback"},
		LogoutCallbackURLs:                  []string{"https://example.com/logout"},
		LaunchURL:                           "https://example.com",
		LogoURL:                             "https://example.com/logo.png",
		DarkLogoURL:                         "https://example.com/logo-dark.png",
		HasLogo:                             true,
		HasDarkLogo:                         true,
		IsPublic:                            true,
		IsGroupRestricted:                   true,
		PKCEEnabled:                         true,
		RequiresReauthentication:            true,
		RequiresPushedAuthorizationRequests: true,
		SkipConsent:                         true,
		AccessTokenDurationMinutes:          15,
		RefreshTokenDurationMinutes:         1440,
		Credentials: &OIDCClientCredentials{
			FederatedIdentities: []OIDCClientFederatedIdentity{{
				Issuer:           "https://issuer.example.com",
				Subject:          "subject",
				Audience:         "audience",
				JWKS:             "https://issuer.example.com/jwks",
				ReplayProtection: true,
			}},
		},
	}

	if err := write(client, input); err != nil {
		t.Fatalf("write OIDC client: %v", err)
	}
	if body == nil {
		t.Fatal("expected the stub server to receive a request body")
	}
	return body
}

func assertFederatedIdentityFieldsSet(t *testing.T, body map[string]any) {
	t.Helper()

	credentials, ok := body["credentials"].(map[string]any)
	if !ok {
		t.Fatalf("expected credentials object in payload, got %v", body["credentials"])
	}
	assertDTOFieldsSet(t, models.GithubComPocketIDPocketIDBackendInternalDtoOidcClientCredentialsDto{}, credentials, "credentials.")
	assertDTOFieldsSet(t, models.GithubComPocketIDPocketIDBackendInternalDtoOidcClientFederatedIdentityDto{},
		firstFederatedIdentity(t, body), "credentials.federatedIdentities[0].")
}

// assertDTOFieldsSet reports every JSON key of dto's type that the payload
// leaves out or sends as a zero value.
func assertDTOFieldsSet(t *testing.T, dto any, payload map[string]any, prefix string) {
	t.Helper()

	typ := reflect.TypeOf(dto)
	for i := range typ.NumField() {
		key, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		if key == "" || key == "-" {
			continue
		}
		value, present := payload[key]
		if !present {
			t.Errorf("%s%s: missing from payload — map it in client.go", prefix, key)
			continue
		}
		if isZeroJSON(value) {
			t.Errorf("%s%s: sent as zero value %v — map it in client.go", prefix, key, value)
		}
	}
}

func isZeroJSON(value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case bool:
		return !v
	case string:
		return v == ""
	case float64:
		return v == 0
	case []any:
		return len(v) == 0
	case map[string]any:
		return len(v) == 0
	default:
		return false
	}
}
