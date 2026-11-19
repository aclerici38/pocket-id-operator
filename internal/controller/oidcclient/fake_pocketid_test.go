package oidcclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"

	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid/pocketidtest"
)

// fakeAPI serves routes, keyed by method pattern such as "PATCH /api/admin/oidc/clients/{id}".
// Anything else answers 404, as Pocket-ID does for a missing resource.
func fakeAPI(t testing.TB, routes map[string]http.HandlerFunc) *pocketid.Client {
	t.Helper()
	mux := http.NewServeMux()
	for pattern, handler := range routes {
		mux.HandleFunc(pattern, handler)
	}
	if _, ok := routes["/"]; !ok {
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			writeStatus(w, http.StatusNotFound, map[string]string{"code": "not_found", "error": "not found"})
		})
	}
	return pocketidtest.NewClient(t, mux)
}

func writeJSON(w http.ResponseWriter, v any) {
	writeStatus(w, http.StatusOK, v)
}

func writeStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// encodedID is an OIDC client ID as it appears in a path.
func encodedID(id string) string {
	encoded, _ := pid.OIDCClientID(id).MarshalText()
	return string(encoded)
}

// clientPath is the admin path of an OIDC client.
func clientPath(id string) string {
	return "/api/admin/oidc/clients/" + encodedID(id)
}

// decodeBody decodes a request body into v, failing the test on error.
func decodeBody(t testing.TB, r *http.Request, v any) {
	t.Helper()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		t.Errorf("decode %s %s body: %v", r.Method, r.URL.Path, err)
	}
}

// fakeOIDCClient is a Pocket-ID holding one OIDC client. It records every write in calls,
// applies PATCHes to the stored client and answers with the result, as Pocket-ID does.
type fakeOIDCClient struct {
	t       testing.TB
	client  pid.OIDCClientWithAllowedUserGroupsDto
	calls   []string
	patches []map[string]any
	// fail, when set, answers a request with status and body instead of serving it; a zero
	// status serves it as usual.
	fail func(r *http.Request, body map[string]any) (status int, resp any)
}

func newFakeOIDCClient(t testing.TB, id, name string) *fakeOIDCClient {
	return &fakeOIDCClient{t: t, client: pid.OIDCClientWithAllowedUserGroupsDto{ID: id, Name: name}}
}

// routes serves the client's endpoints, for combining with others in fakeAPI.
func (f *fakeOIDCClient) routes() map[string]http.HandlerFunc {
	path := clientPath(f.client.ID)
	serve := func(handle func(w http.ResponseWriter, r *http.Request, body map[string]any)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			if r.ContentLength != 0 && r.Body != nil {
				decodeBody(f.t, r, &body)
			}
			if f.fail != nil {
				if status, resp := f.fail(r, body); status != 0 {
					writeStatus(w, status, resp)
					return
				}
			}
			handle(w, r, body)
		}
	}
	return map[string]http.HandlerFunc{
		"GET " + path: serve(func(w http.ResponseWriter, _ *http.Request, _ map[string]any) { writeJSON(w, f.client) }),
		"PATCH " + path: serve(func(w http.ResponseWriter, _ *http.Request, body map[string]any) {
			f.calls = append(f.calls, "PATCH")
			f.patches = append(f.patches, body)
			f.merge(body)
			writeJSON(w, f.client)
		}),
		"PUT " + path + "/allowed-user-groups": serve(func(w http.ResponseWriter, _ *http.Request, body map[string]any) {
			ids, _ := body["userGroupIds"].([]any)
			f.calls = append(f.calls, fmt.Sprintf("groups %v", ids))
			f.client.AllowedUserGroups = nil
			for _, id := range ids {
				f.client.AllowedUserGroups = append(f.client.AllowedUserGroups, pid.UserGroupMinimalDto{ID: id.(string)})
			}
			resp := f.client
			resp.AllowedUserGroups = nil
			writeJSON(w, resp)
		}),
		"DELETE " + path + "/logo": serve(func(w http.ResponseWriter, r *http.Request, _ map[string]any) {
			light := r.URL.Query().Get("light") == "true"
			f.calls = append(f.calls, fmt.Sprintf("delete logo light=%t", light))
			if light {
				f.client.HasLogo = false
			} else {
				f.client.HasDarkLogo = false
			}
			w.WriteHeader(http.StatusNoContent)
		}),
	}
}

func (f *fakeOIDCClient) api() *pocketid.Client { return fakeAPI(f.t, f.routes()) }

// merge applies a PATCH body. A logo URL stands for Pocket-ID downloading the logo, and a
// client left unrestricted loses its groups.
func (f *fakeOIDCClient) merge(body map[string]any) {
	var stored map[string]any
	raw, _ := json.Marshal(f.client)
	_ = json.Unmarshal(raw, &stored)
	for key, value := range body {
		switch key {
		case "logoUrl":
			stored["hasLogo"] = true
		case "darkLogoUrl":
			stored["hasDarkLogo"] = true
		case "credentials":
			credentials := stored["credentials"].(map[string]any)
			for k, v := range value.(map[string]any) {
				credentials[k] = v
			}
		default:
			stored[key] = value
		}
	}
	raw, _ = json.Marshal(stored)
	f.client = pid.OIDCClientWithAllowedUserGroupsDto{}
	_ = json.Unmarshal(raw, &f.client)
	if !f.client.IsGroupRestricted {
		f.client.AllowedUserGroups = nil
	}
}

// logoPatches returns the logo URL each logo PATCH carried, keyed "light" or "dark".
func (f *fakeOIDCClient) logoPatches() []string {
	var logos []string
	for _, patch := range f.patches {
		if url, ok := patch["logoUrl"].(string); ok {
			logos = append(logos, "light "+url)
		}
		if url, ok := patch["darkLogoUrl"].(string); ok {
			logos = append(logos, "dark "+url)
		}
	}
	return logos
}

// logoRejected answers a logo PATCH the way Pocket-ID reports a logo it could not fetch.
func logoRejected(rejected ...string) func(*http.Request, map[string]any) (int, any) {
	return func(r *http.Request, body map[string]any) (int, any) {
		for _, key := range []string{"logoUrl", "darkLogoUrl"} {
			if url, ok := body[key].(string); ok && r.Method == http.MethodPatch && slices.Contains(rejected, url) {
				return http.StatusUnprocessableEntity, map[string]string{"code": "logo_download_failed", "error": "Logo could not be downloaded"}
			}
		}
		return 0, nil
	}
}

// createdSecret is secret as Pocket-ID returns it from the create that disclosed value.
func createdSecret(secret pid.OIDCClientSecretDto, value string) *pid.OIDCClientSecretCreatedDto {
	return &pid.OIDCClientSecretCreatedDto{
		ID: secret.ID, Prefix: secret.Prefix, CreatedAt: secret.CreatedAt, ExpiresAt: secret.ExpiresAt, IsActive: secret.IsActive, Secret: value,
	}
}
