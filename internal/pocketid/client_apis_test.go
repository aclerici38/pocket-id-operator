package pocketid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// apiResponse is the JSON shape returned by pocket-id for API endpoints.
type apiResponse struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Resource    string              `json:"resource"`
	CreatedAt   string              `json:"createdAt"`
	Permissions []apiPermissionResp `json:"permissions"`
}

type apiPermissionResp struct {
	ID          string `json:"id"`
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func TestCreateAPI_SendsNameAndResource(t *testing.T) {
	var sent map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/apis" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&sent)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(apiResponse{ID: "api-1", Name: "Orders", Resource: "https://orders.example.com"})
	}))
	defer ts.Close()

	c := mustClient(t, ts.URL)
	api, err := c.CreateAPI(context.Background(), APIInput{Name: "Orders", Resource: "https://orders.example.com"})
	if err != nil {
		t.Fatalf("CreateAPI: %v", err)
	}
	if sent["name"] != "Orders" || sent["resource"] != "https://orders.example.com" {
		t.Fatalf("unexpected payload: %+v", sent)
	}
	if api.ID != "api-1" || api.Resource != "https://orders.example.com" {
		t.Fatalf("unexpected api: %+v", api)
	}
}

func TestUpdateAPI_SendsNameOnly(t *testing.T) {
	var sent map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/apis/api-1" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&sent)
		writeJSON(w, apiResponse{ID: "api-1", Name: "Renamed", Resource: "https://orders.example.com"})
	}))
	defer ts.Close()

	c := mustClient(t, ts.URL)
	if _, err := c.UpdateAPI(context.Background(), "api-1", "Renamed"); err != nil {
		t.Fatalf("UpdateAPI: %v", err)
	}
	if sent["name"] != "Renamed" {
		t.Fatalf("expected name Renamed, got %+v", sent)
	}
	if _, hasResource := sent["resource"]; hasResource {
		t.Fatalf("update must not send resource (immutable), got %+v", sent)
	}
}

func TestGetAPI_ParsesPermissions(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/apis/api-1" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, apiResponse{
			ID: "api-1", Name: "Orders", Resource: "https://orders.example.com",
			Permissions: []apiPermissionResp{{ID: "p1", Key: "read:orders", Name: "Read", Description: "d"}},
		})
	}))
	defer ts.Close()

	c := mustClient(t, ts.URL)
	api, err := c.GetAPI(context.Background(), "api-1")
	if err != nil {
		t.Fatalf("GetAPI: %v", err)
	}
	if len(api.Permissions) != 1 || api.Permissions[0].ID != "p1" || api.Permissions[0].Key != "read:orders" {
		t.Fatalf("unexpected permissions: %+v", api.Permissions)
	}
}

func TestUpdateAPIPermissions_SendsFullList(t *testing.T) {
	var sent struct {
		Permissions []map[string]any `json:"permissions"`
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/apis/api-1/permissions" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&sent)
		writeJSON(w, apiResponse{ID: "api-1", Name: "Orders", Resource: "https://orders.example.com"})
	}))
	defer ts.Close()

	c := mustClient(t, ts.URL)
	_, err := c.UpdateAPIPermissions(context.Background(), "api-1", []APIPermissionInput{
		{Key: "read:orders", Name: "Read"},
		{Key: "write:orders", Name: "Write", Description: "d"},
	})
	if err != nil {
		t.Fatalf("UpdateAPIPermissions: %v", err)
	}
	if len(sent.Permissions) != 2 || sent.Permissions[0]["key"] != "read:orders" {
		t.Fatalf("unexpected permissions payload: %+v", sent.Permissions)
	}
}

func TestAPIClientGrants_ListSetRemove(t *testing.T) {
	var sent map[string]any
	removed := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/api-access/client-1/apis":
			writeJSON(w, []map[string]any{
				{
					"api":                        map[string]any{"id": "api-1"},
					"clientAccess":               true,
					"userDelegatedAccess":        true,
					"clientPermissionIds":        []string{"c1"},
					"userDelegatedPermissionIds": []string{"d1", "d2"},
				},
				// Reachable only through the API's CIMD setting, so it is not the client's grant.
				{
					"api":               map[string]any{"id": "api-2"},
					"cimdGrantedAccess": true,
				},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/api/apis/api-1/clients/client-1":
			_ = json.NewDecoder(r.Body).Decode(&sent)
			writeJSON(w, sent)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/apis/api-1/clients/client-1":
			removed = true
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	c := mustClient(t, ts.URL)
	ctx := context.Background()

	grants, err := c.ListAPIClientGrants(ctx, "client-1")
	if err != nil {
		t.Fatalf("ListAPIClientGrants: %v", err)
	}
	if len(grants) != 1 || grants[0].APIID != "api-1" {
		t.Fatalf("expected only the client's own grant, got %+v", grants)
	}
	if !grants[0].ClientAccess || !grants[0].UserDelegatedAccess ||
		!reflect.DeepEqual(grants[0].ClientPermissionIDs, []string{"c1"}) ||
		!reflect.DeepEqual(grants[0].UserDelegatedPermissionIDs, []string{"d1", "d2"}) {
		t.Fatalf("unexpected grant: %+v", grants[0])
	}

	applied, err := c.SetAPIClientGrant(ctx, "api-1", "client-1", APIClientGrant{
		ClientAccess:        true,
		ClientPermissionIDs: []string{"c2"},
	})
	if err != nil {
		t.Fatalf("SetAPIClientGrant: %v", err)
	}
	if sent["clientAccess"] != true || !reflect.DeepEqual(sent["clientPermissionIds"], []any{"c2"}) {
		t.Fatalf("unexpected update payload: %+v", sent)
	}
	if applied.APIID != "api-1" || !applied.ClientAccess {
		t.Fatalf("unexpected applied grant: %+v", applied)
	}

	if err := c.RemoveAPIClientGrant(ctx, "api-1", "client-1"); err != nil {
		t.Fatalf("RemoveAPIClientGrant: %v", err)
	}
	if !removed {
		t.Fatal("RemoveAPIClientGrant did not call the endpoint")
	}
}

func TestDeleteAPI(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/api/apis/api-1" {
			called = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c := mustClient(t, ts.URL)
	if err := c.DeleteAPI(context.Background(), "api-1"); err != nil {
		t.Fatalf("DeleteAPI: %v", err)
	}
	if !called {
		t.Fatal("DeleteAPI did not call the endpoint")
	}
}

func mustClient(t *testing.T, url string) *Client {
	t.Helper()
	c, err := NewClient(url, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestSetAPICIMDAccess(t *testing.T) {
	var sent map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/apis/api-1/cimd-access" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&sent)
		writeJSON(w, map[string]any{
			"id":               "api-1",
			"allowCimdClients": sent["enabled"],
			"permissions": []map[string]any{
				{"id": "p-read", "key": "read", "allowedForCimdClients": true},
			},
		})
	}))
	defer ts.Close()

	got, err := mustClient(t, ts.URL).SetAPICIMDAccess(context.Background(), "api-1", true, []string{"p-read"})
	if err != nil {
		t.Fatalf("SetAPICIMDAccess: %v", err)
	}
	if sent["enabled"] != true || !reflect.DeepEqual(sent["permissionIds"], []any{"p-read"}) {
		t.Fatalf("unexpected payload: %+v", sent)
	}
	if !got.AllowCIMDClients || !got.Permissions[0].AllowedForCIMDClients {
		t.Fatalf("unexpected API: %+v", got)
	}
}

// An enabled API with no permissions is a valid grant, so the empty list must be sent
// rather than omitted: Pocket-ID requires the field.
func TestSetAPICIMDAccess_SendsEmptyPermissionList(t *testing.T) {
	var raw map[string]json.RawMessage
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&raw)
		writeJSON(w, map[string]any{"id": "api-1", "allowCimdClients": true})
	}))
	defer ts.Close()

	if _, err := mustClient(t, ts.URL).SetAPICIMDAccess(context.Background(), "api-1", true, nil); err != nil {
		t.Fatalf("SetAPICIMDAccess: %v", err)
	}
	if string(raw["permissionIds"]) != "[]" {
		t.Fatalf("permissionIds = %s, want []", raw["permissionIds"])
	}
}
