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

func TestClientAPIAccess_GetAndUpdate(t *testing.T) {
	var sent map[string][]string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/api-access/client-1":
			writeJSON(w, map[string][]string{
				"clientPermissionIds":        {"c1"},
				"userDelegatedPermissionIds": {"d1", "d2"},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/api/api-access/client-1":
			_ = json.NewDecoder(r.Body).Decode(&sent)
			writeJSON(w, map[string][]string{
				"clientPermissionIds":        sent["clientPermissionIds"],
				"userDelegatedPermissionIds": sent["userDelegatedPermissionIds"],
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	c := mustClient(t, ts.URL)

	got, err := c.GetClientAPIAccess(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("GetClientAPIAccess: %v", err)
	}
	if !reflect.DeepEqual(got.ClientPermissionIDs, []string{"c1"}) ||
		!reflect.DeepEqual(got.UserDelegatedPermissionIDs, []string{"d1", "d2"}) {
		t.Fatalf("unexpected access: %+v", got)
	}

	_, err = c.UpdateClientAPIAccess(context.Background(), "client-1", ClientAPIAccess{
		ClientPermissionIDs:        []string{"c2"},
		UserDelegatedPermissionIDs: []string{"d3"},
	})
	if err != nil {
		t.Fatalf("UpdateClientAPIAccess: %v", err)
	}
	if !reflect.DeepEqual(sent["clientPermissionIds"], []string{"c2"}) ||
		!reflect.DeepEqual(sent["userDelegatedPermissionIds"], []string{"d3"}) {
		t.Fatalf("unexpected update payload: %+v", sent)
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
