package oidcclient

import (
	"context"
	"net/http"
	"strings"
	"testing"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"

	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

func TestFindExistingOIDCClient(t *testing.T) {
	const cimdID = "https://apps.example.com/meta.json"
	byID := map[string]pid.OIDCClientWithAllowedUserGroupsDto{
		"my-app-id": {ID: "my-app-id", Name: "My Application"},
		// An explicit spec.clientID is the opt-in for CIMD management, so a by-ID lookup adopts.
		cimdID: {ID: cimdID, Name: "metadata-app", ClientType: pocketid.ClientTypeCIMD},
	}
	listed := []pid.OIDCClientWithAllowedGroupsDto{
		{ID: "grafana-dev-id", Name: "grafana-dev"},
		{ID: "grafana-id", Name: "grafana", ClientType: "standard"},
		// A name match is not an opt-in: a document-supplied client_name colliding with a CR
		// name must never pull an unrelated self-registered client under management.
		{ID: cimdID, Name: "metadata-app", ClientType: pocketid.ClientTypeCIMD},
		{ID: "https://apps.example.com/other.json", Name: "grafana", ClientType: pocketid.ClientTypeCIMD},
	}

	routes := map[string]http.HandlerFunc{
		"GET /api/admin/oidc/clients": func(w http.ResponseWriter, r *http.Request) {
			var matches []pid.OIDCClientWithAllowedGroupsDto
			for _, c := range listed {
				if strings.HasPrefix(c.Name, r.URL.Query().Get("search")) {
					matches = append(matches, c)
				}
			}
			writeJSON(w, pid.PaginatedDtoOIDCClientWithAllowedGroupsDto{Data: matches})
		},
	}
	for id, c := range byID {
		routes["GET "+clientPath(id)] = func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, c) }
	}
	apiClient := fakeAPI(t, routes)

	for _, tc := range []struct {
		name, specClientID, search string
		wantID                     string
	}{
		{name: "by ID", specClientID: "my-app-id", search: "ignored", wantID: "my-app-id"},
		{name: "by ID not found", specClientID: "missing", search: "my-app"},
		{name: "by ID adopts a CIMD client", specClientID: cimdID, search: "metadata-app", wantID: cimdID},
		{name: "by name picks the exact match", search: "grafana", wantID: "grafana-id"},
		{name: "by name no match", search: "new-client"},
		{name: "by name skips a CIMD client", search: "metadata-app"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotID, err := (&Reconciler{}).findExistingOIDCClient(context.Background(), apiClient, tc.specClientID, tc.search)
			if err != nil {
				t.Fatalf("findExistingOIDCClient: %v", err)
			}
			if gotID != tc.wantID {
				t.Fatalf("found %q, want %q", gotID, tc.wantID)
			}
		})
	}
}
