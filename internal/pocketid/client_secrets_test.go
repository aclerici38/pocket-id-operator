package pocketid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aclerici38/pocket-id-go-client/v2/models"
)

// SecretPrefix has to agree with Pocket-ID's clientSecretPrefix exactly. The operator matches a
// stored credential against these prefixes to decide what to retire, so a divergence here would
// make it delete the wrong secret rather than fail visibly.
func TestSecretPrefix(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "takes the leading characters", value: "abcdefgh", want: "abcd"},
		{name: "one longer than the prefix", value: "abcde", want: "abcd"},
		{name: "exactly the prefix length is not recorded", value: "abcd", want: ""},
		{name: "shorter than the prefix length", value: "abc", want: ""},
		{name: "empty", value: "", want: ""},
		// Pocket-ID slices bytes too, so a rune-aware "fix" here would silently disagree with it.
		{name: "slices bytes, as Pocket-ID does", value: "√ab", want: "√a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SecretPrefix(tt.value); got != tt.want {
				t.Fatalf("SecretPrefix(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

// Pocket-ID serialises timestamps with time.Time's MarshalJSON, which emits RFC 3339 with a
// fractional second. Failing to parse that would zero every CreatedAt and silently collapse the
// overlap to nothing, so this pins the formats that must round-trip.
func TestParseAPITime(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  time.Time
	}{
		{
			name:  "fractional seconds, as time.Time marshals them",
			value: "2026-08-19T12:34:56.789012345Z",
			want:  time.Date(2026, 8, 19, 12, 34, 56, 789012345, time.UTC),
		},
		{
			name:  "whole seconds",
			value: "2026-08-19T12:34:56Z",
			want:  time.Date(2026, 8, 19, 12, 34, 56, 0, time.UTC),
		},
		{
			name:  "non-UTC offset",
			value: "2026-08-19T12:34:56+02:00",
			want:  time.Date(2026, 8, 19, 10, 34, 56, 0, time.UTC),
		},
		{name: "absent", value: ""},
		{name: "unparseable yields the zero time rather than an error", value: "not-a-time"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAPITime(tt.value)
			if !got.Equal(tt.want) {
				t.Fatalf("parseAPITime(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestOIDCClientSecretsFromDTO(t *testing.T) {
	secrets := oidcClientSecretsFromDTO([]*models.GithubComPocketIDPocketIDBackendInternalDtoOidcClientSecretDto{
		{ID: "current", Prefix: "abcd", CreatedAt: "2026-08-19T12:00:00Z", IsActive: true},
		{ID: "migrated", CreatedAt: "2026-01-01T00:00:00Z", IsActive: true},
		{ID: "expired", Prefix: "efgh", CreatedAt: "2026-02-01T00:00:00Z"},
		nil,
		{Prefix: "ijkl"}, // no ID: nothing could be deleted by it
	})

	if len(secrets) != 3 {
		t.Fatalf("expected the unusable entries to be dropped, got %d: %+v", len(secrets), secrets)
	}
	if secrets[0].ID != "current" || secrets[0].Prefix != "abcd" || !secrets[0].IsActive {
		t.Fatalf("unexpected first secret: %+v", secrets[0])
	}
	if !secrets[0].CreatedAt.Equal(time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("unexpected CreatedAt: %v", secrets[0].CreatedAt)
	}
	// A secret Pocket-ID migrated from the single-secret column has no prefix to match on.
	if secrets[1].ID != "migrated" || secrets[1].Prefix != "" {
		t.Fatalf("unexpected migrated secret: %+v", secrets[1])
	}
	if secrets[2].ID != "expired" || secrets[2].IsActive {
		t.Fatalf("expected the expired secret to stay inactive: %+v", secrets[2])
	}
}

// Every read of a client carries its secrets, which is what lets reconcile work from one GET.
func TestGetOIDCClient_CarriesSecrets(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "client-123",
			"name": "Test",
			"credentials": {"secrets": [
				{"id": "s1", "prefix": "abcd", "createdAt": "2026-08-19T12:00:00Z", "isActive": true}
			]}
		}`))
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	got, err := client.GetOIDCClient(context.Background(), "client-123")
	if err != nil {
		t.Fatalf("GetOIDCClient: %v", err)
	}
	if len(got.Secrets) != 1 || got.Secrets[0].ID != "s1" || got.Secrets[0].Prefix != "abcd" {
		t.Fatalf("expected the client read to carry its secrets, got %+v", got.Secrets)
	}
}

// A client with no credentials block at all must read as "no secrets", not panic.
func TestGetOIDCClient_WithoutCredentials(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id": "client-123", "name": "Test"}`))
	}))
	defer ts.Close()

	client, _ := NewClient(ts.URL, "")
	got, err := client.GetOIDCClient(context.Background(), "client-123")
	if err != nil {
		t.Fatalf("GetOIDCClient: %v", err)
	}
	if len(got.Secrets) != 0 {
		t.Fatalf("expected no secrets, got %+v", got.Secrets)
	}
}

func TestCreateOIDCClientSecret(t *testing.T) {
	t.Run("returns the created secret and its value", func(t *testing.T) {
		var sent map[string]any
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&sent)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"s1","prefix":"decl","secret":"declared-value-abc","isActive":true,
				"createdAt":"2026-08-19T12:00:00Z"}`))
		}))
		defer ts.Close()

		client, _ := NewClient(ts.URL, "")
		created, value, err := client.CreateOIDCClientSecret(context.Background(), "client-123", "declared-value-abc")
		if err != nil {
			t.Fatalf("CreateOIDCClientSecret: %v", err)
		}
		if sent["secret"] != "declared-value-abc" {
			t.Fatalf("expected the declared value to be sent, got %v", sent["secret"])
		}
		if value != "declared-value-abc" {
			t.Fatalf("expected the stored value back, got %q", value)
		}
		if created.ID != "s1" || created.Prefix != "decl" || !created.IsActive {
			t.Fatalf("unexpected created secret: %+v", created)
		}
	})

	// The value is disclosed exactly once. A response the operator cannot read leaves a secret it
	// can never use, so it has to fail rather than store an empty credential.
	t.Run("rejects a response with no secret value", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"s1","prefix":"abcd"}`))
		}))
		defer ts.Close()

		client, _ := NewClient(ts.URL, "")
		if _, _, err := client.CreateOIDCClientSecret(context.Background(), "client-123", ""); err == nil {
			t.Fatal("expected an error when the response carries no secret value")
		}
	})

	t.Run("propagates a rejected create", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer ts.Close()

		client, _ := NewClient(ts.URL, "")
		if _, _, err := client.CreateOIDCClientSecret(context.Background(), "client-123", ""); err == nil {
			t.Fatal("expected the API error to propagate")
		}
	})
}

func TestDeleteOIDCClientSecret(t *testing.T) {
	// Retirement is retried until it sticks, so a secret already gone is the desired end state.
	t.Run("treats an already-deleted secret as deleted", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer ts.Close()

		client, _ := NewClient(ts.URL, "")
		if err := client.DeleteOIDCClientSecret(context.Background(), "client-123", "gone"); err != nil {
			t.Fatalf("expected a missing secret to count as deleted, got %v", err)
		}
	})

	t.Run("propagates other failures", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		client, _ := NewClient(ts.URL, "")
		if err := client.DeleteOIDCClientSecret(context.Background(), "client-123", "s1"); err == nil {
			t.Fatal("expected a server error to propagate rather than count as deleted")
		}
	})
}

func TestDeleteOIDCClientLogo(t *testing.T) {
	t.Run("targets the requested side", func(t *testing.T) {
		var path, query string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path, query = r.URL.Path, r.URL.RawQuery
			w.WriteHeader(http.StatusNoContent)
		}))
		defer ts.Close()

		client, _ := NewClient(ts.URL, "")
		if err := client.DeleteOIDCClientLogo(context.Background(), "client-123", false); err != nil {
			t.Fatalf("DeleteOIDCClientLogo: %v", err)
		}
		if path != "/api/oidc/clients/client-123/logo" {
			t.Errorf("path: got %q", path)
		}
		if query != "light=false" {
			t.Errorf("query: got %q, want light=false", query)
		}
	})

	// Removal is retried until it sticks, so a logo already gone is the desired end state.
	t.Run("treats an already-deleted logo as deleted", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer ts.Close()

		client, _ := NewClient(ts.URL, "")
		if err := client.DeleteOIDCClientLogo(context.Background(), "client-123", true); err != nil {
			t.Fatalf("expected a missing logo to count as deleted, got %v", err)
		}
	})

	t.Run("propagates other failures", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		client, _ := NewClient(ts.URL, "")
		if err := client.DeleteOIDCClientLogo(context.Background(), "client-123", true); err == nil {
			t.Fatal("expected a server error to propagate rather than count as deleted")
		}
	})
}
