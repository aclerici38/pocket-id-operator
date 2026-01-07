package pocketid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aclerici38/pocket-id-go-client/v2/models"
)

const (
	pathUsersMe  = "/api/users/me"
	pathUsers    = "/api/users"
	pathAPIKeysC = "/api/api-keys"
)

func TestNewClient(t *testing.T) {
	client := NewClient("https://example.com")
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.raw == nil {
		t.Error("expected non-nil raw client")
	}
	if client.transport == nil {
		t.Error("expected non-nil transport")
	}
}

func TestNewClient_WithPort(t *testing.T) {
	client := NewClient("https://example.com:8443")
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNewClient_HTTP(t *testing.T) {
	client := NewClient("http://localhost:1411")
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestClient_WithAPIKey(t *testing.T) {
	baseClient := NewClient("https://example.com")
	authClient := baseClient.WithAPIKey("test-api-key")

	if authClient == nil {
		t.Fatal("expected non-nil client")
	}
	if authClient == baseClient {
		t.Error("expected different client instance")
	}
	if authClient.transport.DefaultAuthentication == nil {
		t.Error("expected authentication to be set")
	}
}

func TestClient_WithCookie(t *testing.T) {
	baseClient := NewClient("https://example.com")
	cookie := &http.Cookie{Name: "session", Value: "test-session"}
	authClient := baseClient.WithCookie(cookie)

	if authClient == nil {
		t.Fatal("expected non-nil client")
	}
	if authClient == baseClient {
		t.Error("expected different client instance")
	}
	if authClient.transport.DefaultAuthentication == nil {
		t.Error("expected authentication to be set")
	}
}

func TestUserFromDTO(t *testing.T) {
	tests := []struct {
		name     string
		dto      *models.GithubComPocketIDPocketIDBackendInternalDtoUserDto
		expected *User
	}{
		{
			name:     "nil dto",
			dto:      nil,
			expected: nil,
		},
		{
			name: "full dto",
			dto: &models.GithubComPocketIDPocketIDBackendInternalDtoUserDto{
				ID:          "user-123",
				Username:    "testuser",
				FirstName:   "Test",
				LastName:    "User",
				Email:       "test@example.com",
				DisplayName: "Test User",
				IsAdmin:     true,
				Disabled:    false,
				Locale:      "en-US",
			},
			expected: &User{
				ID:          "user-123",
				Username:    "testuser",
				FirstName:   "Test",
				LastName:    "User",
				Email:       "test@example.com",
				DisplayName: "Test User",
				IsAdmin:     true,
				Disabled:    false,
				Locale:      "en-US",
			},
		},
		{
			name: "partial dto",
			dto: &models.GithubComPocketIDPocketIDBackendInternalDtoUserDto{
				ID:       "user-456",
				Username: "minimaluser",
			},
			expected: &User{
				ID:       "user-456",
				Username: "minimaluser",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := userFromDTO(tt.dto)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.ID != tt.expected.ID {
				t.Errorf("expected ID %s, got %s", tt.expected.ID, result.ID)
			}
			if result.Username != tt.expected.Username {
				t.Errorf("expected Username %s, got %s", tt.expected.Username, result.Username)
			}
			if result.FirstName != tt.expected.FirstName {
				t.Errorf("expected FirstName %s, got %s", tt.expected.FirstName, result.FirstName)
			}
			if result.LastName != tt.expected.LastName {
				t.Errorf("expected LastName %s, got %s", tt.expected.LastName, result.LastName)
			}
			if result.Email != tt.expected.Email {
				t.Errorf("expected Email %s, got %s", tt.expected.Email, result.Email)
			}
			if result.DisplayName != tt.expected.DisplayName {
				t.Errorf("expected DisplayName %s, got %s", tt.expected.DisplayName, result.DisplayName)
			}
			if result.IsAdmin != tt.expected.IsAdmin {
				t.Errorf("expected IsAdmin %v, got %v", tt.expected.IsAdmin, result.IsAdmin)
			}
			if result.Disabled != tt.expected.Disabled {
				t.Errorf("expected Disabled %v, got %v", tt.expected.Disabled, result.Disabled)
			}
			if result.Locale != tt.expected.Locale {
				t.Errorf("expected Locale %s, got %s", tt.expected.Locale, result.Locale)
			}
		})
	}
}

func TestAPIKeyFromDTO(t *testing.T) {
	tests := []struct {
		name     string
		dto      *models.GithubComPocketIDPocketIDBackendInternalDtoAPIKeyDto
		expected APIKey
	}{
		{
			name:     "nil dto",
			dto:      nil,
			expected: APIKey{},
		},
		{
			name: "full dto",
			dto: &models.GithubComPocketIDPocketIDBackendInternalDtoAPIKeyDto{
				ID:          "key-123",
				Name:        "test-key",
				Description: "Test API key",
				CreatedAt:   "2026-01-01T00:00:00Z",
				ExpiresAt:   "2030-01-01T00:00:00Z",
				LastUsedAt:  "2026-01-02T00:00:00Z",
			},
			expected: APIKey{
				ID:          "key-123",
				Name:        "test-key",
				Description: "Test API key",
				CreatedAt:   "2026-01-01T00:00:00Z",
				ExpiresAt:   "2030-01-01T00:00:00Z",
				LastUsedAt:  "2026-01-02T00:00:00Z",
			},
		},
		{
			name: "partial dto",
			dto: &models.GithubComPocketIDPocketIDBackendInternalDtoAPIKeyDto{
				ID:   "key-456",
				Name: "minimal-key",
			},
			expected: APIKey{
				ID:   "key-456",
				Name: "minimal-key",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := apiKeyFromDTO(tt.dto)
			if result.ID != tt.expected.ID {
				t.Errorf("expected ID %s, got %s", tt.expected.ID, result.ID)
			}
			if result.Name != tt.expected.Name {
				t.Errorf("expected Name %s, got %s", tt.expected.Name, result.Name)
			}
			if result.Description != tt.expected.Description {
				t.Errorf("expected Description %s, got %s", tt.expected.Description, result.Description)
			}
			if result.CreatedAt != tt.expected.CreatedAt {
				t.Errorf("expected CreatedAt %s, got %s", tt.expected.CreatedAt, result.CreatedAt)
			}
			if result.ExpiresAt != tt.expected.ExpiresAt {
				t.Errorf("expected ExpiresAt %s, got %s", tt.expected.ExpiresAt, result.ExpiresAt)
			}
			if result.LastUsedAt != tt.expected.LastUsedAt {
				t.Errorf("expected LastUsedAt %s, got %s", tt.expected.LastUsedAt, result.LastUsedAt)
			}
		})
	}
}

// Integration-style tests that use httptest to mock the API server

func TestClient_GetCurrentUser(t *testing.T) {
	userResp := &models.GithubComPocketIDPocketIDBackendInternalDtoUserDto{
		ID:          "user-123",
		Username:    "testuser",
		FirstName:   "Test",
		LastName:    "User",
		Email:       "test@example.com",
		DisplayName: "Test User",
		IsAdmin:     true,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != pathUsersMe {
			t.Errorf("expected path %s, got %s", pathUsersMe, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(userResp)
	}))
	defer server.Close()

	client := NewClient(server.URL).WithAPIKey("test-key")
	user, err := client.GetCurrentUser(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.ID != "user-123" {
		t.Errorf("expected ID user-123, got %s", user.ID)
	}
	if user.Username != "testuser" {
		t.Errorf("expected username testuser, got %s", user.Username)
	}
}

func TestClient_GetUser(t *testing.T) {
	userResp := &models.GithubComPocketIDPocketIDBackendInternalDtoUserDto{
		ID:        "user-456",
		Username:  "specificuser",
		FirstName: "Specific",
		LastName:  "User",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/users/user-456" {
			t.Errorf("expected path /api/users/user-456, got %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(userResp)
	}))
	defer server.Close()

	client := NewClient(server.URL).WithAPIKey("test-key")
	user, err := client.GetUser(context.Background(), "user-456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.ID != "user-456" {
		t.Errorf("expected ID user-456, got %s", user.ID)
	}
}

func TestClient_CreateUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != pathUsers {
			t.Errorf("expected path %s, got %s", pathUsers, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		userResp := &models.GithubComPocketIDPocketIDBackendInternalDtoUserDto{
			ID:        "new-user-id",
			Username:  "newuser",
			FirstName: "New",
			LastName:  "User",
			Email:     "new@example.com",
			IsAdmin:   false,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(userResp)
	}))
	defer server.Close()

	client := NewClient(server.URL).WithAPIKey("test-key")
	user, err := client.CreateUser(context.Background(), UserInput{
		Username:    "newuser",
		FirstName:   "New",
		LastName:    "User",
		Email:       "new@example.com",
		DisplayName: "New User",
		IsAdmin:     false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.ID != "new-user-id" {
		t.Errorf("expected ID new-user-id, got %s", user.ID)
	}
	if user.Username != "newuser" {
		t.Errorf("expected username newuser, got %s", user.Username)
	}
}

func TestClient_UpdateUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/users/user-123" {
			t.Errorf("expected path /api/users/user-123, got %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}

		userResp := &models.GithubComPocketIDPocketIDBackendInternalDtoUserDto{
			ID:        "user-123",
			Username:  "updateduser",
			FirstName: "Updated",
			LastName:  "User",
			Email:     "updated@example.com",
			IsAdmin:   true,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(userResp)
	}))
	defer server.Close()

	client := NewClient(server.URL).WithAPIKey("test-key")
	user, err := client.UpdateUser(context.Background(), "user-123", UserInput{
		Username:    "updateduser",
		FirstName:   "Updated",
		LastName:    "User",
		Email:       "updated@example.com",
		DisplayName: "Updated User",
		IsAdmin:     true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.Username != "updateduser" {
		t.Errorf("expected username updateduser, got %s", user.Username)
	}
	if !user.IsAdmin {
		t.Error("expected IsAdmin to be true")
	}
}

func TestClient_DeleteUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/users/user-123" {
			t.Errorf("expected path /api/users/user-123, got %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(server.URL).WithAPIKey("test-key")
	err := client.DeleteUser(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClient_ListAPIKeys(t *testing.T) {
	keysResp := struct {
		Data []*models.GithubComPocketIDPocketIDBackendInternalDtoAPIKeyDto `json:"data"`
	}{
		Data: []*models.GithubComPocketIDPocketIDBackendInternalDtoAPIKeyDto{
			{
				ID:        "key-1",
				Name:      "first-key",
				ExpiresAt: "2030-01-01T00:00:00Z",
			},
			{
				ID:        "key-2",
				Name:      "second-key",
				ExpiresAt: "2031-01-01T00:00:00Z",
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != pathAPIKeysC {
			t.Errorf("expected path %s, got %s", pathAPIKeysC, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(keysResp)
	}))
	defer server.Close()

	client := NewClient(server.URL).WithAPIKey("test-key")
	keys, err := client.ListAPIKeys(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if keys[0].ID != "key-1" {
		t.Errorf("expected first key ID key-1, got %s", keys[0].ID)
	}
	if keys[1].Name != "second-key" {
		t.Errorf("expected second key name second-key, got %s", keys[1].Name)
	}
}

func TestClient_CreateAPIKey(t *testing.T) {
	keyResp := struct {
		APIKey *models.GithubComPocketIDPocketIDBackendInternalDtoAPIKeyDto `json:"apiKey"`
		Token  string                                                       `json:"token"`
	}{
		APIKey: &models.GithubComPocketIDPocketIDBackendInternalDtoAPIKeyDto{
			ID:          "new-key-id",
			Name:        "new-key",
			Description: "A new API key",
			CreatedAt:   "2026-01-01T00:00:00Z",
			ExpiresAt:   "2030-01-01T00:00:00Z",
		},
		Token: "secret-token-value",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != pathAPIKeysC {
			t.Errorf("expected path %s, got %s", pathAPIKeysC, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(keyResp)
	}))
	defer server.Close()

	client := NewClient(server.URL).WithAPIKey("test-key")
	key, err := client.CreateAPIKey(context.Background(), "new-key", "2030-01-01T00:00:00Z", "A new API key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if key.ID != "new-key-id" {
		t.Errorf("expected ID new-key-id, got %s", key.ID)
	}
	if key.Token != "secret-token-value" {
		t.Errorf("expected token secret-token-value, got %s", key.Token)
	}
}

func TestClient_DeleteAPIKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/api-keys/key-123" {
			t.Errorf("expected path /api/api-keys/key-123, got %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(server.URL).WithAPIKey("test-key")
	err := client.DeleteAPIKey(context.Background(), "key-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Error handling tests

func TestClient_GetUser_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error": "user not found"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL).WithAPIKey("test-key")
	_, err := client.GetUser(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for not found user")
	}
}

func TestClient_CreateUser_Conflict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error": "user already exists"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL).WithAPIKey("test-key")
	_, err := client.CreateUser(context.Background(), UserInput{
		Username:    "existing",
		FirstName:   "First",
		LastName:    "Last",
		Email:       "email@example.com",
		DisplayName: "First Last",
		IsAdmin:     false,
	})
	if err == nil {
		t.Fatal("expected error for conflicting user")
	}
}

func TestClient_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": "invalid API key"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL).WithAPIKey("invalid-key")
	_, err := client.GetCurrentUser(context.Background())
	if err == nil {
		t.Fatal("expected error for unauthorized request")
	}
}
