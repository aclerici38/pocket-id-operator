package pocketid

import (
	"testing"

	"github.com/aclerici38/pocket-id-go-client/v2/models"
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
