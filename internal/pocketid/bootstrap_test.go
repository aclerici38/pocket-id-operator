package pocketid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const (
	testKeyID      = "key-123"
	testKeyName    = "operator-key"
	testUserID     = "user-123"
	testSessionVal = "test-session-token"
	testAPIToken   = "secret-api-token"
)

func TestNewBootstrapClient(t *testing.T) {
	client := NewBootstrapClient("https://example.com")
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.baseURL != "https://example.com" {
		t.Errorf("expected baseURL to be https://example.com, got %s", client.baseURL)
	}
	if client.httpClient.Timeout != 10*time.Second {
		t.Errorf("expected timeout to be 10s, got %v", client.httpClient.Timeout)
	}
}

func TestBootstrapClient_Setup(t *testing.T) {
	setupResponse := SetupResponse{
		ID:          testUserID,
		Username:    "admin",
		FirstName:   "Admin",
		LastName:    "User",
		Email:       "admin@example.com",
		DisplayName: "Admin User",
		IsAdmin:     true,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/signup/setup" {
			t.Errorf("expected /api/signup/setup, got %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Set a session cookie
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: testSessionVal,
		})

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(setupResponse)
	}))
	defer server.Close()

	client := NewBootstrapClient(server.URL)
	req := SetupRequest{
		Username:  "admin",
		FirstName: "Admin",
		LastName:  "User",
	}

	resp, cookies, err := client.Setup(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.ID != testUserID {
		t.Errorf("expected ID %s, got %s", testUserID, resp.ID)
	}
	if resp.Username != "admin" {
		t.Errorf("expected username admin, got %s", resp.Username)
	}
	if !resp.IsAdmin {
		t.Error("expected IsAdmin to be true")
	}

	if len(cookies) == 0 {
		t.Error("expected cookies to be returned")
	}
}

func TestBootstrapClient_Setup_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("setup already completed"))
	}))
	defer server.Close()

	client := NewBootstrapClient(server.URL)
	req := SetupRequest{
		Username:  "admin",
		FirstName: "Admin",
	}

	_, _, err := client.Setup(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "setup failed with status 400: setup already completed" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestBootstrapClient_CreateAPIKeyWithCookies(t *testing.T) {
	apiKeyResponse := CreateAPIKeyResponse{
		Token: testAPIToken,
	}
	apiKeyResponse.APIKey.ID = testKeyID
	apiKeyResponse.APIKey.Name = testKeyName
	apiKeyResponse.APIKey.Description = "Test key"
	apiKeyResponse.APIKey.CreatedAt = "2026-01-01T00:00:00Z"
	apiKeyResponse.APIKey.ExpiresAt = "2030-01-01T00:00:00Z"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/api-keys" {
			t.Errorf("expected /api/api-keys, got %s", r.URL.Path)
		}

		// Check that the cookie is sent
		cookie, err := r.Cookie("session")
		if err != nil {
			t.Errorf("expected session cookie: %v", err)
		}
		if cookie.Value != testSessionVal {
			t.Errorf("expected session cookie value %s, got %s", testSessionVal, cookie.Value)
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(apiKeyResponse)
	}))
	defer server.Close()

	client := NewBootstrapClient(server.URL)
	cookies := []*http.Cookie{
		{Name: "session", Value: testSessionVal},
	}
	req := CreateAPIKeyRequest{
		Name:        testKeyName,
		ExpiresAt:   "2030-01-01T00:00:00Z",
		Description: "Test key",
	}

	resp, err := client.CreateAPIKeyWithCookies(context.Background(), cookies, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Token != testAPIToken {
		t.Errorf("expected token %s, got %s", testAPIToken, resp.Token)
	}
	if resp.APIKey.ID != testKeyID {
		t.Errorf("expected ID %s, got %s", testKeyID, resp.APIKey.ID)
	}
	if resp.APIKey.Name != testKeyName {
		t.Errorf("expected name %s, got %s", testKeyName, resp.APIKey.Name)
	}
}

func TestBootstrapClient_CreateAPIKeyWithCookies_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
	}))
	defer server.Close()

	client := NewBootstrapClient(server.URL)
	cookies := []*http.Cookie{
		{Name: "session", Value: "invalid-token"},
	}
	req := CreateAPIKeyRequest{
		Name:      "operator-key",
		ExpiresAt: "2030-01-01T00:00:00Z",
	}

	_, err := client.CreateAPIKeyWithCookies(context.Background(), cookies, req)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "create API key failed with status 401: unauthorized" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestBootstrapClient_Bootstrap(t *testing.T) {
	setupResponse := SetupResponse{
		ID:          testUserID,
		Username:    "admin",
		FirstName:   "Admin",
		LastName:    "User",
		DisplayName: "Admin User",
		IsAdmin:     true,
	}

	apiKeyResponse := CreateAPIKeyResponse{
		Token: testAPIToken,
	}
	apiKeyResponse.APIKey.ID = testKeyID
	apiKeyResponse.APIKey.Name = testKeyName
	apiKeyResponse.APIKey.ExpiresAt = "2030-01-01T00:00:00Z"

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch r.URL.Path {
		case "/api/signup/setup":
			http.SetCookie(w, &http.Cookie{
				Name:  "session",
				Value: testSessionVal,
			})
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(setupResponse)
		case "/api/api-keys":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(apiKeyResponse)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewBootstrapClient(server.URL)
	setupReq := SetupRequest{
		Username:  "admin",
		FirstName: "Admin",
		LastName:  "User",
	}

	setup, apiKey, err := client.Bootstrap(
		context.Background(),
		setupReq,
		testKeyName,
		"Test key",
		time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if callCount != 2 {
		t.Errorf("expected 2 API calls, got %d", callCount)
	}

	if setup.ID != testUserID {
		t.Errorf("expected setup ID %s, got %s", testUserID, setup.ID)
	}
	if apiKey.Token != testAPIToken {
		t.Errorf("expected token %s, got %s", testAPIToken, apiKey.Token)
	}
}

func TestBootstrapClient_Bootstrap_NoCookies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Don't set any cookies
		setupResponse := SetupResponse{
			ID:       testUserID,
			Username: "admin",
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(setupResponse)
	}))
	defer server.Close()

	client := NewBootstrapClient(server.URL)
	setupReq := SetupRequest{
		Username:  "admin",
		FirstName: "Admin",
	}

	_, _, err := client.Bootstrap(
		context.Background(),
		setupReq,
		testKeyName,
		"Test key",
		time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	)
	if err == nil {
		t.Fatal("expected error due to missing cookies")
	}
	if err.Error() != "no session cookies returned from setup" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDefaultAPIKeyExpiry(t *testing.T) {
	expiry := DefaultAPIKeyExpiry()
	now := time.Now()

	// Should be approximately 10 years from now
	expectedExpiry := now.AddDate(10, 0, 0)
	diff := expiry.Sub(expectedExpiry)

	// Allow for a small margin of error (1 minute)
	if diff > time.Minute || diff < -time.Minute {
		t.Errorf("expected expiry to be ~10 years from now, got %v (diff: %v)", expiry, diff)
	}
}
