package pocketid

import (
	"context"
	"encoding/json"
	"io"
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
	pathSetup      = "/api/signup/setup"
	pathAPIKeys    = "/api/api-keys"
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
		if r.URL.Path != pathSetup {
			t.Errorf("expected %s, got %s", pathSetup, r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Verify request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}
		var req SetupRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("failed to unmarshal body: %v", err)
		}
		if req.Username != "admin" {
			t.Errorf("expected username admin, got %s", req.Username)
		}
		if req.FirstName != "Admin" {
			t.Errorf("expected firstName Admin, got %s", req.FirstName)
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

func TestBootstrapClient_Setup_WithEmail(t *testing.T) {
	setupResponse := SetupResponse{
		ID:       testUserID,
		Username: "admin",
		Email:    "admin@example.com",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req SetupRequest
		_ = json.Unmarshal(body, &req)

		if req.Email != "admin@example.com" {
			t.Errorf("expected email admin@example.com, got %s", req.Email)
		}

		http.SetCookie(w, &http.Cookie{Name: "session", Value: testSessionVal})
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(setupResponse)
	}))
	defer server.Close()

	client := NewBootstrapClient(server.URL)
	req := SetupRequest{
		Username:  "admin",
		FirstName: "Admin",
		Email:     "admin@example.com",
	}

	resp, _, err := client.Setup(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Email != "admin@example.com" {
		t.Errorf("expected email admin@example.com, got %s", resp.Email)
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

func TestBootstrapClient_Setup_InternalServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("database connection failed"))
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
	if err.Error() != "setup failed with status 500: database connection failed" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestBootstrapClient_Setup_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: testSessionVal})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json"))
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
	if err.Error()[:18] != "unmarshal response" {
		t.Errorf("expected unmarshal error, got: %v", err)
	}
}

func TestBootstrapClient_Setup_ConnectionError(t *testing.T) {
	client := NewBootstrapClient("http://localhost:99999")
	req := SetupRequest{
		Username:  "admin",
		FirstName: "Admin",
	}

	_, _, err := client.Setup(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
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
		if r.URL.Path != pathAPIKeys {
			t.Errorf("expected %s, got %s", pathAPIKeys, r.URL.Path)
		}

		// Check that the cookie is sent
		cookie, err := r.Cookie("session")
		if err != nil {
			t.Errorf("expected session cookie: %v", err)
		}
		if cookie.Value != testSessionVal {
			t.Errorf("expected session cookie value %s, got %s", testSessionVal, cookie.Value)
		}

		// Verify request body
		body, _ := io.ReadAll(r.Body)
		var req CreateAPIKeyRequest
		_ = json.Unmarshal(body, &req)
		if req.Name != testKeyName {
			t.Errorf("expected name %s, got %s", testKeyName, req.Name)
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

func TestBootstrapClient_CreateAPIKeyWithCookies_MultipleCookies(t *testing.T) {
	apiKeyResponse := CreateAPIKeyResponse{Token: testAPIToken}
	apiKeyResponse.APIKey.ID = testKeyID

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that both cookies are sent
		session, _ := r.Cookie("session")
		csrf, _ := r.Cookie("csrf")

		if session == nil || session.Value != testSessionVal {
			t.Error("expected session cookie")
		}
		if csrf == nil || csrf.Value != "csrf-token" {
			t.Error("expected csrf cookie")
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(apiKeyResponse)
	}))
	defer server.Close()

	client := NewBootstrapClient(server.URL)
	cookies := []*http.Cookie{
		{Name: "session", Value: testSessionVal},
		{Name: "csrf", Value: "csrf-token"},
	}
	req := CreateAPIKeyRequest{Name: testKeyName, ExpiresAt: "2030-01-01T00:00:00Z"}

	_, err := client.CreateAPIKeyWithCookies(context.Background(), cookies, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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

func TestBootstrapClient_CreateAPIKeyWithCookies_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("insufficient permissions"))
	}))
	defer server.Close()

	client := NewBootstrapClient(server.URL)
	cookies := []*http.Cookie{{Name: "session", Value: testSessionVal}}
	req := CreateAPIKeyRequest{Name: "key", ExpiresAt: "2030-01-01T00:00:00Z"}

	_, err := client.CreateAPIKeyWithCookies(context.Background(), cookies, req)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "create API key failed with status 403: insufficient permissions" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestBootstrapClient_CreateAPIKeyWithCookies_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	client := NewBootstrapClient(server.URL)
	cookies := []*http.Cookie{{Name: "session", Value: testSessionVal}}
	req := CreateAPIKeyRequest{Name: "key", ExpiresAt: "2030-01-01T00:00:00Z"}

	_, err := client.CreateAPIKeyWithCookies(context.Background(), cookies, req)
	if err == nil {
		t.Fatal("expected error")
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
		case pathSetup:
			http.SetCookie(w, &http.Cookie{
				Name:  "session",
				Value: testSessionVal,
			})
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(setupResponse)
		case pathAPIKeys:
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

func TestBootstrapClient_Bootstrap_SetupFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("setup already completed"))
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
		t.Fatal("expected error due to setup failure")
	}
}

func TestBootstrapClient_Bootstrap_APIKeyFails(t *testing.T) {
	setupResponse := SetupResponse{
		ID:       testUserID,
		Username: "admin",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case pathSetup:
			http.SetCookie(w, &http.Cookie{Name: "session", Value: testSessionVal})
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(setupResponse)
		case pathAPIKeys:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("failed to create API key"))
		}
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
		t.Fatal("expected error due to API key creation failure")
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

func TestDefaultAPIKeyExpiry_Format(t *testing.T) {
	expiry := DefaultAPIKeyExpiry()

	// Should be parseable as RFC3339
	formatted := expiry.Format(time.RFC3339)
	_, err := time.Parse(time.RFC3339, formatted)
	if err != nil {
		t.Errorf("expected valid RFC3339 format, got error: %v", err)
	}
}

// Context cancellation tests

func TestBootstrapClient_Setup_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewBootstrapClient(server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _, err := client.Setup(ctx, SetupRequest{Username: "admin", FirstName: "Admin"})
	if err == nil {
		t.Fatal("expected error due to context cancellation")
	}
}

func TestBootstrapClient_CreateAPIKeyWithCookies_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := NewBootstrapClient(server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cookies := []*http.Cookie{{Name: "session", Value: testSessionVal}}
	_, err := client.CreateAPIKeyWithCookies(ctx, cookies, CreateAPIKeyRequest{Name: "key", ExpiresAt: "2030-01-01T00:00:00Z"})
	if err == nil {
		t.Fatal("expected error due to context cancellation")
	}
}
