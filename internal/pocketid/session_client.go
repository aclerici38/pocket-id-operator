package pocketid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	logoutTimeout   = 5 * time.Second
	apiKeysPageSize = 100
)

// UserSession is a browser session for one user, the only credential that can manage keys the user owns.
type UserSession struct {
	baseURL    string
	httpClient *http.Client
	cookies    []*http.Cookie
}

func newUserSession(baseURL string, httpClient *http.Client) *UserSession {
	trimmed := strings.TrimRight(baseURL, "/")
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &UserSession{
		baseURL:    trimmed,
		httpClient: httpClient,
	}
}

// doJSONRequest sends a request in the session, failing with an *APIError unless the response has one of wantStatuses.
func (s *UserSession) doJSONRequest(ctx context.Context, operation, method, path string, requestBody any, wantStatuses ...int) (*http.Response, []byte, error) {
	var bodyReader io.Reader
	if requestBody != nil {
		body, err := json.Marshal(requestBody)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, s.baseURL+path, bodyReader)
	if err != nil {
		return nil, nil, fmt.Errorf("create request: %w", err)
	}
	if requestBody != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	for _, cookie := range s.cookies {
		httpReq.AddCookie(cookie)
	}

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}
	if !slices.Contains(wantStatuses, resp.StatusCode) {
		return nil, nil, newAPIError(operation, resp.StatusCode, resp.Header, respBody, errors.New(string(respBody)))
	}

	return resp, respBody, nil
}

// do sends a request in the session and decodes the response into out, failing unless it has wantStatus.
func (s *UserSession) do(ctx context.Context, operation, method, path string, requestBody any, wantStatus int, out any) error {
	_, respBody, err := s.doJSONRequest(ctx, operation, method, path, requestBody, wantStatus)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}
	return nil
}

func (s *UserSession) exchangeOneTimeAccessToken(ctx context.Context, token string) error {
	path := "/api/one-time-access-token/" + url.PathEscape(token)
	resp, _, err := s.doJSONRequest(ctx, "PostAPIOneTimeAccessTokenToken", http.MethodPost, path, nil, http.StatusOK)
	if err != nil {
		return err
	}
	if len(resp.Cookies()) == 0 {
		return fmt.Errorf("no session cookies returned from token exchange")
	}
	s.cookies = resp.Cookies()
	return nil
}

// ListAPIKeys returns every API key the user owns.
func (s *UserSession) ListAPIKeys(ctx context.Context) (keys []APIKey, err error) {
	start := time.Now()
	defer func() { recordCall("list_api_keys", err, time.Since(start)) }()

	for page := 1; ; page++ {
		query := url.Values{
			"pagination[page]":  {strconv.Itoa(page)},
			"pagination[limit]": {strconv.Itoa(apiKeysPageSize)},
		}
		var resp struct {
			Data       []APIKey `json:"data"`
			Pagination struct {
				TotalPages int `json:"totalPages"`
			} `json:"pagination"`
		}
		if err := s.do(ctx, "GetAPIAPIKeys", http.MethodGet, "/api/api-keys?"+query.Encode(), nil, http.StatusOK, &resp); err != nil {
			return nil, fmt.Errorf("list API keys: %w", err)
		}
		keys = append(keys, resp.Data...)
		if page >= resp.Pagination.TotalPages {
			return keys, nil
		}
	}
}

// CreateAPIKey creates an API key. Its token is only ever returned here.
func (s *UserSession) CreateAPIKey(ctx context.Context, name, expiresAt, description string, scopes []string) (result *APIKeyWithToken, err error) {
	start := time.Now()
	defer func() { recordCall("create_api_key_for_user", err, time.Since(start)) }()

	body := map[string]any{"name": name, "expiresAt": expiresAt, "description": description, "scopes": scopes}
	if err := s.do(ctx, "PostAPIAPIKeys", http.MethodPost, "/api/api-keys", body, http.StatusCreated, &result); err != nil {
		return nil, fmt.Errorf("create API key: %w", err)
	}
	return result, nil
}

// UpdateAPIKey changes a key's name, description and scopes, keeping its token.
func (s *UserSession) UpdateAPIKey(ctx context.Context, id, name, description string, scopes []string) (result *APIKey, err error) {
	start := time.Now()
	defer func() { recordCall("update_api_key", err, time.Since(start)) }()

	body := map[string]any{"name": name, "description": description, "scopes": scopes}
	if err := s.do(ctx, "PutAPIAPIKeysID", http.MethodPut, "/api/api-keys/"+url.PathEscape(id), body, http.StatusOK, &result); err != nil {
		return nil, fmt.Errorf("update API key: %w", err)
	}
	return result, nil
}

// RenewAPIKey moves a key's expiry, which replaces its token and revokes the old one immediately.
func (s *UserSession) RenewAPIKey(ctx context.Context, id, expiresAt string) (result *APIKeyWithToken, err error) {
	start := time.Now()
	defer func() { recordCall("renew_api_key", err, time.Since(start)) }()

	body := map[string]any{"expiresAt": expiresAt, "gracePeriodHours": 0}
	if err := s.do(ctx, "PostAPIAPIKeysIDRenew", http.MethodPost, "/api/api-keys/"+url.PathEscape(id)+"/renew", body, http.StatusOK, &result); err != nil {
		return nil, fmt.Errorf("renew API key: %w", err)
	}
	return result, nil
}

// DeleteAPIKey revokes an API key, treating one that's already gone as deleted.
func (s *UserSession) DeleteAPIKey(ctx context.Context, id string) (err error) {
	start := time.Now()
	defer func() { recordCall("delete_api_key", err, time.Since(start)) }()

	if _, _, err := s.doJSONRequest(ctx, "DeleteAPIAPIKeysID", http.MethodDelete, "/api/api-keys/"+url.PathEscape(id), nil, http.StatusNoContent, http.StatusNotFound); err != nil {
		return fmt.Errorf("delete API key: %w", err)
	}
	return nil
}

// logout is detached from ctx's cancellation so a cancelled reconcile doesn't leave the session behind.
func (s *UserSession) logout(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), logoutTimeout)
	defer cancel()

	_, _, err := s.doJSONRequest(ctx, "PostAPIWebauthnLogout", http.MethodPost, "/api/webauthn/logout", nil, http.StatusNoContent)
	return err
}
