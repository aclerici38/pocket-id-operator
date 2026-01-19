package pocketid

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type sessionClient struct {
	baseURL    string
	httpClient *http.Client
}

// CreateAPIKeyRequest is the request body for creating an API key via session auth.
type CreateAPIKeyRequest struct {
	Name        string `json:"name"`
	ExpiresAt   string `json:"expiresAt"`
	Description string `json:"description"`
}

// CreateAPIKeyResponse is the response from creating an API key.
type CreateAPIKeyResponse struct {
	APIKey struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		CreatedAt   string `json:"createdAt"`
		ExpiresAt   string `json:"expiresAt"`
	} `json:"apiKey"`
	Token string `json:"token"`
}

func newSessionClient(baseURL string, httpClient *http.Client) *sessionClient {
	trimmed := strings.TrimRight(baseURL, "/")
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &sessionClient{
		baseURL:    trimmed,
		httpClient: httpClient,
	}
}

func (s *sessionClient) doJSONRequest(ctx context.Context, method, path string, requestBody any, cookies []*http.Cookie) (int, []*http.Cookie, []byte, error) {
	var bodyReader io.Reader
	if requestBody != nil {
		body, err := json.Marshal(requestBody)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, s.baseURL+path, bodyReader)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("create request: %w", err)
	}
	if requestBody != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	for _, cookie := range cookies {
		httpReq.AddCookie(cookie)
	}

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("read response: %w", err)
	}

	return resp.StatusCode, resp.Cookies(), respBody, nil
}

func (s *sessionClient) exchangeOneTimeAccessToken(ctx context.Context, token string) ([]*http.Cookie, error) {
	path := "/api/one-time-access-token/" + url.PathEscape(token)
	status, cookies, respBody, err := s.doJSONRequest(ctx, http.MethodPost, path, nil, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("exchange token failed with status %d: %s", status, string(respBody))
	}
	if len(cookies) == 0 {
		return nil, fmt.Errorf("no session cookies returned from token exchange")
	}
	return cookies, nil
}

func (s *sessionClient) createAPIKeyWithCookies(ctx context.Context, cookies []*http.Cookie, req CreateAPIKeyRequest) (*CreateAPIKeyResponse, error) {
	status, _, respBody, err := s.doJSONRequest(ctx, http.MethodPost, "/api/api-keys", req, cookies)
	if err != nil {
		return nil, err
	}
	if status != http.StatusCreated {
		return nil, fmt.Errorf("create API key failed with status %d: %s", status, string(respBody))
	}

	var apiKeyResp CreateAPIKeyResponse
	if err := json.Unmarshal(respBody, &apiKeyResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &apiKeyResp, nil
}
