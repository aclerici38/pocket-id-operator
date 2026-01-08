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

func (s *sessionClient) doJSONRequest(ctx context.Context, method, path string, requestBody interface{}, cookies []*http.Cookie) (int, []*http.Cookie, []byte, error) {
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

func (s *sessionClient) setup(ctx context.Context, req SetupRequest) (*SetupResponse, []*http.Cookie, error) {
	status, cookies, respBody, err := s.doJSONRequest(ctx, http.MethodPost, "/api/signup/setup", req, nil)
	if err != nil {
		return nil, nil, err
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("setup failed with status %d: %s", status, string(respBody))
	}

	var setupResp SetupResponse
	if err := json.Unmarshal(respBody, &setupResp); err != nil {
		return nil, nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &setupResp, cookies, nil
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
