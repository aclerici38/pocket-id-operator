package pocketid

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"
)

const (
	tokenPath    = "/api/users/user-1/one-time-access-token"
	exchangePath = "/api/one-time-access-token"
	keysPath     = "/api/api-keys"
	keyPath      = "/api/api-keys/key-1"
	logoutPath   = "/api/webauthn/logout"
)

const sessionCookie = "session_token=session-value"

// sessionCalls records the requests a sessionServer received.
type sessionCalls struct {
	paths        []string
	logoutCookie string
}

// sessionServer serves the session flow, passing API key requests to keys.
func sessionServer(t *testing.T, exchangeStatus, logoutStatus int, keys http.HandlerFunc) (*Client, *sessionCalls) {
	t.Helper()
	calls := &sessionCalls{}
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.paths = append(calls.paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case tokenPath:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"token":"one-time-token"}`))
		case exchangePath:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["token"] != "one-time-token" {
				t.Errorf("exchange body token = %q, want the one-time token", body["token"])
			}
			if exchangeStatus != 0 {
				w.WriteHeader(exchangeStatus)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "session-value"})
		case logoutPath:
			calls.logoutCookie = r.Header.Get("Cookie")
			w.WriteHeader(cmp.Or(logoutStatus, http.StatusNoContent))
		default:
			if r.Header.Get("Cookie") != sessionCookie {
				t.Errorf("%s %s sent cookie %q, want the session's", r.Method, r.URL.Path, r.Header.Get("Cookie"))
			}
			keys(w, r)
		}
	}))
	return client, calls
}

func TestWithUserSession_EndsSession(t *testing.T) {
	inSession := []string{tokenPath, exchangePath, keysPath, logoutPath}
	tests := []struct {
		name           string
		exchangeStatus int
		listStatus     int
		logoutStatus   int
		cancelDuringFn bool
		wantCalls      []string
		wantErr        bool
	}{
		{name: "after fn returns", wantCalls: inSession},
		{name: "when fn fails", listStatus: http.StatusBadRequest, wantCalls: inSession, wantErr: true},
		{name: "when ctx is cancelled mid-call", cancelDuringFn: true, wantCalls: inSession, wantErr: true},
		{name: "without failing the call when logout fails", logoutStatus: http.StatusInternalServerError, wantCalls: inSession},
		{
			name:           "not when no session was started",
			exchangeStatus: http.StatusUnauthorized,
			wantCalls:      []string{tokenPath, exchangePath},
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			// Holds the list response so the client can only see the cancellation.
			release := make(chan struct{})
			client, calls := sessionServer(t, tt.exchangeStatus, tt.logoutStatus, func(w http.ResponseWriter, _ *http.Request) {
				if tt.cancelDuringFn {
					cancel()
					<-release
					return
				}
				w.WriteHeader(cmp.Or(tt.listStatus, http.StatusOK))
				_, _ = w.Write([]byte(`{"data":[],"pagination":{"totalPages":1}}`))
			})

			err := client.WithUserSession(ctx, "user-1", 5, func(session *UserSession) error {
				_, err := session.ListAPIKeys(ctx)
				return err
			})
			close(release)

			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(calls.paths, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", calls.paths, tt.wantCalls)
			}
			if len(tt.wantCalls) == len(inSession) && calls.logoutCookie != sessionCookie {
				t.Errorf("logout cookie = %q, want the exchange's session cookie", calls.logoutCookie)
			}
		})
	}
}

func TestWithUserSession_ReportsRateLimit(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == tokenPath {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"token":"one-time-token"}`))
			return
		}
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"Too many requests","code":"rate_limited"}`))
	}))

	err := client.WithUserSession(t.Context(), "user-1", 5, func(*UserSession) error { return nil })
	if !IsRateLimitedError(err) || AsAPIError(err).RetryAfter != 7*time.Second {
		t.Errorf("error = %v, want rate limited with Retry-After 7s", err)
	}
}

func TestListAPIKeys_ReadsEveryPage(t *testing.T) {
	var pages []string
	client, _ := sessionServer(t, 0, 0, func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("pagination[page]")
		pages = append(pages, page)
		_, _ = fmt.Fprintf(w, `{"data":[{"id":"key-%s","scopes":["account:read"]}],"pagination":{"totalPages":2}}`, page)
	})

	var keys []APIKey
	err := client.WithUserSession(t.Context(), "user-1", 5, func(session *UserSession) (err error) {
		keys, err = session.ListAPIKeys(t.Context())
		return err
	})
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}

	want := []APIKey{{ID: "key-1", Scopes: []string{"account:read"}}, {ID: "key-2", Scopes: []string{"account:read"}}}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("keys = %+v, want %+v", keys, want)
	}
	if !reflect.DeepEqual(pages, []string{"1", "2"}) {
		t.Errorf("pages = %v, want [1 2]", pages)
	}
}

func TestAPIKeyWrites(t *testing.T) {
	scopes := []string{"account:read", "users:read"}
	tests := []struct {
		name       string
		call       func(*UserSession) (string, error)
		status     int
		wantMethod string
		wantPath   string
		wantBody   map[string]any
		want       string
		wantErr    bool
	}{
		{
			name: "create sends the key and returns its token",
			call: func(s *UserSession) (string, error) {
				k, err := s.CreateAPIKey(t.Context(), "key", "2030-01-01T00:00:00Z", "desc", scopes)
				if err != nil {
					return "", err
				}
				return k.Token, nil
			},
			status:     http.StatusCreated,
			wantMethod: http.MethodPost,
			wantPath:   keysPath,
			wantBody:   map[string]any{"name": "key", "expiresAt": "2030-01-01T00:00:00Z", "description": "desc", "scopes": []any{"account:read", "users:read"}},
			want:       "key-token",
		},
		{
			name: "update sends the editable fields",
			call: func(s *UserSession) (string, error) {
				k, err := s.UpdateAPIKey(t.Context(), "key-1", "key", "desc", scopes)
				if err != nil {
					return "", err
				}
				return k.ID, nil
			},
			status:     http.StatusOK,
			wantMethod: http.MethodPut,
			wantPath:   keyPath,
			wantBody:   map[string]any{"name": "key", "description": "desc", "scopes": []any{"account:read", "users:read"}},
			want:       "key-1",
		},
		{
			name: "renew revokes the old token at once",
			call: func(s *UserSession) (string, error) {
				k, err := s.RenewAPIKey(t.Context(), "key-1", "2031-01-01T00:00:00Z")
				if err != nil {
					return "", err
				}
				return k.Token, nil
			},
			status:     http.StatusOK,
			wantMethod: http.MethodPost,
			wantPath:   keyPath + "/renew",
			wantBody:   map[string]any{"expiresAt": "2031-01-01T00:00:00Z", "gracePeriodHours": float64(0)},
			want:       "key-token",
		},
		{
			name:       "delete revokes the key",
			call:       func(s *UserSession) (string, error) { return "", s.DeleteAPIKey(t.Context(), "key-1") },
			status:     http.StatusNoContent,
			wantMethod: http.MethodDelete,
			wantPath:   keyPath,
		},
		{
			name:       "delete treats a key that's already gone as deleted",
			call:       func(s *UserSession) (string, error) { return "", s.DeleteAPIKey(t.Context(), "key-1") },
			status:     http.StatusNotFound,
			wantMethod: http.MethodDelete,
			wantPath:   keyPath,
		},
		{
			name: "update reports a refused change",
			call: func(s *UserSession) (string, error) {
				_, err := s.UpdateAPIKey(t.Context(), "key-1", "key", "desc", scopes)
				return "", err
			},
			status:     http.StatusBadRequest,
			wantMethod: http.MethodPut,
			wantPath:   keyPath,
			wantBody:   map[string]any{"name": "key", "description": "desc", "scopes": []any{"account:read", "users:read"}},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var method, path string
			var body map[string]any
			client, _ := sessionServer(t, 0, 0, func(w http.ResponseWriter, r *http.Request) {
				method, path = r.Method, r.URL.Path
				_ = json.NewDecoder(r.Body).Decode(&body)
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(`{"id":"key-1","apiKey":{"id":"key-1"},"token":"key-token"}`))
			})

			var got string
			err := client.WithUserSession(t.Context(), "user-1", 5, func(session *UserSession) (err error) {
				got, err = tt.call(session)
				return err
			})

			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if method != tt.wantMethod || path != tt.wantPath {
				t.Errorf("request = %s %s, want %s %s", method, path, tt.wantMethod, tt.wantPath)
			}
			if !reflect.DeepEqual(body, tt.wantBody) {
				t.Errorf("body = %v, want %v", body, tt.wantBody)
			}
			if got != tt.want {
				t.Errorf("result = %q, want %q", got, tt.want)
			}
		})
	}
}
