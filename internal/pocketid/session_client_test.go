package pocketid

import (
	"cmp"
	"context"
	"net/http"
	"reflect"
	"testing"
)

const (
	tokenPath    = "/api/users/user-1/one-time-access-token"
	exchangePath = "/api/one-time-access-token/one-time-token"
	createPath   = "/api/api-keys"
	deletePath   = "/api/api-keys/key-1"
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
			if exchangeStatus != 0 {
				w.WriteHeader(exchangeStatus)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "session-value"})
		case logoutPath:
			calls.logoutCookie = r.Header.Get("Cookie")
			w.WriteHeader(cmp.Or(logoutStatus, http.StatusNoContent))
		default:
			keys(w, r)
		}
	}))
	return client, calls
}

func TestCreateAPIKeyForUser_EndsSession(t *testing.T) {
	tests := []struct {
		name               string
		exchangeStatus     int
		createStatus       int
		logoutStatus       int
		cancelDuringCreate bool
		wantCalls          []string
		wantErr            bool
	}{
		{
			name:      "after creating the key",
			wantCalls: []string{tokenPath, exchangePath, createPath, logoutPath},
		},
		{
			name:         "when creating the key fails",
			createStatus: http.StatusBadRequest,
			wantCalls:    []string{tokenPath, exchangePath, createPath, logoutPath},
			wantErr:      true,
		},
		{
			name:               "when ctx is cancelled mid-call",
			cancelDuringCreate: true,
			wantCalls:          []string{tokenPath, exchangePath, createPath, logoutPath},
			wantErr:            true,
		},
		{
			name:         "without failing the call when logout fails",
			logoutStatus: http.StatusInternalServerError,
			wantCalls:    []string{tokenPath, exchangePath, createPath, logoutPath},
		},
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

			// Holds the create response so the client can only see the cancellation.
			release := make(chan struct{})
			client, calls := sessionServer(t, tt.exchangeStatus, tt.logoutStatus, func(w http.ResponseWriter, _ *http.Request) {
				if tt.cancelDuringCreate {
					cancel()
					<-release
					return
				}
				if tt.createStatus != 0 {
					w.WriteHeader(tt.createStatus)
					return
				}
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"apiKey":{"id":"key-1"},"token":"key-token"}`))
			})

			key, err := client.CreateAPIKeyForUser(ctx, "user-1", "key", "2030-01-01T00:00:00Z", "", 5)
			close(release)

			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(calls.paths, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", calls.paths, tt.wantCalls)
			}
			if !tt.wantErr && key.Token != "key-token" {
				t.Errorf("token = %q, want key-token", key.Token)
			}
			if len(tt.wantCalls) == 4 && calls.logoutCookie != sessionCookie {
				t.Errorf("logout cookie = %q, want the exchange's session cookie", calls.logoutCookie)
			}
		})
	}
}

func TestDeleteAPIKeyForUser(t *testing.T) {
	tests := []struct {
		name           string
		exchangeStatus int
		deleteStatus   int
		wantCalls      []string
		wantErr        bool
	}{
		{
			name:         "deletes the key in the user's session",
			deleteStatus: http.StatusNoContent,
			wantCalls:    []string{tokenPath, exchangePath, deletePath, logoutPath},
		},
		{
			name:         "treats a key that's already gone as deleted",
			deleteStatus: http.StatusNotFound,
			wantCalls:    []string{tokenPath, exchangePath, deletePath, logoutPath},
		},
		{
			name:         "reports a failed delete and still ends the session",
			deleteStatus: http.StatusBadRequest,
			wantCalls:    []string{tokenPath, exchangePath, deletePath, logoutPath},
			wantErr:      true,
		},
		{
			name:           "reports a failed session exchange",
			exchangeStatus: http.StatusUnauthorized,
			wantCalls:      []string{tokenPath, exchangePath},
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var deleteCookie, deleteMethod string
			client, calls := sessionServer(t, tt.exchangeStatus, 0, func(w http.ResponseWriter, r *http.Request) {
				deleteMethod, deleteCookie = r.Method, r.Header.Get("Cookie")
				w.WriteHeader(tt.deleteStatus)
			})

			err := client.DeleteAPIKeyForUser(t.Context(), "user-1", "key-1", 5)

			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(calls.paths, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", calls.paths, tt.wantCalls)
			}
			if tt.deleteStatus != 0 && (deleteMethod != http.MethodDelete || deleteCookie != sessionCookie) {
				t.Errorf("delete request = %s with cookie %q, want DELETE in the user's session", deleteMethod, deleteCookie)
			}
		})
	}
}
