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
	logoutPath   = "/api/webauthn/logout"
)

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

			var calls []string
			var logoutCookie string
			client := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.URL.Path)
				w.Header().Set("Content-Type", "application/json")

				switch r.URL.Path {
				case tokenPath:
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"token":"one-time-token"}`))
				case exchangePath:
					if tt.exchangeStatus != 0 {
						w.WriteHeader(tt.exchangeStatus)
						return
					}
					http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "session-value"})
				case createPath:
					if tt.cancelDuringCreate {
						cancel()
					}
					if tt.createStatus != 0 {
						w.WriteHeader(tt.createStatus)
						return
					}
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"apiKey":{"id":"key-1"},"token":"key-token"}`))
				case logoutPath:
					logoutCookie = r.Header.Get("Cookie")
					w.WriteHeader(cmp.Or(tt.logoutStatus, http.StatusNoContent))
				default:
					t.Errorf("unexpected request to %s", r.URL.Path)
				}
			}))

			key, err := client.CreateAPIKeyForUser(ctx, "user-1", "key", "2030-01-01T00:00:00Z", "", 5)

			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(calls, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", calls, tt.wantCalls)
			}
			if !tt.wantErr && key.Token != "key-token" {
				t.Errorf("token = %q, want key-token", key.Token)
			}
			if len(tt.wantCalls) == 4 && logoutCookie != "session_token=session-value" {
				t.Errorf("logout cookie = %q, want the exchange's session cookie", logoutCookie)
			}
		})
	}
}
