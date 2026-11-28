package pocketid

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/aclerici38/pocket-id-go-client/v3/client"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/aclerici38/pocket-id-operator/internal/metrics"
)

// newTestClient returns a client whose requests are all served by handler over httptest's
// in-memory network. It mirrors pocketidtest.NewClient, which this package can't import.
func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	ts := httptest.NewTestServer(t, handler)
	// Server.URL is only populated by the first Client call.
	hc := ts.Client()
	c, err := NewClient(ts.URL, client.WithAPIKey(""), WithHTTPClient(hc))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// SecretPrefix has to agree with Pocket-ID's clientSecretPrefix exactly. The operator matches a
// stored credential against these prefixes to decide what to retire, so a divergence here would
// make it delete the wrong secret rather than fail visibly.
func TestSecretPrefix(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "takes the leading characters", value: "abcdefgh", want: "abcd"},
		{name: "one longer than the prefix", value: "abcde", want: "abcd"},
		{name: "exactly the prefix length is not recorded", value: "abcd", want: ""},
		{name: "shorter than the prefix length", value: "abc", want: ""},
		{name: "empty", value: "", want: ""},
		// Pocket-ID slices bytes too, so a rune-aware "fix" here would silently disagree with it.
		{name: "slices bytes, as Pocket-ID does", value: "√ab", want: "√a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SecretPrefix(tt.value); got != tt.want {
				t.Fatalf("SecretPrefix(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

// A looser test (any "://") would route a mistyped "http://" client ID down the adopt-only
// path, where it waits forever for a client Pocket-ID will never materialize.
func TestLooksLikeCIMDID_RequiresHTTPSScheme(t *testing.T) {
	for id, want := range map[string]bool{
		"https://apps.example.com/myapp/client-metadata.json": true,
		"http://apps.example.com/myapp/client-metadata.json":  false,
		"ftp://apps.example.com/meta.json":                    false,
		"grafana":                                             false,
		"my-client.id_2":                                      false,
	} {
		if got := LooksLikeCIMDID(id); got != want {
			t.Errorf("LooksLikeCIMDID(%q) = %v, want %v", id, got, want)
		}
	}
}

func versionHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"currentVersion":"2.14.0"}`))
}

func getVersion(c *Client) error {
	_, err := client.Decode[client.CurrentVersionDto](c.GetCurrentDeployedVersionOfPocketID(context.Background()))
	return err
}

// TLS-terminating instances are reached over HTTPS with a certificate the system trust store
// does not know, so the caller-supplied config has to reach the transport that performs requests.
func TestWithTLSConfig(t *testing.T) {
	ts := httptest.NewTestServer(t, http.HandlerFunc(versionHandler))
	ts.StartTLS()

	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	// httptest's certificate is issued for example.com, so the handshake only succeeds if both
	// RootCAs and ServerName made it through.
	trusted := &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}

	for name, tt := range map[string]struct {
		cfg     *tls.Config
		wantErr bool
	}{
		"uses the supplied trust store":    {cfg: trusted},
		"nil keeps the system trust store": {wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := NewClient(ts.URL, client.WithAPIKey(""), WithTLSConfig(tt.cfg))
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			if err := getVersion(c); (err != nil) != tt.wantErr {
				t.Fatalf("request error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMetricsTransport_LabelsOperationAndResult(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version/current":
			versionHandler(w, r)
		case "/api/admin/users/gone":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))

	count := func(operation, result string) float64 {
		return testutil.ToFloat64(metrics.PocketIDAPIRequests.WithLabelValues(operation, result))
	}
	before := []float64{
		count("GetCurrentDeployedVersionOfPocketID", "success"),
		count("GetUserByID", "not_found"),
		count("DeleteUserGroup", "error"),
	}

	_ = getVersion(c)
	_ = client.Check(c.GetUserByID(context.Background(), "gone"))
	_ = client.Check(c.DeleteUserGroup(context.Background(), "group"))

	after := []float64{
		count("GetCurrentDeployedVersionOfPocketID", "success"),
		count("GetUserByID", "not_found"),
		count("DeleteUserGroup", "error"),
	}
	for i := range before {
		if after[i] != before[i]+1 {
			t.Errorf("metric %d: got %v, want %v", i, after[i], before[i]+1)
		}
	}
}

func TestWithUserSession_EndsSession(t *testing.T) {
	const (
		tokenPath    = "/api/admin/users/user-1/one-time-access-token"
		exchangePath = "/api/one-time-access-token"
		keysPath     = "/api/api-keys"
		logoutPath   = "/api/webauthn/logout"
	)
	inSession := []string{tokenPath, exchangePath, keysPath, logoutPath}

	tests := []struct {
		name           string
		exchangeStatus int
		logoutStatus   int
		fnErr          bool
		cancelDuringFn bool
		wantCalls      []string
		wantErr        bool
	}{
		{name: "after fn returns", wantCalls: inSession},
		{name: "when fn fails", fnErr: true, wantCalls: inSession, wantErr: true},
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

			var calls []string
			var logoutCookie string
			// Holds the list response so the client can only see the cancellation.
			release := make(chan struct{})
			c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case tokenPath:
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"token":"one-time"}`))
				case exchangePath:
					if tt.exchangeStatus != 0 {
						w.WriteHeader(tt.exchangeStatus)
						return
					}
					http.SetCookie(w, &http.Cookie{Name: "session", Value: "s1", Path: "/"})
					_, _ = w.Write([]byte(`{}`))
				case keysPath:
					if tt.cancelDuringFn {
						cancel()
						<-release
						return
					}
					if tt.fnErr {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					_, _ = w.Write([]byte(`{"data":[],"pagination":{"currentPage":1,"totalPages":1}}`))
				case logoutPath:
					if cookie, err := r.Cookie("session"); err == nil {
						logoutCookie = cookie.Value
					}
					w.WriteHeader(max(tt.logoutStatus, http.StatusNoContent))
				}
			}))

			err := c.WithUserSession(ctx, "user-1", 0, func(session *client.Client) error {
				for _, err := range client.All[client.APIKeyDto](func(page int) (*http.Response, error) {
					return session.ListAPIKeys(ctx, &client.ListAPIKeysParams{PaginationPage: &page})
				}) {
					return err
				}
				return nil
			})
			close(release)

			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(calls, tt.wantCalls) {
				t.Errorf("calls = %v, want %v", calls, tt.wantCalls)
			}
			if len(tt.wantCalls) == len(inSession) && logoutCookie != "s1" {
				t.Errorf("logout cookie = %q, want the exchange's session cookie", logoutCookie)
			}
		})
	}
}

// After a throttled exchange, sessions fail without a request until Retry-After passes.
func TestWithUserSession_WaitsOutRateLimit(t *testing.T) {
	calls := 0
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/one-time-access-token" {
			w.Header().Set("Retry-After", "10")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"Too many requests","code":"rate_limited"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"one-time"}`))
	}))
	fn := func(*client.Client) error { return nil }

	if err := c.WithUserSession(t.Context(), "user-1", 0, fn); !IsRateLimitedError(err) {
		t.Fatalf("first call: got %v, want rate limited", err)
	}
	err := c.WithUserSession(t.Context(), "user-1", 0, fn)
	if !IsRateLimitedError(err) || AsAPIError(err).RetryAfter <= 0 {
		t.Fatalf("second call: got %v, want rate limited with a wait", err)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2 (none after the 429)", calls)
	}
}
