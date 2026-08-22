//go:build e2e
// +build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// This file reaches the shared Pocket-ID instance over the NodePort that Kind publishes
// on the host (see pocketIDNodePort). Most callers should prefer the typed `pid` client,
// which is the same one the operator uses; the helpers here cover the endpoints that
// client does not wrap — the public app configuration and the OIDC token endpoint — plus
// the handful of assertions that read a raw response body.

// testCtx returns a context bounded by a timeout, so a hung request fails the spec with a
// deadline rather than stalling until Ginkgo's suite timeout.
func testCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

// pocketIDRequest issues an authenticated request against the shared instance and returns
// the response body and status code. It fails the spec only if the request could not be
// made at all; callers decide what to make of the status.
func pocketIDRequest(method, apiPath string, body any) (string, int) {
	GinkgoHelper()

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		Expect(err).NotTo(HaveOccurred(), "encoding request body")
		payload = bytes.NewReader(encoded)
	}

	ctx, cancel := testCtx()
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, pocketIDBaseURL()+apiPath, payload)
	Expect(err).NotTo(HaveOccurred(), "building request for %s", apiPath)
	req.Header.Set("X-API-KEY", staticAPIKey())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	Expect(err).NotTo(HaveOccurred(), "calling %s %s", method, apiPath)
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	Expect(err).NotTo(HaveOccurred(), "reading response from %s", apiPath)
	return string(raw), resp.StatusCode
}

// getFromPocketID returns the raw body of a GET against the Pocket-ID API, and requires
// the call to succeed. Used to assert that operator-managed state really landed in
// Pocket-ID's database.
func getFromPocketID(apiPath string) string {
	GinkgoHelper()
	body, code := pocketIDRequest(http.MethodGet, apiPath, nil)
	Expect(code).To(BeNumerically("<", 300), "GET %s returned %d: %s", apiPath, code, body)
	return body
}

// getStatusFromPocketID returns just the status code of a GET, for callers asserting that
// something is absent rather than reading it.
func getStatusFromPocketID(apiPath string) int {
	GinkgoHelper()
	_, code := pocketIDRequest(http.MethodGet, apiPath, nil)
	return code
}

// deleteFromPocketID removes a resource directly through the API, simulating a deletion
// performed out-of-band — in the UI, or by another cluster.
func deleteFromPocketID(apiPath string) {
	GinkgoHelper()
	body, code := pocketIDRequest(http.MethodDelete, apiPath, nil)
	Expect(code).To(BeNumerically("<", 300), "DELETE %s returned %d: %s", apiPath, code, body)
}

// getAppConfigFieldFromPocketID returns a single field from Pocket-ID's public application
// configuration. The endpoint needs no auth: it is the same payload the login page reads
// before the user has a session. The response is a flat array of {"key","type","value"}
// rather than an object keyed by field name, and values are always strings, so booleans
// come back as "true"/"false".
func getAppConfigFieldFromPocketID(field string) string {
	GinkgoHelper()

	body := getFromPocketID("/api/application-configuration")

	var entries []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	Expect(json.Unmarshal([]byte(body), &entries)).To(Succeed(), "decoding application configuration")

	for _, e := range entries {
		if e.Key == field {
			return e.Value
		}
	}
	return ""
}

// clientSecretAuthResult reports what Pocket-ID makes of a client_id/client_secret pair by
// asking its token endpoint for a client_credentials grant. It answers "ok" when a token
// comes back and the OAuth error code otherwise — "invalid_client" being the one that means
// the secret is not accepted. This is the only way to tell that a secret Pocket-ID still
// lists is actually usable, and that a retired one really stopped working.
func clientSecretAuthResult(clientID, clientSecret string) string {
	GinkgoHelper()

	ctx, cancel := testCtx()
	defer cancel()

	form := url.Values{"grant_type": []string{"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		pocketIDBaseURL()+"/api/oidc/token", strings.NewReader(form.Encode()))
	Expect(err).NotTo(HaveOccurred())
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	Expect(err).NotTo(HaveOccurred(), "calling the token endpoint")
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	Expect(err).NotTo(HaveOccurred())

	var decoded struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	Expect(json.Unmarshal(raw, &decoded)).To(Succeed(),
		"decoding token response (%d): %s", resp.StatusCode, raw)

	if decoded.AccessToken != "" {
		return "ok"
	}
	return decoded.Error
}

func pocketIDUsernameForAPIKey(apiKey string) string {
	GinkgoHelper()

	ctx, cancel := testCtx()
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pocketIDBaseURL()+"/api/users/me", nil)
	Expect(err).NotTo(HaveOccurred())
	req.Header.Set("X-API-KEY", apiKey)

	return usernameFrom(http.DefaultClient.Do(req))
}

// pocketIDUsernameForOneTimeToken redeems a one-time access token and reports who the
// resulting session belongs to. Pocket-ID answers the exchange with an access_token
// cookie, which is then presented as the session.
func pocketIDUsernameForOneTimeToken(token string) string {
	GinkgoHelper()

	ctx, cancel := testCtx()
	defer cancel()

	exchange, err := http.NewRequestWithContext(ctx, http.MethodPost,
		pocketIDBaseURL()+"/api/one-time-access-token/"+token, nil)
	Expect(err).NotTo(HaveOccurred())

	resp, err := http.DefaultClient.Do(exchange)
	Expect(err).NotTo(HaveOccurred(), "redeeming the one-time access token")
	defer func() { _ = resp.Body.Close() }()
	Expect(resp.StatusCode).To(BeNumerically("<", 300), "token exchange returned %d", resp.StatusCode)

	var session *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "access_token" {
			session = c
			break
		}
	}
	Expect(session).NotTo(BeNil(), "the exchange should set an access_token cookie")

	me, err := http.NewRequestWithContext(ctx, http.MethodGet, pocketIDBaseURL()+"/api/users/me", nil)
	Expect(err).NotTo(HaveOccurred())
	me.AddCookie(session)

	return usernameFrom(http.DefaultClient.Do(me))
}

// usernameFrom reads the username out of a /api/users/me response.
func usernameFrom(resp *http.Response, reqErr error) string {
	GinkgoHelper()

	Expect(reqErr).NotTo(HaveOccurred(), "calling /api/users/me")
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	Expect(err).NotTo(HaveOccurred())
	Expect(resp.StatusCode).To(Equal(http.StatusOK),
		"/api/users/me returned %d: %s", resp.StatusCode, body)

	var me struct {
		Username string `json:"username"`
	}
	Expect(json.Unmarshal(body, &me)).To(Succeed(), "decoding /api/users/me")
	return me.Username
}
