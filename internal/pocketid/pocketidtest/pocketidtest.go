// Package pocketidtest provides utilities for testing against a fake Pocket-ID API.
package pocketidtest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// NewClient returns a Pocket-ID client whose requests are all served by handler over
// httptest's in-memory network. The server shuts down when t's test ends.
func NewClient(t testing.TB, handler http.Handler) *pocketid.Client {
	t.Helper()
	ts := httptest.NewTestServer(t, handler)
	// Server.URL is only populated by the first Client call.
	hc := ts.Client()
	c, err := pocketid.NewClient(ts.URL, "", pocketid.WithHTTPClient(hc))
	if err != nil {
		t.Fatalf("pocketid.NewClient: %v", err)
	}
	return c
}
