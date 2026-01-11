package pocketid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRateLimitedTransportIsUsed verifies that a custom transport is actually used by the client.
// This is a regression test for the issue where go-openapi's sync.Once was capturing
// http.DefaultTransport instead of the provided transport.
func TestRateLimitedTransportIsUsed(t *testing.T) {
	transportCalled := false

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"test-id","username":"test","firstName":"Test","lastName":"User","email":"test@example.com","displayName":"Test User","isAdmin":false,"disabled":false,"locale":"en"}`))
	}))
	defer server.Close()

	// Create a rate-limited transport
	rateLimitedTransport := NewRateLimitedTransport(10.0, 5)

	// Wrap it to track calls
	wrappedTransport := &testTransportWrapper{
		Base: rateLimitedTransport,
		onCall: func() {
			transportCalled = true
		},
	}

	// Create client with custom transport
	client, err := NewClient(server.URL, "test-api-key", wrappedTransport)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Make an API call
	ctx := context.Background()
	_, err = client.GetUser(ctx, "test-id")
	if err != nil {
		t.Logf("GetUser error (expected): %v", err)
	}

	// Verify our custom transport was called
	if !transportCalled {
		t.Fatal("Custom transport was not called - rate limiting is being bypassed")
	}
}

// testTransportWrapper wraps a transport and calls a callback when RoundTrip is invoked
type testTransportWrapper struct {
	Base   http.RoundTripper
	onCall func()
}

func (t *testTransportWrapper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.onCall != nil {
		t.onCall()
	}
	return t.Base.RoundTrip(req)
}
