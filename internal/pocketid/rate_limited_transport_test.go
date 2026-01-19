package pocketid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRateLimitedTransport(t *testing.T) {
	// Track request times
	var requestCount atomic.Int32
	requestTimes := make([]time.Time, 0)
	var mu sync.Mutex

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestTimes = append(requestTimes, time.Now())
		mu.Unlock()
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"test"}`))
	}))
	defer server.Close()

	// Create rate-limited transport: 2 QPS, burst 1
	qps := 2.0
	burst := 1
	transport := NewRateLimitedTransport(qps, burst)

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	// Send 5 requests rapidly
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 5; i++ {
		req, err := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		_ = resp.Body.Close()
	}
	elapsed := time.Since(start)

	// Verify all requests were made
	if requestCount.Load() != 5 {
		t.Errorf("Expected 5 requests, got %d", requestCount.Load())
	}

	// With 2 QPS and 5 requests:
	// Request 1: immediate (uses 1 token)
	// Request 2: wait 0.5s (need 1 token, rate is 2/s = 0.5s per token)
	// Request 3: wait 0.5s
	// Request 4: wait 0.5s
	// Request 5: wait 0.5s
	// Total time should be at least 2 seconds (4 * 0.5s delays)
	minExpectedTime := 2 * time.Second
	if elapsed < minExpectedTime {
		t.Errorf("Rate limiting not working: 5 requests took %v, expected at least %v", elapsed, minExpectedTime)
	}

	// Verify requests were spaced out
	mu.Lock()
	defer mu.Unlock()

	if len(requestTimes) != 5 {
		t.Fatalf("Expected 5 request times, got %d", len(requestTimes))
	}

	for i := 1; i < len(requestTimes); i++ {
		delay := requestTimes[i].Sub(requestTimes[i-1])
		// Each request should be delayed by approximately 0.5s (1/qps)
		// Allow some variance for test execution time
		if delay < 400*time.Millisecond {
			t.Errorf("Request %d was too fast: delay=%v, expected ~500ms", i, delay)
		}
	}

	t.Logf("Rate limiting working correctly: 5 requests took %v", elapsed)
}

func TestRateLimitedTransportBurst(t *testing.T) {
	var requestCount atomic.Int32
	requestTimes := make([]time.Time, 0)
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestTimes = append(requestTimes, time.Now())
		mu.Unlock()
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"test"}`))
	}))
	defer server.Close()

	// Create rate-limited transport: 5 QPS, burst 3
	qps := 5.0
	burst := 3
	transport := NewRateLimitedTransport(qps, burst)

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	// Send 3 requests rapidly (should all go through immediately due to burst)
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 3; i++ {
		req, err := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		_ = resp.Body.Close()
	}
	burstElapsed := time.Since(start)

	// First 3 requests should be very fast (burst allows them)
	if burstElapsed > 500*time.Millisecond {
		t.Errorf("Burst not working: first 3 requests took %v, expected <500ms", burstElapsed)
	}

	// 4th request should be delayed
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	fourthStart := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("4th request failed: %v", err)
	}
	_ = resp.Body.Close()
	fourthDelay := time.Since(fourthStart)

	// 4th request should wait for a token (1/5s = 200ms)
	if fourthDelay < 100*time.Millisecond {
		t.Errorf("4th request wasn't rate limited: delay=%v, expected ~200ms", fourthDelay)
	}

	t.Logf("Burst working: first 3 in %v, 4th delayed by %v", burstElapsed, fourthDelay)
}

func TestClientUsesRateLimitedTransport(t *testing.T) {
	// This test verifies that a Client created with rate-limited transport actually uses it
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)

		// Return appropriate response based on endpoint
		if r.URL.Path == "/api/users" {
			_, _ = w.Write([]byte(`{"data":[],"pagination":{"totalItems":0,"totalPages":0,"currentPage":1,"itemsPerPage":10}}`))
		} else {
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()

	// Create client with rate-limited transport
	qps := 2.0
	burst := 1
	transport := NewRateLimitedTransport(qps, burst)

	client, err := NewClient(server.URL, "test-api-key", transport)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Make multiple API calls
	ctx := context.Background()
	start := time.Now()

	for i := 0; i < 3; i++ {
		_, _ = client.ListUsers(ctx, "")
	}

	elapsed := time.Since(start)

	// With 2 QPS and 3 requests, should take at least 1 second
	minExpectedTime := 1 * time.Second
	if elapsed < minExpectedTime {
		t.Errorf("Rate limiting not applied to Client: 3 requests took %v, expected at least %v", elapsed, minExpectedTime)
	}

	if requestCount.Load() != 3 {
		t.Errorf("Expected 3 requests, got %d", requestCount.Load())
	}

	t.Logf("Client rate limiting working: 3 requests took %v", elapsed)
}
