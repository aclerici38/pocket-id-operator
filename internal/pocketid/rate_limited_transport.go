package pocketid

import (
	"fmt"
	"net/http"
	"time"

	"golang.org/x/time/rate"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// RateLimitedRoundTripper wraps an http.RoundTripper with rate limiting
type RateLimitedRoundTripper struct {
	Base    http.RoundTripper
	Limiter *rate.Limiter
}

// RoundTrip implements http.RoundTripper with rate limiting
func (rt *RateLimitedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Reserve a token from the rate limiter
	reservation := rt.Limiter.Reserve()
	if !reservation.OK() {
		return nil, fmt.Errorf("rate limiter reservation failed")
	}

	delay := reservation.Delay()
	if delay > 0 {
		log := logf.Log.WithName("rate-limiter")
		log.V(1).Info("Rate limiting request",
			"delay", delay.String(),
			"method", req.Method,
			"path", req.URL.Path,
		)
		time.Sleep(delay)
	}

	// Execute the request
	resp, err := rt.Base.RoundTrip(req)

	if err == nil && resp.StatusCode == http.StatusTooManyRequests {
		log := logf.Log.WithName("rate-limiter")
		log.Info("Received 429 despite rate limiting",
			"method", req.Method,
			"path", req.URL.Path,
		)
	}

	return resp, err
}

// NewRateLimitedTransport creates a new rate-limited HTTP transport
func NewRateLimitedTransport(qps float64, burst int) http.RoundTripper {
	// Clone the default transport to get sensible defaults
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()

	limiter := rate.NewLimiter(rate.Limit(qps), burst)

	return &RateLimitedRoundTripper{
		Base:    baseTransport,
		Limiter: limiter,
	}
}
