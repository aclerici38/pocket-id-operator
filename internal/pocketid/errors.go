// Package pocketid provides a clean wrapper around the Pocket-ID API client.
package pocketid

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/go-openapi/runtime"
)

// IsNotFoundError returns true if the error indicates the resource was not found (HTTP 404).
func IsNotFoundError(err error) bool {
	var apiErr *runtime.APIError
	if errors.As(err, &apiErr) {
		return apiErr.IsCode(http.StatusNotFound)
	}
	return false
}

// IsAlreadyExistsError returns true if the error indicates the resource already exists (HTTP 400 or 409).
// Pocket-ID returns HTTP 400 with "already in use" or "already exists" messages for duplicate resources.
func IsAlreadyExistsError(err error) bool {
	var apiErr *runtime.APIError
	if errors.As(err, &apiErr) {
		return apiErr.IsCode(http.StatusBadRequest) || apiErr.IsCode(http.StatusConflict)
	}
	return false
}

// IsTransientError returns true for temporary/retryable API and network failures.
func IsTransientError(err error) bool {
	if err == nil {
		return false
	}

	var apiErr *runtime.APIError
	if errors.As(err, &apiErr) {
		// 429 + 5xx are generally retryable.
		if apiErr.Code == http.StatusTooManyRequests || apiErr.Code >= http.StatusInternalServerError {
			return true
		}
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() || netErr.Temporary() {
			return true
		}
	}

	msg := strings.ToLower(err.Error())
	retryableFragments := []string{
		"connection refused",
		"no such host",
		"i/o timeout",
		"context deadline exceeded",
		"dial tcp",
		"connection reset by peer",
		"tls handshake timeout",
		"temporary failure in name resolution",
		"eof",
		"you are not signed in",
	}
	for _, fragment := range retryableFragments {
		if strings.Contains(msg, fragment) {
			return true
		}
	}

	return false
}
