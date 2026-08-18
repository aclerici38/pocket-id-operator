// Package pocketid provides a clean wrapper around the Pocket-ID API client.
package pocketid

import (
	"errors"
	"net/http"
	"slices"

	"github.com/go-openapi/runtime"
)

// hasStatus reports whether err carries one of the given HTTP status codes. Operations that
// declare a default response yield a generated per-operation error type rather than
// runtime.APIError; ClientResponseStatus is the interface both satisfy.
func hasStatus(err error, codes ...int) bool {
	var status runtime.ClientResponseStatus
	if !errors.As(err, &status) {
		return false
	}
	return slices.ContainsFunc(codes, status.IsCode)
}

// IsNotFoundError returns true if the error indicates the resource was not found (HTTP 404).
func IsNotFoundError(err error) bool {
	return hasStatus(err, http.StatusNotFound)
}

// IsServerError returns true if the error is an HTTP 500 internal server error.
func IsServerError(err error) bool {
	return hasStatus(err, http.StatusInternalServerError)
}

// IsAlreadyExistsError returns true if the error indicates the resource already exists (HTTP 400 or 409).
// Pocket-ID returns HTTP 400 with "already in use" or "already exists" messages for duplicate resources.
func IsAlreadyExistsError(err error) bool {
	return hasStatus(err, http.StatusBadRequest, http.StatusConflict)
}
