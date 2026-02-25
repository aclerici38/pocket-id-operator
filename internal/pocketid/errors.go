// Package pocketid provides a clean wrapper around the Pocket-ID API client.
package pocketid

import (
	"errors"
	"net/http"

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

// IsServerError returns true if the error is an HTTP 500 internal server error.
func IsServerError(err error) bool {
	var apiErr *runtime.APIError
	if errors.As(err, &apiErr) {
		return apiErr.IsCode(http.StatusInternalServerError)
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
