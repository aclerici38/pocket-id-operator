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
