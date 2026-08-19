// Package pocketid provides a clean wrapper around the Pocket-ID API client.
package pocketid

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-openapi/runtime"

	"github.com/aclerici38/pocket-id-go-client/v2/models"
)

// APIError is a failed Pocket-ID call carrying the structured error envelope:
//
//	{"error": "...", "code": "already_in_use", "details": {...}, "request_id": "..."}
type APIError struct {
	Operation  string
	StatusCode int
	// Code is empty when something other than Pocket-ID answered — a proxy, an ingress
	// controller — and classification falls back to StatusCode.
	Code    models.ApperrorCode
	Message string
	// RequestID matches the entry in Pocket-ID's own logs.
	RequestID string
	// Details is the envelope's extra context, e.g. {"property": "email"}.
	Details map[string]any
	// RetryAfter is set only on rate-limited responses.
	RetryAfter time.Duration

	// err is kept so errors.As still finds the generated response types underneath.
	err error
}

// Error renders as "[PostAPIOidcClients] status 409: Client ID is already in use
// (code client_id_already_exists, request_id req-42)". The request ID goes in the message
// so it reaches both the operator's logs and the resource's Ready condition.
func (e *APIError) Error() string {
	message := e.Message
	if message == "" && e.err != nil {
		message = e.err.Error()
	}

	var attrs []string
	if e.Code != "" {
		attrs = append(attrs, "code "+string(e.Code))
	}
	if e.RequestID != "" {
		attrs = append(attrs, "request_id "+e.RequestID)
	}

	text := fmt.Sprintf("[%s] status %d: %s", e.Operation, e.StatusCode, message)
	if len(attrs) > 0 {
		text += " (" + strings.Join(attrs, ", ") + ")"
	}
	return text
}

func (e *APIError) Unwrap() error { return e.err }

// AsAPIError returns the *APIError in err's chain, or nil if the call never got a response.
func AsAPIError(err error) *APIError {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return nil
}

// classify reports whether err carries one of codes. A code is authoritative: if one is
// present and not in the list the answer is no, whatever the status says. Only an
// envelope-less failure falls back to fallbackStatuses.
func classify(err error, codes []models.ApperrorCode, fallbackStatuses ...int) bool {
	if apiErr := AsAPIError(err); apiErr != nil && apiErr.Code != "" {
		return slices.Contains(codes, apiErr.Code)
	}
	var status runtime.ClientResponseStatus
	return errors.As(err, &status) && slices.ContainsFunc(fallbackStatuses, status.IsCode)
}

// setup_not_available also answers 404, but means the setup endpoint is closed rather than
// a managed resource missing.
var notFoundCodes = []models.ApperrorCode{
	models.ApperrorCodeNotFound,
	models.ApperrorCodeUserNotFound,
	models.ApperrorCodeAPIKeyNotFound,
	models.ApperrorCodeImageNotFound,
}

var alreadyExistsCodes = []models.ApperrorCode{
	models.ApperrorCodeAlreadyInUse,
	models.ApperrorCodeClientIDAlreadyExists,
}

var validationCodes = []models.ApperrorCode{
	models.ApperrorCodeValidationFailed,
	models.ApperrorCodeInvalidRequestBody,
	models.ApperrorCodeOidcInvalidCallbackURL,
	models.ApperrorCodeReservedClaim,
	models.ApperrorCodeDuplicateClaim,
	models.ApperrorCodeInvalidAPIKeyExpiration,
}

func IsNotFoundError(err error) bool {
	return classify(err, notFoundCodes, http.StatusNotFound)
}

func IsServerError(err error) bool {
	return classify(err, []models.ApperrorCode{models.ApperrorCodeInternalError}, http.StatusInternalServerError)
}

// IsAlreadyExistsError reports a uniqueness conflict. The status fallback is 409 only: a
// bare 400 is a validation failure, and adopting an existing resource in response to one
// would hide a bad callback URL or an out-of-range token duration.
func IsAlreadyExistsError(err error) bool {
	return classify(err, alreadyExistsCodes, http.StatusConflict)
}

// IsValidationError reports a request Pocket-ID rejected on its contents. Retrying is
// pointless until the resource spec changes.
func IsValidationError(err error) bool {
	return classify(err, validationCodes, http.StatusBadRequest)
}

// IsRateLimitedError pairs with AsAPIError().RetryAfter to back off for as long as
// Pocket-ID asked.
func IsRateLimitedError(err error) bool {
	return classify(err, []models.ApperrorCode{models.ApperrorCodeRateLimited}, http.StatusTooManyRequests)
}
