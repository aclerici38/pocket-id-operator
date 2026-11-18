package pocketid

import (
	"net/http"
	"slices"

	"github.com/aclerici38/pocket-id-go-client/v3/client"
)

// APIError is a non-2xx response from Pocket-ID.
type APIError = client.APIError

// AsAPIError returns the *APIError in err's chain, or nil if the call never got a response.
var AsAPIError = client.AsAPIError

// classify reports whether err carries one of codes. A code is authoritative: if one is
// present and not in the list the answer is no, whatever the status says. Only a response
// without Pocket-ID's error body, such as a proxy's, falls back to statuses.
func classify(err error, codes []client.Code, statuses ...int) bool {
	apiErr := AsAPIError(err)
	if apiErr == nil {
		return false
	}
	if apiErr.Code != "" {
		return slices.Contains(codes, apiErr.Code)
	}
	return slices.Contains(statuses, apiErr.StatusCode)
}

// setup_not_available also answers 404, but means the setup endpoint is closed rather than
// a managed resource missing.
var notFoundCodes = []client.Code{
	client.CodeNotFound,
	client.CodeUserNotFound,
	client.CodeAPIKeyNotFound,
	client.CodeImageNotFound,
}

var alreadyExistsCodes = []client.Code{
	client.CodeAlreadyInUse,
	client.CodeClientIDAlreadyExists,
}

var logoCodes = []client.Code{
	client.CodeLogoDownloadFailed,
	client.CodeLogoTypeNotSupported,
	client.CodeLogoTooLarge,
}

// IsLogoError reports a failure Pocket-ID blames on a logo URL rather than on the client
// configuration, which it has already committed by the time it fetches the logo. A URL it
// rejects outright — not http/https, no host, a private address — is reported as a plain
// validation failure, so that case is recognised by the field it names instead of by a code.
func IsLogoError(err error) bool {
	if classify(err, logoCodes) {
		return true
	}
	apiErr := AsAPIError(err)
	return apiErr != nil && apiErr.Code == client.CodeValidationFailed &&
		apiErr.HasFieldError("logoUrl", "darkLogoUrl")
}

func IsNotFoundError(err error) bool {
	return classify(err, notFoundCodes, http.StatusNotFound)
}

func IsServerError(err error) bool {
	return classify(err, []client.Code{client.CodeInternal}, http.StatusInternalServerError)
}

// IsAlreadyExistsError reports a uniqueness conflict. The status fallback is 409 only: a
// bare 400 is a validation failure, and adopting an existing resource in response to one
// would hide a bad callback URL or an out-of-range token duration.
func IsAlreadyExistsError(err error) bool {
	return classify(err, alreadyExistsCodes, http.StatusConflict)
}

// IsRateLimitedError pairs with AsAPIError().RetryAfter to back off for as long as
// Pocket-ID asked.
func IsRateLimitedError(err error) bool {
	return classify(err, []client.Code{client.CodeRateLimited}, http.StatusTooManyRequests)
}
