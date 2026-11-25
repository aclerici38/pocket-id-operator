package pocketid

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/aclerici38/pocket-id-go-client/v3/client"
)

func TestClassification(t *testing.T) {
	type check struct {
		name string
		is   func(error) bool
	}
	notFound := check{"IsNotFoundError", IsNotFoundError}
	exists := check{"IsAlreadyExistsError", IsAlreadyExistsError}
	server := check{"IsServerError", IsServerError}
	limited := check{"IsRateLimitedError", IsRateLimitedError}
	all := []check{notFound, exists, server, limited}

	tests := []struct {
		name string
		err  error
		want []check
	}{
		{name: "not found code", err: &APIError{StatusCode: 404, Code: client.CodeUserNotFound}, want: []check{notFound}},
		{name: "conflict code", err: &APIError{StatusCode: 409, Code: client.CodeClientIDAlreadyExists}, want: []check{exists}},
		// A bare 400 must not be adopted as a conflict: that would hide a bad callback URL.
		{name: "validation failure is not a conflict", err: &APIError{StatusCode: 400, Code: client.CodeValidationFailed}},
		{name: "rate limited", err: &APIError{StatusCode: 429, Code: client.CodeRateLimited}, want: []check{limited}},
		// A 404 that is not a missing resource must not read as one.
		{name: "code beats status", err: &APIError{StatusCode: 404, Code: client.CodeSetupNotAvailable}},
		{name: "bare 404", err: &APIError{StatusCode: http.StatusNotFound}, want: []check{notFound}},
		{name: "bare 409", err: &APIError{StatusCode: http.StatusConflict}, want: []check{exists}},
		{name: "bare 400", err: &APIError{StatusCode: http.StatusBadRequest}},
		{name: "bare 500", err: &APIError{StatusCode: http.StatusInternalServerError}, want: []check{server}},
		// Something other than Pocket-ID answering leaves nothing the operator acts on.
		{name: "proxy error page", err: &APIError{StatusCode: http.StatusBadGateway}},
		{name: "wrapped", err: fmt.Errorf("get user: %w", &APIError{StatusCode: 404}), want: []check{notFound}},
		{name: "no response", err: errors.New("connection refused")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, c := range all {
				want := false
				for _, w := range tt.want {
					want = want || w.name == c.name
				}
				if got := c.is(tt.err); got != want {
					t.Errorf("%s = %v, want %v", c.name, got, want)
				}
			}
		})
	}
}

// Pocket-ID commits the client update before it fetches the logo, so these codes have to be
// separable from a failure that rejected the configuration itself.
func TestIsLogoError(t *testing.T) {
	blames := func(field string) map[string]any {
		return map[string]any{"fields": []any{map[string]any{"field": field, "message": "invalid"}}}
	}
	tests := []struct {
		name string
		err  *APIError
		want bool
	}{
		{name: "download failed", err: &APIError{StatusCode: 422, Code: client.CodeLogoDownloadFailed}, want: true},
		{name: "unsupported type", err: &APIError{StatusCode: 422, Code: client.CodeLogoTypeNotSupported}, want: true},
		{name: "too large", err: &APIError{StatusCode: 422, Code: client.CodeLogoTooLarge}, want: true},
		// An unusable URL has no code of its own; the blamed field is the only signal.
		{name: "invalid URL blamed on logoUrl", err: &APIError{StatusCode: 400, Code: client.CodeValidationFailed, Details: blames("logoUrl")}, want: true},
		{name: "invalid URL blamed on darkLogoUrl", err: &APIError{StatusCode: 400, Code: client.CodeValidationFailed, Details: blames("darkLogoUrl")}, want: true},
		{name: "validation failure on another field", err: &APIError{StatusCode: 400, Code: client.CodeValidationFailed, Details: blames("callbackURLs")}},
		{name: "validation failure with no details", err: &APIError{StatusCode: 400, Code: client.CodeValidationFailed}},
		// No error body means no attribution, so the whole update has to be treated as failed.
		{name: "proxy error page", err: &APIError{StatusCode: http.StatusBadGateway}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLogoError(tt.err); got != tt.want {
				t.Errorf("IsLogoError = %v, want %v", got, tt.want)
			}
		})
	}
}
