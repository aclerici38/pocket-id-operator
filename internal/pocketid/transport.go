package pocketid

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-openapi/runtime"

	"github.com/aclerici38/pocket-id-go-client/v2/models"
)

const maxErrorBodyBytes = 64 << 10

// responseCapture is what one round trip disclosed, filled in by errorCapturingTransport
// and read by the classifyingTransport call that put it in the request context.
type responseCapture struct {
	statusCode int
	header     http.Header
	body       []byte
}

type captureContextKey struct{}

// errorCapturingTransport takes failed responses off the wire as they go past. It has to
// happen here: go-openapi closes the response body before returning the error
// (client/runtime.go: `defer res.Body.Close()`), and the generated client discards the
// body outright for operations whose swagger declares no default response — every
// /api/apis and /api/api-keys endpoint.
type errorCapturingTransport struct {
	next http.RoundTripper
}

func (t *errorCapturingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(req)
	capture, ok := req.Context().Value(captureContextKey{}).(*responseCapture)
	if err != nil || !ok {
		return resp, err
	}

	capture.statusCode = resp.StatusCode
	capture.header = resp.Header
	if resp.StatusCode < http.StatusBadRequest {
		return resp, nil
	}

	capture.body, _ = io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	_ = resp.Body.Close()
	// Hand the body back unread: operations that do model their error response still
	// decode it themselves.
	resp.Body = io.NopCloser(bytes.NewReader(capture.body))
	return resp, nil
}

// classifyingTransport turns the generated client's errors into *APIError.
type classifyingTransport struct {
	inner runtime.ContextualTransport
}

func (t *classifyingTransport) Submit(operation *runtime.ClientOperation) (any, error) {
	ctx := operation.Context //nolint:staticcheck // the generated client's non-context methods carry it here
	if ctx == nil {
		ctx = context.Background()
	}
	return t.SubmitContext(ctx, operation)
}

func (t *classifyingTransport) SubmitContext(ctx context.Context, operation *runtime.ClientOperation) (any, error) {
	capture := &responseCapture{}
	result, err := t.inner.SubmitContext(context.WithValue(ctx, captureContextKey{}, capture), operation)
	// A refused connection or a DNS failure has no response to classify, and is already as
	// descriptive as it is going to get.
	if err == nil || capture.statusCode == 0 {
		return result, err
	}

	// A body that is not the envelope leaves every field zero.
	var envelope models.GithubComPocketIDPocketIDBackendInternalDtoErrorDto
	_ = json.Unmarshal(capture.body, &envelope)

	requestID := envelope.RequestID
	if requestID == "" {
		requestID = capture.header.Get("X-Request-ID")
	}

	return result, &APIError{
		Operation:  operation.ID,
		StatusCode: capture.statusCode,
		Code:       envelope.Code,
		Message:    envelope.Error,
		RequestID:  requestID,
		Details:    envelope.Details,
		RetryAfter: parseRetryAfter(capture.header.Get("Retry-After")),
		err:        err,
	}
}

// parseRetryAfter reads a Retry-After header. Pocket-ID sends whole seconds, never the
// HTTP-date form the RFC also allows.
func parseRetryAfter(value string) time.Duration {
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}
