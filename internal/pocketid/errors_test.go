package pocketid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-openapi/runtime"

	"github.com/aclerici38/pocket-id-go-client/v2/models"
)

// errorEnvelope is the JSON shape pocket-id returns for every failure.
type errorEnvelope struct {
	Error     string         `json:"error"`
	Code      string         `json:"code"`
	Details   map[string]any `json:"details,omitempty"`
	RequestID string         `json:"request_id"`
}

// envelopeServer answers every request with the given status and envelope.
func envelopeServer(t *testing.T, status int, envelope errorEnvelope, headers map[string]string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", envelope.RequestID)
		for name, value := range headers {
			w.Header().Set(name, value)
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func newTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	client, err := NewClient(baseURL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// Operations that declare a default response decode the envelope themselves, so the code
// has to survive the generated response type.
func TestAPIError_TypedDefaultResponse(t *testing.T) {
	ts := envelopeServer(t, http.StatusConflict, errorEnvelope{
		Error:     "Email is already in use",
		Code:      string(models.ApperrorCodeAlreadyInUse),
		Details:   map[string]any{"property": "email"},
		RequestID: "req-typed",
	}, nil)

	_, err := newTestClient(t, ts.URL).CreateUser(context.Background(), UserInput{Username: "someone"})
	if err == nil {
		t.Fatal("CreateUser: expected an error")
	}

	apiErr := AsAPIError(err)
	if apiErr == nil {
		t.Fatalf("AsAPIError: got nil for %v", err)
	}
	if apiErr.Code != models.ApperrorCodeAlreadyInUse {
		t.Errorf("Code: got %q, want %q", apiErr.Code, models.ApperrorCodeAlreadyInUse)
	}
	if apiErr.StatusCode != http.StatusConflict {
		t.Errorf("StatusCode: got %d, want %d", apiErr.StatusCode, http.StatusConflict)
	}
	if apiErr.RequestID != "req-typed" {
		t.Errorf("RequestID: got %q, want %q", apiErr.RequestID, "req-typed")
	}
	if apiErr.Message != "Email is already in use" {
		t.Errorf("Message: got %q", apiErr.Message)
	}
	if got := apiErr.Details["property"]; got != "email" {
		t.Errorf("Details[property]: got %v, want email", got)
	}
	if !IsAlreadyExistsError(err) {
		t.Error("IsAlreadyExistsError: got false, want true")
	}
}

// The /api/apis endpoints declare no default response, so the client discards the body and
// hands back a bare status. The envelope has to come off the wire instead.
func TestAPIError_UntypedResponse(t *testing.T) {
	ts := envelopeServer(t, http.StatusNotFound, errorEnvelope{
		Error:     "Resource not found",
		Code:      string(models.ApperrorCodeNotFound),
		RequestID: "req-untyped",
	}, nil)

	_, err := newTestClient(t, ts.URL).GetAPI(context.Background(), "missing")
	if err == nil {
		t.Fatal("GetAPI: expected an error")
	}

	apiErr := AsAPIError(err)
	if apiErr == nil {
		t.Fatalf("AsAPIError: got nil for %v", err)
	}
	if apiErr.Code != models.ApperrorCodeNotFound {
		t.Errorf("Code: got %q, want %q", apiErr.Code, models.ApperrorCodeNotFound)
	}
	if apiErr.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode: got %d, want %d", apiErr.StatusCode, http.StatusNotFound)
	}
	if apiErr.RequestID != "req-untyped" {
		t.Errorf("RequestID: got %q, want %q", apiErr.RequestID, "req-untyped")
	}
	if !IsNotFoundError(err) {
		t.Error("IsNotFoundError: got false, want true")
	}
	if apiErr.Operation != "GetAPIApisID" {
		t.Errorf("Operation: got %q, want GetAPIApisID", apiErr.Operation)
	}
}

// A rejected callback URL or an out-of-range token duration is a 400; treating one as a
// conflict would send it down the adopt path.
func TestValidationFailureIsNotAConflict(t *testing.T) {
	ts := envelopeServer(t, http.StatusBadRequest, errorEnvelope{
		Error:     "Callback URL is invalid",
		Code:      string(models.ApperrorCodeValidationFailed),
		RequestID: "req-validation",
	}, nil)

	_, err := newTestClient(t, ts.URL).CreateOIDCClient(context.Background(), OIDCClientInput{Name: "app"})
	if err == nil {
		t.Fatal("CreateOIDCClient: expected an error")
	}
	if IsAlreadyExistsError(err) {
		t.Error("IsAlreadyExistsError: got true for a validation failure, want false")
	}
	if !IsValidationError(err) {
		t.Error("IsValidationError: got false, want true")
	}
}

// Failures with no envelope classify on their status alone.
func TestBareStatusFallback(t *testing.T) {
	notFound := runtime.NewAPIError("op", nil, http.StatusNotFound)
	if !IsNotFoundError(notFound) {
		t.Error("IsNotFoundError: got false for a bare 404, want true")
	}

	conflict := runtime.NewAPIError("op", nil, http.StatusConflict)
	if !IsAlreadyExistsError(conflict) {
		t.Error("IsAlreadyExistsError: got false for a bare 409, want true")
	}

	badRequest := runtime.NewAPIError("op", nil, http.StatusBadRequest)
	if IsAlreadyExistsError(badRequest) {
		t.Error("IsAlreadyExistsError: got true for a bare 400, want false")
	}

	serverError := runtime.NewAPIError("op", nil, http.StatusInternalServerError)
	if !IsServerError(serverError) {
		t.Error("IsServerError: got false for a bare 500, want true")
	}
}

// A 404 that is not a missing resource must not read as one.
func TestCodeBeatsStatus(t *testing.T) {
	ts := envelopeServer(t, http.StatusNotFound, errorEnvelope{
		Error:     "Initial setup is not available",
		Code:      string(models.ApperrorCodeSetupNotAvailable),
		RequestID: "req-setup",
	}, nil)

	_, err := newTestClient(t, ts.URL).GetAPI(context.Background(), "whatever")
	if err == nil {
		t.Fatal("GetAPI: expected an error")
	}
	if IsNotFoundError(err) {
		t.Error("IsNotFoundError: got true for setup_not_available, want false")
	}
}

// Pocket-ID rate limits the whole /api group and says how long to wait.
func TestRateLimited(t *testing.T) {
	ts := envelopeServer(t, http.StatusTooManyRequests, errorEnvelope{
		Error:     "Too many requests",
		Code:      string(models.ApperrorCodeRateLimited),
		RequestID: "req-limited",
	}, map[string]string{"Retry-After": "7"})

	_, err := newTestClient(t, ts.URL).GetUser(context.Background(), "someone")
	if err == nil {
		t.Fatal("GetUser: expected an error")
	}
	if !IsRateLimitedError(err) {
		t.Error("IsRateLimitedError: got false, want true")
	}
	if delay := AsAPIError(err).RetryAfter; delay != 7*time.Second {
		t.Errorf("RetryAfter: got %v, want 7s", delay)
	}
}

// Something other than pocket-id answering leaves no envelope to classify on.
func TestNonEnvelopeErrorPage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html><body>502 Bad Gateway</body></html>"))
	}))
	t.Cleanup(ts.Close)

	_, err := newTestClient(t, ts.URL).GetUserGroup(context.Background(), "group")
	if err == nil {
		t.Fatal("GetUserGroup: expected an error")
	}
	apiErr := AsAPIError(err)
	if apiErr == nil {
		t.Fatalf("AsAPIError: got nil for %v", err)
	}
	if apiErr.Code != "" {
		t.Errorf("Code: got %q, want empty", apiErr.Code)
	}
	if apiErr.StatusCode != http.StatusBadGateway {
		t.Errorf("StatusCode: got %d, want %d", apiErr.StatusCode, http.StatusBadGateway)
	}
	if IsNotFoundError(err) || IsAlreadyExistsError(err) || IsServerError(err) {
		t.Error("a 502 from a proxy should not classify as anything the operator acts on")
	}
}

// The request ID has to reach the operator's logs, which read the error's message.
func TestErrorMessageCarriesRequestID(t *testing.T) {
	apiErr := &APIError{
		Operation:  "PostAPIOidcClients",
		StatusCode: http.StatusConflict,
		Code:       models.ApperrorCodeClientIDAlreadyExists,
		Message:    "Client ID is already in use",
		RequestID:  "req-42",
	}
	want := "[PostAPIOidcClients] status 409: Client ID is already in use (code client_id_already_exists, request_id req-42)"
	if got := apiErr.Error(); got != want {
		t.Errorf("Error():\n got %q\nwant %q", got, want)
	}
}
