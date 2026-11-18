package pocketid

import (
	"cmp"
	"net/http"
	"time"

	"github.com/aclerici38/pocket-id-go-client/v3/client"

	"github.com/aclerici38/pocket-id-operator/internal/metrics"
)

// metricsTransport records the duration and result of every Pocket-ID API call into the
// pocketid_operator_pocketid_api_* metrics, labelled with Pocket-ID's operation name.
type metricsTransport struct {
	next http.RoundTripper
}

func (t metricsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	operation, _ := client.OperationName(req)
	operation = cmp.Or(operation, "unknown")

	start := time.Now()
	resp, err := t.next.RoundTrip(req)
	metrics.PocketIDAPIRequestDuration.WithLabelValues(operation).Observe(time.Since(start).Seconds())

	result := "error"
	switch {
	case err != nil:
	case resp.StatusCode == http.StatusNotFound:
		result = "not_found"
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		result = "success"
	}
	metrics.PocketIDAPIRequests.WithLabelValues(operation, result).Inc()
	return resp, err
}
