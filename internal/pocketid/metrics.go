package pocketid

import (
	"time"

	"github.com/aclerici38/pocket-id-operator/internal/metrics"
)

// recordCall records the duration and result of a Pocket-ID API call into the
// pocketid_operator_pocketid_api_* metrics. Call this immediately after the raw API
// call with the operation name, the error it returned, and the elapsed duration.
//
// Result label mapping:
//   - nil error       -> "success"
//   - IsNotFoundError -> "not_found"
//   - any other error -> "error"
func recordCall(operation string, err error, duration time.Duration) {
	metrics.PocketIDAPIRequestDuration.WithLabelValues(operation).Observe(duration.Seconds())

	resultLabel := "success"
	if err != nil {
		if IsNotFoundError(err) {
			resultLabel = "not_found"
		} else {
			resultLabel = "error"
		}
	}
	metrics.PocketIDAPIRequests.WithLabelValues(operation, resultLabel).Inc()
}
