package common

import (
	"time"

	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// MaxRateLimitRequeue keeps an unexpected Retry-After from parking a resource indefinitely.
const MaxRateLimitRequeue = 5 * time.Minute

// RequeueAfterFor returns how long to wait before retrying a failed reconcile. A throttled
// call waits as long as Pocket-ID asked; every other failure keeps the standard delay.
func RequeueAfterFor(err error) time.Duration {
	apiErr := pocketid.AsAPIError(err)
	if apiErr == nil || !pocketid.IsRateLimitedError(err) || apiErr.RetryAfter < Requeue {
		return Requeue
	}
	return min(apiErr.RetryAfter, MaxRateLimitRequeue)
}
