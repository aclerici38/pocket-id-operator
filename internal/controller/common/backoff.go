package common

import (
	"time"

	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// MaxRateLimitRequeue keeps an unexpected Retry-After from parking a resource indefinitely.
const MaxRateLimitRequeue = 5 * time.Minute

// ReasonRateLimited is the Ready reason for a reconcile Pocket-ID throttled.
const ReasonRateLimited = "RateLimited"

// RequeueAfterFor returns how long to wait before retrying a failed reconcile. A throttled
// call waits as long as Pocket-ID asked; every other failure keeps the standard delay.
func RequeueAfterFor(err error) time.Duration {
	apiErr := pocketid.AsAPIError(err)
	if apiErr == nil || !pocketid.IsRateLimitedError(err) || apiErr.RetryAfter < Requeue {
		return Requeue
	}
	return min(apiErr.RetryAfter, MaxRateLimitRequeue)
}

// ErrorReason returns the Ready reason for a failed reconcile. A throttled call reports
// ReasonRateLimited rather than reason, so a reconcile Pocket-ID never evaluated isn't
// mistaken for one it rejected.
func ErrorReason(err error, reason string) string {
	if pocketid.IsRateLimitedError(err) {
		return ReasonRateLimited
	}
	return reason
}
