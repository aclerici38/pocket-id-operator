package common

import (
	"math/rand"
	"os"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var ResyncInterval = 2 * time.Minute

// Percentage of ResyncInterval to use as max jitter
var JitterFactor = 0.25

func init() {
	if v := os.Getenv("RESYNC_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			ResyncInterval = d
			logf.Log.Info("Using custom resync interval", "interval", d)
		}
	}
}

// jitter returns a random duration between 0 and maxJitter.
func jitter(maxJitter time.Duration) time.Duration {
	if maxJitter <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(maxJitter)))
}

// ApplyResync sets the RequeueAfter to ResyncInterval with jitter applied.
// Ignores jitter when reconciling due to an error
func ApplyResync(result ctrl.Result) ctrl.Result {
	if result.RequeueAfter > 0 && result.RequeueAfter < ResyncInterval {
		return result
	}
	maxJitter := time.Duration(float64(ResyncInterval) * JitterFactor)
	result.RequeueAfter = ResyncInterval + jitter(maxJitter)
	return result
}
