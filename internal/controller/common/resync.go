package common

import (
	"os"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var ResyncInterval = 2 * time.Minute

func init() {
	if v := os.Getenv("RESYNC_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			ResyncInterval = d
			logf.Log.Info("Using custom resync interval", "interval", d)
		}
	}
}

func ApplyResync(result ctrl.Result) ctrl.Result {
	if result.RequeueAfter > 0 && result.RequeueAfter < ResyncInterval {
		return result
	}
	result.RequeueAfter = ResyncInterval
	return result
}
