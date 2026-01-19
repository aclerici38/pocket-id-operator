package common

import (
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
)

const DefaultResyncInterval = 2 * time.Minute

func ApplyResync(result ctrl.Result) ctrl.Result {
	if result.RequeueAfter > 0 && result.RequeueAfter < DefaultResyncInterval {
		return result
	}
	result.RequeueAfter = DefaultResyncInterval
	return result
}
