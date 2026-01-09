package controller

import (
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
)

const defaultResyncInterval = 2 * time.Minute

func applyResync(result ctrl.Result) ctrl.Result {
	if result.RequeueAfter > 0 && result.RequeueAfter < defaultResyncInterval {
		return result
	}
	result.RequeueAfter = defaultResyncInterval
	return result
}
