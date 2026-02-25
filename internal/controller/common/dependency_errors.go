package common

import "strings"

// IsDependencyNotReadyError returns true when reconciliation is blocked on referenced CR readiness.
func IsDependencyNotReadyError(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "is not ready (ready condition not true)") ||
		strings.Contains(msg, "has no userid in status") ||
		strings.Contains(msg, "has no groupid in status") ||
		strings.Contains(msg, "has no clientid in status")
}
