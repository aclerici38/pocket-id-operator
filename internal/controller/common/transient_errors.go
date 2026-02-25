package common

import (
	"context"
	"errors"
	"net"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// IsTransientKubernetesError returns true for Kubernetes API errors that should be retried.
func IsTransientKubernetesError(err error) bool {
	if err == nil {
		return false
	}

	if apierrors.IsTimeout(err) ||
		apierrors.IsServerTimeout(err) ||
		apierrors.IsTooManyRequests(err) ||
		apierrors.IsServiceUnavailable(err) ||
		apierrors.IsInternalError(err) ||
		apierrors.IsUnexpectedServerError(err) ||
		apierrors.IsResourceExpired(err) {
		return true
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() || netErr.Temporary() {
			return true
		}
	}

	msg := strings.ToLower(err.Error())
	retryableFragments := []string{
		"connection refused",
		"no such host",
		"i/o timeout",
		"context deadline exceeded",
		"dial tcp",
		"connection reset by peer",
		"tls handshake timeout",
		"temporary failure in name resolution",
		"eof",
	}
	for _, fragment := range retryableFragments {
		if strings.Contains(msg, fragment) {
			return true
		}
	}

	return false
}

// IsTransientDependencyError returns true when an error is a temporary Kubernetes or Pocket-ID dependency issue.
func IsTransientDependencyError(err error) bool {
	if err == nil {
		return false
	}
	return IsTransientKubernetesError(err) || pocketid.IsTransientError(err)
}

// HandleTransientDependencyError sets a waiting condition and requeues for temporary dependency failures.
func (r *BaseReconciler) HandleTransientDependencyError(
	ctx context.Context,
	obj ConditionedResource,
	err error,
	reason string,
	message string,
) (*ctrl.Result, bool) {
	if !IsTransientDependencyError(err) {
		return nil, false
	}

	if reason == "" {
		reason = "DependencyUnavailable"
	}
	if message == "" {
		message = "Waiting for dependent services to become reachable"
	}

	logf.FromContext(ctx).Info(
		"Dependency is temporarily unavailable, requeuing",
		"reason", reason,
		"error", err.Error(),
	)
	_ = r.SetReadyCondition(ctx, obj, metav1.ConditionFalse, reason, message)
	return &ctrl.Result{RequeueAfter: Requeue}, true
}
