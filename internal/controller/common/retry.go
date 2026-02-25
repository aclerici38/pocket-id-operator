package common

import (
	"context"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// RetryKubernetesRead retries Kubernetes read operations for transient failures.
// NotFound is retried as well to smooth over short creation-order races during startup.
func RetryKubernetesRead(ctx context.Context, attempts int, fn func() error) error {
	if attempts <= 0 {
		attempts = 1
	}

	backoff := SecretReadRetryInitialBackoff
	var lastErr error

	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return lastErr
			}
			return err
		}

		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err
		if attempt >= attempts || (!apierrors.IsNotFound(err) && !IsTransientKubernetesError(err)) {
			return err
		}

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			if lastErr != nil {
				return lastErr
			}
			return ctx.Err()
		case <-timer.C:
		}

		if backoff < SecretReadRetryMaxBackoff {
			backoff *= 2
			if backoff > SecretReadRetryMaxBackoff {
				backoff = SecretReadRetryMaxBackoff
			}
		}
	}

	return lastErr
}
