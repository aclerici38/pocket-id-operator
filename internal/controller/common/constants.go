package common

import (
	"errors"
	"time"
)

const (
	// Requeue is the standard requeue delay for consistent error handling across controllers
	Requeue = 5 * time.Second

	// DependencyRequeue is used when waiting on referenced resources to become ready.
	DependencyRequeue = 20 * time.Second

	// SecretReadRetryAttempts is the number of attempts for important secret reads.
	SecretReadRetryAttempts = 5

	// SecretReadRetryInitialBackoff is the initial wait between secret read retries.
	SecretReadRetryInitialBackoff = 200 * time.Millisecond

	// SecretReadRetryMaxBackoff caps exponential backoff for secret reads.
	SecretReadRetryMaxBackoff = 2 * time.Second

	// OIDCClientAllowedGroupIndexKey is the index key for OIDC client allowed groups
	OIDCClientAllowedGroupIndexKey = "pocketidoidcclient.allowedGroup"

	// UserGroupUserRefIndexKey is the index key for user group user references
	UserGroupUserRefIndexKey = "pocketidusergroup.userRef"

	// UserGroupAllowedOIDCClientIndexKey is the index key for user group allowed OIDC clients
	UserGroupAllowedOIDCClientIndexKey = "pocketidusergroup.allowedOIDCClient"
)

var (
	// ErrAPIClientNotReady indicates the API client cannot be created yet
	ErrAPIClientNotReady = errors.New("api client not ready")
)
