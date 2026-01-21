package common

import (
	"errors"
	"time"
)

const (
	// Requeue is the standard requeue delay for consistent error handling across controllers
	Requeue = 5 * time.Second

	// OIDCClientAllowedGroupIndexKey is the index key for OIDC client allowed groups
	OIDCClientAllowedGroupIndexKey = "pocketidoidcclient.allowedGroup"

	// UserGroupUserRefIndexKey is the index key for user group user references
	UserGroupUserRefIndexKey = "pocketidusergroup.userRef"
)

var (
	// ErrAPIClientNotReady indicates the API client cannot be created yet
	ErrAPIClientNotReady = errors.New("api client not ready")
)
