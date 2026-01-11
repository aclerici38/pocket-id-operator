package controller

import (
	"errors"
	"time"
)

const (
	// Standard requeue delay for consistent error handling across controllers
	Requeue = 5 * time.Second
)

var (
	// ErrAPIClientNotReady indicates the API client cannot be created yet
	ErrAPIClientNotReady = errors.New("api client not ready")
)
