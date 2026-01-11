package controller

import "time"

const (
	// Standard requeue delay for consistent error handling across controllers
	Requeue = 5 * time.Second
)
