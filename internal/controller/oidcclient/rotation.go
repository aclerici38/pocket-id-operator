package oidcclient

import (
	"time"

	"github.com/robfig/cron/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// rotationDue reports whether the elapsed time since the last rotation (or creation,
// if never rotated) has reached the configured interval.
func rotationDue(now, lastRotated, creationTime time.Time, interval time.Duration) bool {
	if interval <= 0 {
		return false
	}
	anchor := lastRotated
	if anchor.IsZero() {
		anchor = creationTime
	}
	if anchor.IsZero() {
		return false
	}
	return now.Sub(anchor) >= interval
}

// withinWindow reports whether now falls inside a recurring maintenance window.
// opens is a standard 5-field cron expression (UTC). The window stays open for
// closesAfter after each cron fire.
func withinWindow(now time.Time, opens string, closesAfter time.Duration) (bool, error) {
	schedule, err := cron.ParseStandard(opens)
	if err != nil {
		return false, err
	}
	// Next() after (now - closesAfter) gives the most recent window open at or after
	// that point. If it is <= now, we are inside the open window.
	windowStart := schedule.Next(now.Add(-closesAfter))
	return !windowStart.After(now), nil
}

// minSpacingOK reports whether enough time has elapsed since the last rotation
// across all clients on the instance. Returns true when minSpacing is zero or
// no global rotation has been recorded yet.
func minSpacingOK(now time.Time, lastGlobal *metav1.Time, minSpacing time.Duration) bool {
	if minSpacing <= 0 || lastGlobal == nil {
		return true
	}
	return now.Sub(lastGlobal.Time) >= minSpacing
}
