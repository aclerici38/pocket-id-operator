package oidcclient

import (
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// rotationEval captures the outcome of evaluating whether a client secret rotation should
// fire, with enough detail to drive logging, metrics, and the schedule gauges.
type rotationEval struct {
	// enabled reports whether scheduled rotation is configured and enabled.
	enabled bool
	// due reports whether all gates passed and a rotation should fire now.
	due bool
	// intervalElapsed reports whether the per-client interval gate passed.
	intervalElapsed bool
	// deferReason is set when intervalElapsed is true but a downstream gate blocked the
	// rotation: "window_closed", "min_spacing", or "window_error".
	deferReason string
	// lastRotated is the timestamp of the most recent rotation, zero when never rotated.
	lastRotated time.Time
	// anchor is the reference point for the interval gate (lastRotated, or creation time
	// when never rotated).
	anchor time.Time
	// interval is the configured rotation interval.
	interval time.Duration
}

// nextEligible returns the earliest time the client becomes eligible for rotation
// (anchor + interval). Zero when no anchor or interval is available.
func (e rotationEval) nextEligible() time.Time {
	if e.anchor.IsZero() || e.interval <= 0 {
		return time.Time{}
	}
	return e.anchor.Add(e.interval)
}

// rotationAnchor returns the reference point for interval-based rotation: the last rotation
// time, or the creation time when the secret has never been rotated.
func rotationAnchor(lastRotated, creationTime time.Time) time.Time {
	if !lastRotated.IsZero() {
		return lastRotated
	}
	return creationTime
}

// intervalElapsed reports whether the elapsed time since the last rotation (or creation,
// if never rotated) has reached the configured interval.
func intervalElapsed(now, lastRotated, creationTime time.Time, interval time.Duration) bool {
	if interval <= 0 {
		return false
	}
	anchor := rotationAnchor(lastRotated, creationTime)
	if anchor.IsZero() {
		return false
	}
	return now.Sub(anchor) >= interval
}

// windowState reports whether now falls inside a recurring maintenance window and when the
// window next opens. opens is a standard 5-field cron expression evaluated in the operator's
// local timezone (set via the TZ env var; UTC when unset). The window stays open for
// closesAfter after each cron fire. nextOpen is the next cron fire strictly after now (i.e.
// the next time the window opens; when currently open, this is the following occurrence).
func windowState(now time.Time, opens string, closesAfter time.Duration) (open bool, nextOpen time.Time, err error) {
	schedule, err := cron.ParseStandard(opens)
	if err != nil {
		return false, time.Time{}, err
	}
	first := schedule.Next(now)
	gap := schedule.Next(first).Sub(first)
	if closesAfter >= gap {
		return false, time.Time{}, fmt.Errorf("closesAfter (%s) must be shorter than the cron repeat period (%s)", closesAfter, gap)
	}
	// Next() after (now - closesAfter) gives the most recent window open at or after
	// that point. If it is <= now, we are inside the open window.
	windowStart := schedule.Next(now.Add(-closesAfter))
	return !windowStart.After(now), first, nil
}

// withinWindow reports whether now falls inside a recurring maintenance window.
func withinWindow(now time.Time, opens string, closesAfter time.Duration) (bool, error) {
	open, _, err := windowState(now, opens, closesAfter)
	return open, err
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
