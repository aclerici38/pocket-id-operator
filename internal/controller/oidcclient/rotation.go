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
	// deferReason is set when a rotation was owed (its trigger fired) but a downstream gate
	// blocked it: "window_closed", "min_spacing", or "window_error".
	deferReason string
	// lastRotated is the timestamp of the most recent rotation, zero when never rotated.
	lastRotated time.Time
	// anchor is the reference point for the trigger (lastRotated, or creation time when never
	// rotated).
	anchor time.Time
	// interval is the configured rotation interval, zero in window-driven mode.
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

// parseWindow parses a maintenance-window cron expression and validates that closesAfter is
// shorter than the gap between consecutive fires (otherwise the window would never close). opens
// is a standard 5-field cron expression evaluated in the operator's local timezone (set via the
// TZ env var; UTC when unset). The gap is sampled at the first fire after now, matching how the
// window's open/closed state is evaluated.
func parseWindow(now time.Time, opens string, closesAfter time.Duration) (cron.Schedule, error) {
	schedule, err := cron.ParseStandard(opens)
	if err != nil {
		return nil, err
	}
	first := schedule.Next(now)
	gap := schedule.Next(first).Sub(first)
	if closesAfter >= gap {
		return nil, fmt.Errorf("closesAfter (%s) must be shorter than the cron repeat period (%s)", closesAfter, gap)
	}
	return schedule, nil
}

// windowState reports whether now falls inside a recurring maintenance window and when the
// window next opens. The window stays open for closesAfter after each cron fire. nextOpen is the
// next cron fire strictly after now (i.e. the next time the window opens; when currently open,
// this is the following occurrence).
func windowState(now time.Time, opens string, closesAfter time.Duration) (open bool, nextOpen time.Time, err error) {
	schedule, err := parseWindow(now, opens, closesAfter)
	if err != nil {
		return false, time.Time{}, err
	}
	// Next() after (now - closesAfter) gives the most recent window open at or after
	// that point. If it is <= now, we are inside the open window.
	windowStart := schedule.Next(now.Add(-closesAfter))
	return !windowStart.After(now), schedule.Next(now), nil
}

// withinWindow reports whether now falls inside a recurring maintenance window.
func withinWindow(now time.Time, opens string, closesAfter time.Duration) (bool, error) {
	open, _, err := windowState(now, opens, closesAfter)
	return open, err
}

// windowRotationDue evaluates a maintenance window for window-driven rotation (no interval). It
// reports whether now is inside the window (open) and whether a rotation is owed (owed) — i.e. a
// window has opened strictly after the anchor (the last rotation, or creation when never rotated)
// and at or before now. Owed unifies both cases the caller cares about: owed && open means a
// rotation should fire now; owed && !open means an opening was missed and the rotation is waiting
// for the next one. When not owed, the secret has already been rotated for the most recent opening
// (or none has occurred yet), so there is nothing to do.
func windowRotationDue(now, anchor time.Time, opens string, closesAfter time.Duration) (open, owed bool, err error) {
	schedule, err := parseWindow(now, opens, closesAfter)
	if err != nil {
		return false, false, err
	}
	windowStart := schedule.Next(now.Add(-closesAfter))
	open = !windowStart.After(now)
	// A rotation is owed when the next fire after the anchor has already occurred (<= now): that
	// fire is an opening we have not yet rotated for.
	owed = !schedule.Next(anchor).After(now)
	return open, owed, nil
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
