package oidcclient

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIntervalElapsed_DueWhenIntervalElapsed(t *testing.T) {
	now := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC)
	lastRotated := now.Add(-31 * 24 * time.Hour)
	interval := 30 * 24 * time.Hour
	if !intervalElapsed(now, lastRotated, time.Time{}, interval) {
		t.Error("expected rotation to be due")
	}
}

func TestIntervalElapsed_NotDueWhenIntervalNotElapsed(t *testing.T) {
	now := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC)
	lastRotated := now.Add(-29 * 24 * time.Hour)
	interval := 30 * 24 * time.Hour
	if intervalElapsed(now, lastRotated, time.Time{}, interval) {
		t.Error("expected rotation to not be due")
	}
}

func TestIntervalElapsed_UsesCreationTimeWhenNeverRotated(t *testing.T) {
	now := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC)
	created := now.Add(-31 * 24 * time.Hour)
	interval := 30 * 24 * time.Hour
	if !intervalElapsed(now, time.Time{}, created, interval) {
		t.Error("expected rotation to be due based on creation time")
	}
}

func TestIntervalElapsed_NeverDueWithZeroInterval(t *testing.T) {
	now := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC)
	if intervalElapsed(now, time.Time{}, time.Time{}, 0) {
		t.Error("expected no rotation with zero interval")
	}
}

func TestIntervalElapsed_NeverDueWithBothAnchorsZero(t *testing.T) {
	now := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC)
	if intervalElapsed(now, time.Time{}, time.Time{}, 30*24*time.Hour) {
		t.Error("expected no rotation when no anchor available")
	}
}

func TestWithinWindow_InsideWindow(t *testing.T) {
	// 1am daily window, 4h duration: 2:30am is inside
	now := time.Date(2026, 1, 31, 2, 30, 0, 0, time.UTC)
	ok, err := withinWindow(now, "0 1 * * *", 4*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected to be inside window")
	}
}

func TestWithinWindow_OutsideWindow(t *testing.T) {
	// 1am daily window, 4h duration: 6am is outside
	now := time.Date(2026, 1, 31, 6, 0, 0, 0, time.UTC)
	ok, err := withinWindow(now, "0 1 * * *", 4*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected to be outside window")
	}
}

func TestWithinWindow_AtWindowOpen(t *testing.T) {
	// Exactly at 1am, should be inside
	now := time.Date(2026, 1, 31, 1, 0, 0, 0, time.UTC)
	ok, err := withinWindow(now, "0 1 * * *", 4*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected to be inside window at open time")
	}
}

func TestWithinWindow_InvalidCron(t *testing.T) {
	now := time.Date(2026, 1, 31, 2, 0, 0, 0, time.UTC)
	_, err := withinWindow(now, "not a cron", 4*time.Hour)
	if err == nil {
		t.Error("expected error for invalid cron expression")
	}
}

func TestWindowState_OpenReportsNextOccurrence(t *testing.T) {
	// 1am daily, 4h window: at 2:30am the window is open and the next open is the following 1am.
	now := time.Date(2026, 1, 31, 2, 30, 0, 0, time.UTC)
	open, nextOpen, err := windowState(now, "0 1 * * *", 4*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !open {
		t.Error("expected window to be open")
	}
	want := time.Date(2026, 2, 1, 1, 0, 0, 0, time.UTC)
	if !nextOpen.Equal(want) {
		t.Errorf("nextOpen = %v, want %v", nextOpen, want)
	}
}

func TestWindowState_ClosedReportsUpcomingOpen(t *testing.T) {
	// 1am daily, 4h window: at 6am the window is closed and opens again at 1am next day.
	now := time.Date(2026, 1, 31, 6, 0, 0, 0, time.UTC)
	open, nextOpen, err := windowState(now, "0 1 * * *", 4*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if open {
		t.Error("expected window to be closed")
	}
	want := time.Date(2026, 2, 1, 1, 0, 0, 0, time.UTC)
	if !nextOpen.Equal(want) {
		t.Errorf("nextOpen = %v, want %v", nextOpen, want)
	}
}

func TestWindowState_InvalidCron(t *testing.T) {
	now := time.Date(2026, 1, 31, 2, 0, 0, 0, time.UTC)
	if _, _, err := windowState(now, "not a cron", 4*time.Hour); err == nil {
		t.Error("expected error for invalid cron expression")
	}
}

func TestMinSpacingOK_ZeroSpacing(t *testing.T) {
	now := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC)
	recent := metav1.NewTime(now.Add(-30 * time.Second))
	if !minSpacingOK(now, &recent, 0) {
		t.Error("expected OK when no min spacing configured")
	}
}

func TestMinSpacingOK_NilLastRotated(t *testing.T) {
	now := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC)
	if !minSpacingOK(now, nil, time.Hour) {
		t.Error("expected OK when never rotated globally")
	}
}

func TestMinSpacingOK_SpacingMet(t *testing.T) {
	now := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC)
	last := metav1.NewTime(now.Add(-90 * time.Minute))
	if !minSpacingOK(now, &last, time.Hour) {
		t.Error("expected OK when spacing met")
	}
}

func TestMinSpacingOK_SpacingNotMet(t *testing.T) {
	now := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC)
	last := metav1.NewTime(now.Add(-30 * time.Minute))
	if minSpacingOK(now, &last, time.Hour) {
		t.Error("expected not OK when spacing not met")
	}
}
