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
	open, nextOpen, nextClose, err := windowState(now, "0 1 * * *", 4*time.Hour)
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
	// The open window started at 1am today and closes 4h later at 5am.
	wantClose := time.Date(2026, 1, 31, 5, 0, 0, 0, time.UTC)
	if !nextClose.Equal(wantClose) {
		t.Errorf("nextClose = %v, want %v", nextClose, wantClose)
	}
}

func TestWindowState_ClosedReportsUpcomingOpen(t *testing.T) {
	// 1am daily, 4h window: at 6am the window is closed and opens again at 1am next day.
	now := time.Date(2026, 1, 31, 6, 0, 0, 0, time.UTC)
	open, nextOpen, nextClose, err := windowState(now, "0 1 * * *", 4*time.Hour)
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
	// While closed, nextClose is the close of the next window: opens 1am next day, closes 5am.
	wantClose := time.Date(2026, 2, 1, 5, 0, 0, 0, time.UTC)
	if !nextClose.Equal(wantClose) {
		t.Errorf("nextClose = %v, want %v", nextClose, wantClose)
	}
}

func TestWindowState_InvalidCron(t *testing.T) {
	now := time.Date(2026, 1, 31, 2, 0, 0, 0, time.UTC)
	if _, _, _, err := windowState(now, "not a cron", 4*time.Hour); err == nil {
		t.Error("expected error for invalid cron expression")
	}
}

// TestWindowRotationDue pins the window-driven open/owed evaluation against a fixed clock. The
// window opens at 1am daily and stays open 4h (open 1am–5am); the most recent fire relative to the
// test instants is 1am on Jan 31.
func TestWindowRotationDue(t *testing.T) {
	const opens = "0 1 * * *"
	const closesAfter = 4 * time.Hour
	opensAt := time.Date(2026, 1, 31, 1, 0, 0, 0, time.UTC)
	insideWindow := time.Date(2026, 1, 31, 2, 0, 0, 0, time.UTC)
	outsideWindow := time.Date(2026, 1, 31, 6, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		now      time.Time
		anchor   time.Time
		wantOpen bool
		wantOwed bool
		wantErr  bool
	}{
		{name: "open and anchor before the opening is owed", now: insideWindow, anchor: opensAt.Add(-24 * time.Hour), wantOpen: true, wantOwed: true},
		{name: "open but anchor at the opening is not owed", now: insideWindow, anchor: opensAt, wantOpen: true, wantOwed: false},
		{name: "open but anchor after the opening is not owed", now: insideWindow, anchor: opensAt.Add(30 * time.Minute), wantOpen: true, wantOwed: false},
		{name: "closed with a missed opening is owed", now: outsideWindow, anchor: opensAt.Add(-24 * time.Hour), wantOpen: false, wantOwed: true},
		{name: "closed with no opening since anchor is not owed", now: outsideWindow, anchor: opensAt.Add(30 * time.Minute), wantOpen: false, wantOwed: false},
		{name: "zero anchor (never rotated) is owed", now: insideWindow, anchor: time.Time{}, wantOpen: true, wantOwed: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			open, owed, err := windowRotationDue(tc.now, tc.anchor, opens, closesAfter)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if open != tc.wantOpen {
				t.Errorf("open = %v, want %v", open, tc.wantOpen)
			}
			if owed != tc.wantOwed {
				t.Errorf("owed = %v, want %v", owed, tc.wantOwed)
			}
		})
	}
}

func TestWindowRotationDue_InvalidCron(t *testing.T) {
	now := time.Date(2026, 1, 31, 2, 0, 0, 0, time.UTC)
	if _, _, err := windowRotationDue(now, time.Time{}, "not a cron", 4*time.Hour); err == nil {
		t.Error("expected error for invalid cron expression")
	}
}

func TestWindowRotationDue_ClosesAfterTooLong(t *testing.T) {
	// closesAfter (2m) is not shorter than the every-minute repeat period (1m) → error.
	now := time.Date(2026, 1, 31, 2, 0, 0, 0, time.UTC)
	if _, _, err := windowRotationDue(now, time.Time{}, "* * * * *", 2*time.Minute); err == nil {
		t.Error("expected error when closesAfter exceeds the cron repeat period")
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
