package oidcclient

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRotationPhase_DeterministicForSameInput(t *testing.T) {
	interval := 30 * 24 * time.Hour
	a := rotationPhase("default", "argocd-oidc", interval, nil)
	b := rotationPhase("default", "argocd-oidc", interval, nil)
	if a != b {
		t.Fatalf("phase must be deterministic for the same input: %v vs %v", a, b)
	}
	if a < 0 || a >= interval {
		t.Fatalf("phase must lie in [0, interval): got %v (interval=%v)", a, interval)
	}
}

func TestRotationPhase_StaggersAcrossClients(t *testing.T) {
	interval := 30 * 24 * time.Hour
	names := []string{"argocd-oidc", "harbor-oidc", "grafana-oidc", "vikunja-oidc", "uptime-kuma-oidc"}
	phases := make(map[string]time.Duration, len(names))
	for _, n := range names {
		phases[n] = rotationPhase("platform", n, interval, nil)
	}
	for n, p := range phases {
		if p < 0 || p >= interval {
			t.Errorf("phase for %q out of range: %v (interval=%v)", n, p, interval)
		}
	}
	// All five distinct in a 30-day window is statistically near-certain (fnv64 collisions are rare).
	seen := map[time.Duration]string{}
	for n, p := range phases {
		if other, ok := seen[p]; ok {
			t.Errorf("phase collision between %q and %q at %v", n, other, p)
		}
		seen[p] = n
	}
}

func TestRotationPhase_ExplicitOffsetOverridesHash(t *testing.T) {
	interval := 24 * time.Hour
	want := metav1.Duration{Duration: 6 * time.Hour}
	got := rotationPhase("ns", "name", interval, &want)
	if got != want.Duration {
		t.Fatalf("explicit offset must be honored: got %v, want %v", got, want.Duration)
	}
}

func TestRotationPhase_OffsetModuloInterval(t *testing.T) {
	interval := 24 * time.Hour
	// Offset > interval is wrapped via modulo so the phase still lies in [0, interval).
	off := metav1.Duration{Duration: 50 * time.Hour}
	got := rotationPhase("ns", "name", interval, &off)
	if got != 2*time.Hour {
		t.Fatalf("offset modulo interval: got %v, want %v", got, 2*time.Hour)
	}
}

func TestRotationPhase_ZeroIntervalReturnsZero(t *testing.T) {
	if got := rotationPhase("ns", "name", 0, nil); got != 0 {
		t.Fatalf("zero interval must yield zero phase: %v", got)
	}
}

func TestRotationDue_ZeroIntervalNeverDue(t *testing.T) {
	now := time.Now()
	if rotationDue(now, time.Time{}, now.Add(-time.Hour), 0, 0) {
		t.Fatalf("zero interval must never report due")
	}
}

func TestRotationDue_BeforeBoundaryNotDue(t *testing.T) {
	interval := 30 * 24 * time.Hour
	phase := time.Duration(0)
	// lastRotated at the start of a slot; now still inside the same slot.
	lastRotated := time.Unix(0, slotIndex(time.Now(), interval, phase)*int64(interval)+int64(phase))
	now := lastRotated.Add(interval / 2)
	if rotationDue(now, lastRotated, time.Time{}, interval, phase) {
		t.Fatalf("should not be due mid-slot")
	}
}

func TestRotationDue_PastBoundaryIsDue(t *testing.T) {
	interval := 30 * 24 * time.Hour
	phase := time.Duration(0)
	lastRotated := time.Unix(0, slotIndex(time.Now(), interval, phase)*int64(interval)+int64(phase))
	now := lastRotated.Add(interval + time.Minute)
	if !rotationDue(now, lastRotated, time.Time{}, interval, phase) {
		t.Fatalf("should be due after crossing a slot boundary")
	}
}

func TestRotationDue_AnchorsToCreationTimeWhenLastRotatedZero(t *testing.T) {
	interval := time.Hour
	phase := time.Duration(0)
	creation := time.Unix(0, slotIndex(time.Now(), interval, phase)*int64(interval))
	// Inside the same slot as creation: not due.
	now := creation.Add(interval / 3)
	if rotationDue(now, time.Time{}, creation, interval, phase) {
		t.Fatalf("must not be due within the creation slot")
	}
	// Past the next boundary: due.
	now = creation.Add(interval + time.Minute)
	if !rotationDue(now, time.Time{}, creation, interval, phase) {
		t.Fatalf("must be due after crossing the first boundary past creation")
	}
}

func TestRotationDue_StaggeredClientsDoNotFireTogether(t *testing.T) {
	interval := 24 * time.Hour
	// Two clients in the same namespace; their hash phases differ.
	phaseA := rotationPhase("platform", "argocd-oidc", interval, nil)
	phaseB := rotationPhase("platform", "harbor-oidc", interval, nil)
	if phaseA == phaseB {
		t.Skip("hash collision; staggering nature unobservable for this pair")
	}
	earlier, later := phaseA, phaseB
	if later < earlier {
		earlier, later = later, earlier
	}
	// Construct lastRotated so it sits in slot N for both phases simultaneously,
	// then pick "now" between A's (N+1) boundary and B's (N+1) boundary.
	const N = int64(1000)
	intervalNs := int64(interval)
	lastRotated := time.Unix(0, int64(later)+N*intervalNs)
	now := time.Unix(0, int64(earlier)+(N+1)*intervalNs+int64(later-earlier)/2)
	if !rotationDue(now, lastRotated, time.Time{}, interval, earlier) {
		t.Fatalf("earlier-phase client should be due at %v (phase=%v)", now, earlier)
	}
	if rotationDue(now, lastRotated, time.Time{}, interval, later) {
		t.Fatalf("later-phase client should NOT be due at %v (phase=%v)", now, later)
	}
}
