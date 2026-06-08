package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestSetOIDCClientRotationEnabled(t *testing.T) {
	const ns, name = "test-ns", "rot-enabled"
	t.Cleanup(func() { DeleteOIDCClientRotationMetrics(ns, name) })

	SetOIDCClientRotationEnabled(ns, name, true)
	if got := testutil.ToFloat64(OIDCClientRotationEnabled.WithLabelValues(ns, name)); got != 1 {
		t.Errorf("enabled gauge = %v, want 1", got)
	}

	SetOIDCClientRotationEnabled(ns, name, false)
	if got := testutil.ToFloat64(OIDCClientRotationEnabled.WithLabelValues(ns, name)); got != 0 {
		t.Errorf("enabled gauge = %v, want 0", got)
	}
}

func TestSetOIDCClientRotationSchedule_SkipsNonPositive(t *testing.T) {
	const ns, name = "test-ns", "rot-sched"
	t.Cleanup(func() { DeleteOIDCClientRotationMetrics(ns, name) })

	// lastUnix is 0 (never rotated) → that gauge must not be written.
	SetOIDCClientRotationSchedule(ns, name, 3600, 0, 1_700_000_000)

	if got := testutil.ToFloat64(OIDCClientRotationIntervalSeconds.WithLabelValues(ns, name)); got != 3600 {
		t.Errorf("interval gauge = %v, want 3600", got)
	}
	if got := testutil.ToFloat64(OIDCClientNextRotationTimestamp.WithLabelValues(ns, name)); got != 1_700_000_000 {
		t.Errorf("next gauge = %v, want 1700000000", got)
	}
	if c := testutil.CollectAndCount(OIDCClientLastRotationTimestamp); c != 0 {
		t.Errorf("last-rotation gauge series = %d, want 0 (skipped)", c)
	}
}

func TestDeleteOIDCClientRotationSchedule_KeepsEnabled(t *testing.T) {
	const ns, name = "test-ns", "rot-disable"
	t.Cleanup(func() { DeleteOIDCClientRotationMetrics(ns, name) })

	SetOIDCClientRotationEnabled(ns, name, false)
	SetOIDCClientRotationSchedule(ns, name, 3600, 1_699_000_000, 1_700_000_000)

	DeleteOIDCClientRotationSchedule(ns, name)

	if c := testutil.CollectAndCount(OIDCClientRotationIntervalSeconds); c != 0 {
		t.Errorf("interval series = %d, want 0 after schedule delete", c)
	}
	// enabled=0 must survive so the dashboard still reports the client as not rotating.
	if c := testutil.CollectAndCount(OIDCClientRotationEnabled); c != 1 {
		t.Errorf("enabled series = %d, want 1 (kept)", c)
	}
}

func TestInitOIDCClientRotationCounters_SeedsZeroSeries(t *testing.T) {
	const ns, name = "test-ns", "rot-init"
	t.Cleanup(func() { OIDCClientSecretRotations.Reset() })

	InitOIDCClientRotationCounters(ns, name)

	// Every result/trigger combination must exist at 0 so a first rotation is a visible 0→1 step.
	if c := testutil.CollectAndCount(OIDCClientSecretRotations); c != len(rotationResults)*len(rotationTriggers) {
		t.Errorf("seeded series = %d, want %d", c, len(rotationResults)*len(rotationTriggers))
	}
	for _, result := range rotationResults {
		for _, trigger := range rotationTriggers {
			if got := testutil.ToFloat64(OIDCClientSecretRotations.WithLabelValues(ns, name, result, trigger)); got != 0 {
				t.Errorf("counter[%s/%s] = %v, want 0", result, trigger, got)
			}
		}
	}

	// Re-seeding must not clobber an already-incremented series.
	OIDCClientSecretRotations.WithLabelValues(ns, name, "success", "manual").Inc()
	InitOIDCClientRotationCounters(ns, name)
	if got := testutil.ToFloat64(OIDCClientSecretRotations.WithLabelValues(ns, name, "success", "manual")); got != 1 {
		t.Errorf("counter after re-init = %v, want 1 (Add(0) must be a no-op)", got)
	}
}

func TestDeleteOIDCClientRotationMetrics_ClearsAllGauges(t *testing.T) {
	const ns, name = "test-ns", "rot-delete"

	SetOIDCClientRotationEnabled(ns, name, true)
	SetOIDCClientRotationSchedule(ns, name, 3600, 1_699_000_000, 1_700_000_000)

	DeleteOIDCClientRotationMetrics(ns, name)

	// All four gauges should have no series left. Don't call ToFloat64/WithLabelValues here,
	// as that would re-create the series at 0 and defeat the assertion.
	for n, c := range map[string]int{
		"enabled":  testutil.CollectAndCount(OIDCClientRotationEnabled),
		"interval": testutil.CollectAndCount(OIDCClientRotationIntervalSeconds),
		"last":     testutil.CollectAndCount(OIDCClientLastRotationTimestamp),
		"next":     testutil.CollectAndCount(OIDCClientNextRotationTimestamp),
	} {
		if c != 0 {
			t.Errorf("%s series = %d, want 0 after delete", n, c)
		}
	}
}
