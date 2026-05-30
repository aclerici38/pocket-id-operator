package oidcclient

import (
	"hash/fnv"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// rotationPhase returns the rotation phase for a client within the given interval.
// With an explicit offset the offset is taken modulo interval (so an offset >=
// interval still produces a valid phase). With no explicit offset, the phase is
// derived deterministically from a fnv64a hash of namespace/name so clients with
// the same interval stagger across the rotation window without manual coordination.
func rotationPhase(namespace, name string, interval time.Duration, offset *metav1.Duration) time.Duration {
	if interval <= 0 {
		return 0
	}
	intervalNs := interval.Nanoseconds()
	if offset != nil {
		off := offset.Duration.Nanoseconds()
		if off < 0 {
			off = -off
		}
		return time.Duration(off % intervalNs)
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(namespace + "/" + name))
	return time.Duration(int64(h.Sum64() % uint64(intervalNs)))
}

// rotationDue reports whether the client's secret has crossed a fresh rotation
// slot boundary since the last rotation. Slot boundaries align to the Unix epoch
// offset by phase, repeating every interval. When lastRotated is zero (no prior
// rotation recorded), creationTime anchors the calculation so a fresh client
// rotates only after the first slot boundary past its creation.
func rotationDue(now, lastRotated, creationTime time.Time, interval, phase time.Duration) bool {
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
	return slotIndex(now, interval, phase) > slotIndex(anchor, interval, phase)
}

// slotIndex returns the rotation slot index that time t falls into. Slots are
// half-open intervals of width "interval" aligned to (epoch + phase).
func slotIndex(t time.Time, interval, phase time.Duration) int64 {
	if interval <= 0 {
		return 0
	}
	return (t.UnixNano() - int64(phase)) / int64(interval)
}
