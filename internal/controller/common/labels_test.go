package common

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIsManagedByOperator(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   bool
	}{
		{
			name:   "managed-by label with operator value",
			labels: map[string]string{ManagedByLabelKey: ManagedByLabelValue},
			want:   true,
		},
		{
			name:   "managed-by label among other labels",
			labels: map[string]string{"app": "x", ManagedByLabelKey: ManagedByLabelValue},
			want:   true,
		},
		{
			name:   "nil labels",
			labels: nil,
			want:   false,
		},
		{
			name:   "empty labels",
			labels: map[string]string{},
			want:   false,
		},
		{
			name:   "managed-by label with a different value",
			labels: map[string]string{ManagedByLabelKey: "someone-else"},
			want:   false,
		},
		{
			name:   "unrelated labels only",
			labels: map[string]string{"app": "x", "managed-by-something": ManagedByLabelValue},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &metav1.ObjectMeta{Labels: tt.labels}
			if got := IsManagedByOperator(obj); got != tt.want {
				t.Errorf("IsManagedByOperator(%v) = %v, want %v", tt.labels, got, tt.want)
			}
		})
	}
}
