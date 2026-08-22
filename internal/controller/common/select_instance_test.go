package common

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

// SelectInstance decides which Pocket-ID every other reconciler talks to, and it lists
// instances cluster-wide rather than within the resource's namespace. That makes a second
// instance anywhere a global condition: without a selector to narrow it, every selectorless
// resource in the cluster fails to reconcile. These tests pin that behaviour, including the
// cross-namespace case, because it is the constraint the e2e suite is shaped around.

func instanceIn(namespace, name string, labels map[string]string) *pocketidinternalv1alpha1.PocketIDInstance {
	return &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
	}
}

func selector(labels map[string]string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: labels}
}

func TestSelectInstance(t *testing.T) {
	shared := map[string]string{"instance": "shared"}
	other := map[string]string{"instance": "other"}

	for _, tc := range []struct {
		name      string
		instances []*pocketidinternalv1alpha1.PocketIDInstance
		selector  *metav1.LabelSelector
		wantName  string
		wantErr   error
	}{
		{
			name:      "no instances at all",
			instances: nil,
			wantErr:   ErrNoInstance,
		},
		{
			name:      "a single instance is selected without a selector",
			instances: []*pocketidinternalv1alpha1.PocketIDInstance{instanceIn("ns-a", "only", shared)},
			wantName:  "only",
		},
		{
			name: "two instances and no selector is ambiguous",
			instances: []*pocketidinternalv1alpha1.PocketIDInstance{
				instanceIn("ns-a", "first", shared),
				instanceIn("ns-a", "second", other),
			},
			wantErr: ErrMultipleInstance,
		},
		{
			// The list is not namespace-scoped, so an instance in an unrelated namespace
			// still makes a selectorless resource ambiguous. This is why the e2e suite
			// cannot isolate a second instance behind its own namespace.
			name: "instances in different namespaces are still ambiguous",
			instances: []*pocketidinternalv1alpha1.PocketIDInstance{
				instanceIn("ns-a", "first", shared),
				instanceIn("ns-b", "second", other),
			},
			wantErr: ErrMultipleInstance,
		},
		{
			name: "a selector narrows two instances to one",
			instances: []*pocketidinternalv1alpha1.PocketIDInstance{
				instanceIn("ns-a", "first", shared),
				instanceIn("ns-b", "second", other),
			},
			selector: selector(other),
			wantName: "second",
		},
		{
			name: "a selector matching several is still ambiguous",
			instances: []*pocketidinternalv1alpha1.PocketIDInstance{
				instanceIn("ns-a", "first", shared),
				instanceIn("ns-b", "second", shared),
			},
			selector: selector(shared),
			wantErr:  ErrMultipleInstance,
		},
		{
			name:      "a selector matching nothing reports no instance",
			instances: []*pocketidinternalv1alpha1.PocketIDInstance{instanceIn("ns-a", "first", shared)},
			selector:  selector(map[string]string{"instance": "absent"}),
			wantErr:   ErrNoInstance,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(deleteScheme(t))
			for _, instance := range tc.instances {
				builder = builder.WithObjects(instance)
			}

			got, err := SelectInstance(context.Background(), builder.Build(), tc.selector)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error: got %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Name != tc.wantName {
				t.Errorf("selected %q, want %q", got.Name, tc.wantName)
			}
		})
	}
}

// An unparseable selector must be reported as such rather than silently matching
// everything, which would turn a typo into a wrong-instance write.
func TestSelectInstance_InvalidSelector(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(deleteScheme(t)).
		WithObjects(instanceIn("ns-a", "only", nil)).Build()

	bad := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "instance", Operator: "NotAnOperator", Values: []string{"x"}},
		},
	}

	if _, err := SelectInstance(context.Background(), c, bad); err == nil {
		t.Fatal("expected an error for an invalid selector")
	} else if errors.Is(err, ErrNoInstance) || errors.Is(err, ErrMultipleInstance) {
		t.Errorf("invalid selector should not be reported as a count problem: %v", err)
	}
}
