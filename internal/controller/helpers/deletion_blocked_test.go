package helpers

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

// A group can sit terminating indefinitely while the operator refuses to delete
// it, but it is still live in Pocket-ID. Dependents must keep resolving it, or a
// single blocked delete takes down every OIDC client that references the group.
func TestResolveUserGroupReferences_ResolvesBlockedDeletion(t *testing.T) {
	now := metav1.NewTime(time.Now())
	group := &pocketidv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "blocked-group",
			Namespace:         "default",
			Finalizers:        []string{"pocketid.internal/oidc-client-finalizer"},
			DeletionTimestamp: &now,
		},
		Status: pocketidv1alpha1.PocketIDUserGroupStatus{
			GroupID: "group-id",
			Conditions: []metav1.Condition{{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				Reason:             "DeletionBlocked",
				LastTransitionTime: now,
			}},
		},
	}

	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(group).Build()

	ids, err := ResolveUserGroupReferences(
		context.Background(),
		c,
		&fakeUserGroupLookup{},
		[]pocketidv1alpha1.NamespacedUserGroupReference{{Name: group.Name, Namespace: group.Namespace}},
		"default",
	)
	if err != nil {
		t.Fatalf("expected a blocked-deletion group to resolve, got error: %v", err)
	}
	if len(ids) != 1 || ids[0] != "group-id" {
		t.Fatalf("expected [group-id], got %v", ids)
	}
}
