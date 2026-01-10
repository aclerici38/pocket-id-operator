package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pocketidv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

// isResourceReady checks if a resource has the Ready condition set to True
func isResourceReady(conditions []metav1.Condition) bool {
	readyCondition := meta.FindStatusCondition(conditions, "Ready")
	return readyCondition != nil && readyCondition.Status == metav1.ConditionTrue
}

// ResolveUserReferences resolves PocketIDUser references to user IDs
func ResolveUserReferences(
	ctx context.Context,
	c client.Client,
	refs []pocketidv1alpha1.NamespacedUserReference,
	defaultNamespace string,
) ([]string, error) {
	userIDs := make([]string, 0, len(refs))

	for _, ref := range refs {
		if ref.Name == "" {
			return nil, fmt.Errorf("user reference contains an empty name")
		}

		namespace := ref.Namespace
		if namespace == "" {
			namespace = defaultNamespace
		}

		user := &pocketidv1alpha1.PocketIDUser{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.Name}, user); err != nil {
			return nil, fmt.Errorf("get user %s: %w", ref.Name, err)
		}

		if !isResourceReady(user.Status.Conditions) {
			return nil, fmt.Errorf("user %s is not ready (Ready condition not True)", ref.Name)
		}

		if user.Status.UserID == "" {
			return nil, fmt.Errorf("user %s has no UserID in status", ref.Name)
		}

		userIDs = append(userIDs, user.Status.UserID)
	}

	return userIDs, nil
}

// ResolveUserGroupReferences resolves PocketIDUserGroup references to group IDs
func ResolveUserGroupReferences(
	ctx context.Context,
	c client.Client,
	refs []pocketidv1alpha1.NamespacedUserGroupReference,
	defaultNamespace string,
) ([]string, error) {
	groupIDs := make([]string, 0, len(refs))

	for _, ref := range refs {
		if ref.Name == "" {
			return nil, fmt.Errorf("user group reference contains an empty name")
		}

		namespace := ref.Namespace
		if namespace == "" {
			namespace = defaultNamespace
		}

		group := &pocketidv1alpha1.PocketIDUserGroup{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.Name}, group); err != nil {
			return nil, fmt.Errorf("get user group %s: %w", ref.Name, err)
		}

		if !isResourceReady(group.Status.Conditions) {
			return nil, fmt.Errorf("user group %s is not ready (Ready condition not True)", ref.Name)
		}

		if group.Status.GroupID == "" {
			return nil, fmt.Errorf("user group %s has no GroupID in status", ref.Name)
		}

		groupIDs = append(groupIDs, group.Status.GroupID)
	}

	return groupIDs, nil
}
