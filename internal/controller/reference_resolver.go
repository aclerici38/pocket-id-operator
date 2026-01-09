package controller

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	pocketidv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

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

		if user.Status.UserID == "" {
			return nil, fmt.Errorf("user %s is not ready", ref.Name)
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

		if group.Status.GroupID == "" {
			return nil, fmt.Errorf("user group %s is not ready", ref.Name)
		}

		groupIDs = append(groupIDs, group.Status.GroupID)
	}

	return groupIDs, nil
}
