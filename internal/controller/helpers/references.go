package helpers

import (
	"context"
	stderrors "errors"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pocketidv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// ErrUserGroupNotFound marks a reference to a Pocket-ID user group that does not
// exist. It is a spec error rather than a transient failure, so callers can surface
// it distinctly instead of as a generic reconcile error.
var ErrUserGroupNotFound = stderrors.New("user group not found in Pocket-ID")

// UserGroupLookup resolves user groups that are not managed by a PocketIDUserGroup
// in this cluster.
type UserGroupLookup interface {
	ListUserGroups(ctx context.Context, search string) ([]*pocketid.UserGroup, error)
	GetUserGroup(ctx context.Context, id string) (*pocketid.UserGroup, error)
}

// IsResourceReady checks if a resource has the Ready condition set to True
func IsResourceReady(conditions []metav1.Condition) bool {
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

		if !IsResourceReady(user.Status.Conditions) {
			return nil, fmt.Errorf("user %s is not ready (Ready condition not True)", ref.Name)
		}

		if user.Status.UserID == "" {
			return nil, fmt.Errorf("user %s has no UserID in status", ref.Name)
		}

		userIDs = append(userIDs, user.Status.UserID)
	}

	return userIDs, nil
}

// ResolveOIDCClientReferences resolves PocketIDOIDCClient references to client IDs
func ResolveOIDCClientReferences(
	ctx context.Context,
	c client.Client,
	refs []pocketidv1alpha1.NamespacedOIDCClientReference,
	defaultNamespace string,
) ([]string, error) {
	clientIDs := make([]string, 0, len(refs))

	for _, ref := range refs {
		if ref.Name == "" {
			return nil, fmt.Errorf("OIDC client reference contains an empty name")
		}

		namespace := ref.Namespace
		if namespace == "" {
			namespace = defaultNamespace
		}

		oidcClient := &pocketidv1alpha1.PocketIDOIDCClient{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.Name}, oidcClient); err != nil {
			return nil, fmt.Errorf("get OIDC client %s: %w", ref.Name, err)
		}

		if !IsResourceReady(oidcClient.Status.Conditions) {
			return nil, fmt.Errorf("OIDC client %s is not ready (Ready condition not True)", ref.Name)
		}

		if oidcClient.Status.ClientID == "" {
			return nil, fmt.Errorf("OIDC client %s has no ClientID in status", ref.Name)
		}

		clientIDs = append(clientIDs, oidcClient.Status.ClientID)
	}

	return clientIDs, nil
}

// ResolveUserGroupReferences resolves user group references to Pocket-ID group IDs.
// A ref naming a PocketIDUserGroup CR is read from the cluster; a groupName/groupID
// ref names a group directly in Pocket-ID and is resolved through lookup.
func ResolveUserGroupReferences(
	ctx context.Context,
	c client.Client,
	lookup UserGroupLookup,
	refs []pocketidv1alpha1.NamespacedUserGroupReference,
	defaultNamespace string,
) ([]string, error) {
	groupIDs := make([]string, 0, len(refs))

	for _, ref := range refs {
		var id string
		var err error

		switch {
		case ref.GroupID != "":
			id, err = lookupUserGroupByID(ctx, lookup, ref.GroupID)
		case ref.GroupName != "":
			id, err = lookupUserGroupByName(ctx, lookup, ref.GroupName)
		case ref.Name != "":
			id, err = userGroupCRGroupID(ctx, c, ref, defaultNamespace)
		default:
			err = fmt.Errorf("user group reference must set one of name, groupName, or groupID")
		}
		if err != nil {
			return nil, err
		}

		groupIDs = append(groupIDs, id)
	}

	return groupIDs, nil
}

// userGroupCRGroupID returns the Pocket-ID group ID a PocketIDUserGroup CR resolved to.
func userGroupCRGroupID(
	ctx context.Context,
	c client.Client,
	ref pocketidv1alpha1.NamespacedUserGroupReference,
	defaultNamespace string,
) (string, error) {
	namespace := ref.Namespace
	if namespace == "" {
		namespace = defaultNamespace
	}

	group := &pocketidv1alpha1.PocketIDUserGroup{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.Name}, group); err != nil {
		return "", fmt.Errorf("get user group %s: %w", ref.Name, err)
	}

	if !IsResourceReady(group.Status.Conditions) {
		return "", fmt.Errorf("user group %s is not ready (Ready condition not True)", ref.Name)
	}

	if group.Status.GroupID == "" {
		return "", fmt.Errorf("user group %s has no GroupID in status", ref.Name)
	}

	return group.Status.GroupID, nil
}

// lookupUserGroupByName resolves a Pocket-ID group name to its ID. The search is
// server-side and paginated, so only an exact name match is accepted.
func lookupUserGroupByName(ctx context.Context, lookup UserGroupLookup, name string) (string, error) {
	if lookup == nil {
		return "", fmt.Errorf("cannot resolve user group %q by name without a Pocket-ID client", name)
	}

	groups, err := lookup.ListUserGroups(ctx, name)
	if err != nil {
		return "", fmt.Errorf("list user groups matching %q: %w", name, err)
	}

	for _, group := range groups {
		if group.Name == name {
			return group.ID, nil
		}
	}

	return "", fmt.Errorf("%w: no group named %q", ErrUserGroupNotFound, name)
}

// lookupUserGroupByID confirms the group exists. Pocket-ID accepts unknown IDs on the
// allowed-groups write without error, so an unchecked ID would leave the client
// group-restricted with nothing attached while still reporting Ready.
func lookupUserGroupByID(ctx context.Context, lookup UserGroupLookup, id string) (string, error) {
	if lookup == nil {
		return "", fmt.Errorf("cannot resolve user group %q by ID without a Pocket-ID client", id)
	}

	group, err := lookup.GetUserGroup(ctx, id)
	if err != nil {
		if pocketid.IsNotFoundError(err) {
			return "", fmt.Errorf("%w: no group with ID %q", ErrUserGroupNotFound, id)
		}
		return "", fmt.Errorf("get user group %s: %w", id, err)
	}

	return group.ID, nil
}
