package usergroup

import (
	"context"
	"testing"

	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// mockPocketIDUserGroupClient is a mock implementation for testing user group operations
type mockPocketIDUserGroupClient struct {
	listUserGroupsFunc              func(ctx context.Context, search string) ([]*pocketid.UserGroup, error)
	createUserGroupFunc             func(ctx context.Context, name, friendlyName string) (*pocketid.UserGroup, error)
	getUserGroupFunc                func(ctx context.Context, id string) (*pocketid.UserGroup, error)
	updateUserGroupFunc             func(ctx context.Context, id, name, friendlyName string) (*pocketid.UserGroup, error)
	updateUserGroupCustomClaimsFunc func(ctx context.Context, id string, claims []pocketid.CustomClaim) ([]pocketid.CustomClaim, error)
	updateUserGroupUsersFunc        func(ctx context.Context, id string, userIDs []string) error
}

func (m *mockPocketIDUserGroupClient) ListUserGroups(ctx context.Context, search string) ([]*pocketid.UserGroup, error) {
	if m.listUserGroupsFunc != nil {
		return m.listUserGroupsFunc(ctx, search)
	}
	return nil, nil
}

func (m *mockPocketIDUserGroupClient) CreateUserGroup(ctx context.Context, name, friendlyName string) (*pocketid.UserGroup, error) {
	if m.createUserGroupFunc != nil {
		return m.createUserGroupFunc(ctx, name, friendlyName)
	}
	return &pocketid.UserGroup{
		ID:           "new-group-id",
		Name:         name,
		FriendlyName: friendlyName,
	}, nil
}

func (m *mockPocketIDUserGroupClient) GetUserGroup(ctx context.Context, id string) (*pocketid.UserGroup, error) {
	if m.getUserGroupFunc != nil {
		return m.getUserGroupFunc(ctx, id)
	}
	return nil, nil
}

func (m *mockPocketIDUserGroupClient) UpdateUserGroup(ctx context.Context, id, name, friendlyName string) (*pocketid.UserGroup, error) {
	if m.updateUserGroupFunc != nil {
		return m.updateUserGroupFunc(ctx, id, name, friendlyName)
	}
	return &pocketid.UserGroup{
		ID:           id,
		Name:         name,
		FriendlyName: friendlyName,
	}, nil
}

func (m *mockPocketIDUserGroupClient) UpdateUserGroupCustomClaims(ctx context.Context, id string, claims []pocketid.CustomClaim) ([]pocketid.CustomClaim, error) {
	if m.updateUserGroupCustomClaimsFunc != nil {
		return m.updateUserGroupCustomClaimsFunc(ctx, id, claims)
	}
	return claims, nil
}

func (m *mockPocketIDUserGroupClient) UpdateUserGroupUsers(ctx context.Context, id string, userIDs []string) error {
	if m.updateUserGroupUsersFunc != nil {
		return m.updateUserGroupUsersFunc(ctx, id, userIDs)
	}
	return nil
}

func TestFindExistingUserGroup_NoMatch(t *testing.T) {
	ctx := context.Background()
	reconciler := &Reconciler{}

	mockClient := &mockPocketIDUserGroupClient{
		listUserGroupsFunc: func(ctx context.Context, search string) ([]*pocketid.UserGroup, error) {
			return []*pocketid.UserGroup{}, nil
		},
	}

	existingGroup, err := reconciler.FindExistingUserGroup(ctx, mockClient, "newgroup")
	if err != nil {
		t.Fatalf("FindExistingUserGroup returned unexpected error: %v", err)
	}
	if existingGroup != nil {
		t.Fatalf("expected no existing group, got: %+v", existingGroup)
	}
}

func TestFindExistingUserGroup_MatchByName(t *testing.T) {
	ctx := context.Background()
	reconciler := &Reconciler{}

	expectedGroup := &pocketid.UserGroup{
		ID:           "existing-group-id",
		Name:         "admins",
		FriendlyName: "Administrators",
	}

	mockClient := &mockPocketIDUserGroupClient{
		listUserGroupsFunc: func(ctx context.Context, search string) ([]*pocketid.UserGroup, error) {
			if search == "admins" {
				return []*pocketid.UserGroup{expectedGroup}, nil
			}
			return []*pocketid.UserGroup{}, nil
		},
	}

	existingGroup, err := reconciler.FindExistingUserGroup(ctx, mockClient, "admins")
	if err != nil {
		t.Fatalf("FindExistingUserGroup returned unexpected error: %v", err)
	}
	if existingGroup == nil {
		t.Fatal("expected to find existing group, got nil")
		return
	}
	if existingGroup.ID != expectedGroup.ID {
		t.Fatalf("expected group ID %q, got %q", expectedGroup.ID, existingGroup.ID)
	}
}

func TestFindExistingUserGroup_MultipleGroupsInResponse(t *testing.T) {
	ctx := context.Background()
	reconciler := &Reconciler{}

	targetGroup := &pocketid.UserGroup{
		ID:           "target-group-id",
		Name:         "developers",
		FriendlyName: "Developers",
	}

	otherGroup := &pocketid.UserGroup{
		ID:           "other-group-id",
		Name:         "developers-readonly",
		FriendlyName: "Read-only Developers",
	}

	mockClient := &mockPocketIDUserGroupClient{
		listUserGroupsFunc: func(ctx context.Context, search string) ([]*pocketid.UserGroup, error) {
			if search == "developers" {
				return []*pocketid.UserGroup{otherGroup, targetGroup}, nil
			}
			return []*pocketid.UserGroup{}, nil
		},
	}

	existingGroup, err := reconciler.FindExistingUserGroup(ctx, mockClient, "developers")
	if err != nil {
		t.Fatalf("FindExistingUserGroup returned unexpected error: %v", err)
	}
	if existingGroup == nil {
		t.Fatal("expected to find existing group, got nil")
		return
	}
	if existingGroup.ID != targetGroup.ID {
		t.Fatalf("expected target group ID %q, got %q", targetGroup.ID, existingGroup.ID)
	}
}

func TestUserGroupAdoption_ExistingGroupByName(t *testing.T) {
	ctx := context.Background()

	existingGroup := &pocketid.UserGroup{
		ID:           "existing-group-id",
		Name:         "admins",
		FriendlyName: "Administrators",
	}

	createCalled := false
	mockClient := &mockPocketIDUserGroupClient{
		listUserGroupsFunc: func(ctx context.Context, search string) ([]*pocketid.UserGroup, error) {
			if search == "admins" {
				return []*pocketid.UserGroup{existingGroup}, nil
			}
			return []*pocketid.UserGroup{}, nil
		},
		createUserGroupFunc: func(ctx context.Context, name, friendlyName string) (*pocketid.UserGroup, error) {
			createCalled = true
			t.Fatal("CreateUserGroup should not be called when group exists")
			return nil, nil
		},
	}

	reconciler := &Reconciler{}

	foundGroup, err := reconciler.FindExistingUserGroup(ctx, mockClient, "admins")
	if err != nil {
		t.Fatalf("FindExistingUserGroup returned error: %v", err)
	}
	if foundGroup == nil {
		t.Fatal("expected to find existing group")
		return
	}
	if foundGroup.ID != existingGroup.ID {
		t.Fatalf("expected group ID %q, got %q", existingGroup.ID, foundGroup.ID)
	}
	if createCalled {
		t.Fatal("CreateUserGroup should not have been called for existing group")
	}
}
