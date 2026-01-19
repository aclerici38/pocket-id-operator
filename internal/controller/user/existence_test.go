package user

import (
	"context"
	"testing"

	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const (
	testEmailBobGmail = "bob@gmail.com"
)

// mockPocketIDClient is a mock implementation of the PocketID client for testing
type mockPocketIDClient struct {
	listUsersFunc  func(ctx context.Context, search string) ([]*pocketid.User, error)
	createUserFunc func(ctx context.Context, input pocketid.UserInput) (*pocketid.User, error)
	getUserFunc    func(ctx context.Context, id string) (*pocketid.User, error)
	updateUserFunc func(ctx context.Context, id string, input pocketid.UserInput) (*pocketid.User, error)
}

func (m *mockPocketIDClient) ListUsers(ctx context.Context, search string) ([]*pocketid.User, error) {
	if m.listUsersFunc != nil {
		return m.listUsersFunc(ctx, search)
	}
	return nil, nil
}

func (m *mockPocketIDClient) CreateUser(ctx context.Context, input pocketid.UserInput) (*pocketid.User, error) {
	if m.createUserFunc != nil {
		return m.createUserFunc(ctx, input)
	}
	return &pocketid.User{
		ID:       "new-user-id",
		Username: input.Username,
		Email:    input.Email,
	}, nil
}

func (m *mockPocketIDClient) GetUser(ctx context.Context, id string) (*pocketid.User, error) {
	if m.getUserFunc != nil {
		return m.getUserFunc(ctx, id)
	}
	return nil, nil
}

func (m *mockPocketIDClient) UpdateUser(ctx context.Context, id string, input pocketid.UserInput) (*pocketid.User, error) {
	if m.updateUserFunc != nil {
		return m.updateUserFunc(ctx, id, input)
	}
	return &pocketid.User{
		ID:       id,
		Username: input.Username,
		Email:    input.Email,
	}, nil
}

func TestFindExistingUser_NoMatch(t *testing.T) {
	ctx := context.Background()
	reconciler := &Reconciler{}

	mockClient := &mockPocketIDClient{
		listUsersFunc: func(ctx context.Context, search string) ([]*pocketid.User, error) {
			return []*pocketid.User{}, nil
		},
	}

	existingUser, err := reconciler.FindExistingUser(ctx, mockClient, "newuser", "newuser@example.com")
	if err != nil {
		t.Fatalf("FindExistingUser returned unexpected error: %v", err)
	}
	if existingUser != nil {
		t.Fatalf("expected no existing user, got: %+v", existingUser)
	}
}

func TestFindExistingUser_MatchByUsername(t *testing.T) {
	ctx := context.Background()
	reconciler := &Reconciler{}

	expectedUser := &pocketid.User{
		ID:       "existing-user-id",
		Username: "existinguser",
		Email:    "existing@example.com",
	}

	mockClient := &mockPocketIDClient{
		listUsersFunc: func(ctx context.Context, search string) ([]*pocketid.User, error) {
			if search == "existinguser" {
				return []*pocketid.User{expectedUser}, nil
			}
			return []*pocketid.User{}, nil
		},
	}

	existingUser, err := reconciler.FindExistingUser(ctx, mockClient, "existinguser", "different@example.com")
	if err != nil {
		t.Fatalf("FindExistingUser returned unexpected error: %v", err)
	}
	if existingUser == nil {
		t.Fatal("expected to find existing user, got nil")
		return
	}
	if existingUser.ID != expectedUser.ID {
		t.Fatalf("expected user ID %q, got %q", expectedUser.ID, existingUser.ID)
	}
}

func TestFindExistingUser_MatchByEmail(t *testing.T) {
	ctx := context.Background()
	reconciler := &Reconciler{}

	expectedUser := &pocketid.User{
		ID:       "existing-user-id",
		Username: "existinguser",
		Email:    "existing@example.com",
	}

	mockClient := &mockPocketIDClient{
		listUsersFunc: func(ctx context.Context, search string) ([]*pocketid.User, error) {
			if search == "existing@example.com" {
				return []*pocketid.User{expectedUser}, nil
			}
			return []*pocketid.User{}, nil
		},
	}

	existingUser, err := reconciler.FindExistingUser(ctx, mockClient, "newusername", "existing@example.com")
	if err != nil {
		t.Fatalf("FindExistingUser returned unexpected error: %v", err)
	}
	if existingUser == nil {
		t.Fatal("expected to find existing user, got nil")
		return
	}
	if existingUser.ID != expectedUser.ID {
		t.Fatalf("expected user ID %q, got %q", expectedUser.ID, existingUser.ID)
	}
}

func TestFindExistingUser_SkipsPlaceholderEmail(t *testing.T) {
	ctx := context.Background()
	reconciler := &Reconciler{}

	callCount := 0
	mockClient := &mockPocketIDClient{
		listUsersFunc: func(ctx context.Context, search string) ([]*pocketid.User, error) {
			callCount++
			return []*pocketid.User{}, nil
		},
	}

	username := "testuser"
	placeholderEmail := "testuser@placeholder.local"

	existingUser, err := reconciler.FindExistingUser(ctx, mockClient, username, placeholderEmail)
	if err != nil {
		t.Fatalf("FindExistingUser returned unexpected error: %v", err)
	}
	if existingUser != nil {
		t.Fatalf("expected no existing user, got: %+v", existingUser)
	}
	if callCount != 1 {
		t.Fatalf("expected ListUsers to be called once (username only), got %d calls", callCount)
	}
}

func TestUserAdoption_ExistingUserByUsername(t *testing.T) {
	ctx := context.Background()

	existingUser := &pocketid.User{
		ID:       "existing-user-id",
		Username: "bob",
		Email:    testEmailBobGmail,
	}

	createCalled := false
	mockClient := &mockPocketIDClient{
		listUsersFunc: func(ctx context.Context, search string) ([]*pocketid.User, error) {
			if search == "bob" {
				return []*pocketid.User{existingUser}, nil
			}
			return []*pocketid.User{}, nil
		},
		createUserFunc: func(ctx context.Context, input pocketid.UserInput) (*pocketid.User, error) {
			createCalled = true
			t.Fatal("CreateUser should not be called when user exists")
			return nil, nil
		},
	}

	reconciler := &Reconciler{}

	foundUser, err := reconciler.FindExistingUser(ctx, mockClient, "bob", testEmailBobGmail)
	if err != nil {
		t.Fatalf("FindExistingUser returned error: %v", err)
	}
	if foundUser == nil {
		t.Fatal("expected to find existing user")
		return
	}
	if foundUser.ID != existingUser.ID {
		t.Fatalf("expected user ID %q, got %q", existingUser.ID, foundUser.ID)
	}
	if createCalled {
		t.Fatal("CreateUser should not have been called for existing user")
	}
}

func TestUserAdoption_PrioritizesUsernameMatch(t *testing.T) {
	ctx := context.Background()

	userMatchingUsername := &pocketid.User{
		ID:       "username-match-id",
		Username: "bob",
		Email:    "bob@oldmail.com",
	}

	mockClient := &mockPocketIDClient{
		listUsersFunc: func(ctx context.Context, search string) ([]*pocketid.User, error) {
			if search == "bob" {
				return []*pocketid.User{userMatchingUsername}, nil
			}
			if search == testEmailBobGmail {
				t.Fatal("should not search by email when username already matched")
				return nil, nil
			}
			return []*pocketid.User{}, nil
		},
	}

	reconciler := &Reconciler{}

	foundUser, err := reconciler.FindExistingUser(ctx, mockClient, "bob", testEmailBobGmail)
	if err != nil {
		t.Fatalf("FindExistingUser returned error: %v", err)
	}
	if foundUser == nil {
		t.Fatal("expected to find existing user by username")
		return
	}
	if foundUser.ID != userMatchingUsername.ID {
		t.Fatalf("expected user ID %q, got %q", userMatchingUsername.ID, foundUser.ID)
	}
}

func TestFindExistingUser_MultipleUsersInResponse(t *testing.T) {
	ctx := context.Background()
	reconciler := &Reconciler{}

	targetUser := &pocketid.User{
		ID:       "target-user-id",
		Username: "targetuser",
		Email:    "target@example.com",
	}

	otherUser := &pocketid.User{
		ID:       "other-user-id",
		Username: "otheruser",
		Email:    "other@example.com",
	}

	mockClient := &mockPocketIDClient{
		listUsersFunc: func(ctx context.Context, search string) ([]*pocketid.User, error) {
			if search == "targetuser" {
				return []*pocketid.User{otherUser, targetUser}, nil
			}
			return []*pocketid.User{}, nil
		},
	}

	existingUser, err := reconciler.FindExistingUser(ctx, mockClient, "targetuser", "target@example.com")
	if err != nil {
		t.Fatalf("FindExistingUser returned unexpected error: %v", err)
	}
	if existingUser == nil {
		t.Fatal("expected to find existing user, got nil")
		return
	}
	if existingUser.ID != targetUser.ID {
		t.Fatalf("expected target user ID %q, got %q", targetUser.ID, existingUser.ID)
	}
}

func TestFindExistingUser_EmptyEmail(t *testing.T) {
	ctx := context.Background()
	reconciler := &Reconciler{}

	callCount := 0
	mockClient := &mockPocketIDClient{
		listUsersFunc: func(ctx context.Context, search string) ([]*pocketid.User, error) {
			callCount++
			return []*pocketid.User{}, nil
		},
	}

	existingUser, err := reconciler.FindExistingUser(ctx, mockClient, "testuser", "")
	if err != nil {
		t.Fatalf("FindExistingUser returned unexpected error: %v", err)
	}
	if existingUser != nil {
		t.Fatalf("expected no existing user, got: %+v", existingUser)
	}
	if callCount != 1 {
		t.Fatalf("expected ListUsers to be called once (username only), got %d calls", callCount)
	}
}
