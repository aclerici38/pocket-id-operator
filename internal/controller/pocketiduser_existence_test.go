package controller

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
	reconciler := &PocketIDUserReconciler{}

	mockClient := &mockPocketIDClient{
		listUsersFunc: func(ctx context.Context, search string) ([]*pocketid.User, error) {
			// Return empty list - no users found
			return []*pocketid.User{}, nil
		},
	}

	existingUser, err := reconciler.findExistingUser(ctx, mockClient, "newuser", "newuser@example.com")
	if err != nil {
		t.Fatalf("findExistingUser returned unexpected error: %v", err)
	}
	if existingUser != nil {
		t.Fatalf("expected no existing user, got: %+v", existingUser)
	}
}

func TestFindExistingUser_MatchByUsername(t *testing.T) {
	ctx := context.Background()
	reconciler := &PocketIDUserReconciler{}

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

	existingUser, err := reconciler.findExistingUser(ctx, mockClient, "existinguser", "different@example.com")
	if err != nil {
		t.Fatalf("findExistingUser returned unexpected error: %v", err)
	}
	if existingUser == nil {
		t.Fatal("expected to find existing user, got nil")
	}
	if existingUser.ID != expectedUser.ID {
		t.Fatalf("expected user ID %q, got %q", expectedUser.ID, existingUser.ID)
	}
	if existingUser.Username != expectedUser.Username {
		t.Fatalf("expected username %q, got %q", expectedUser.Username, existingUser.Username)
	}
}

func TestFindExistingUser_MatchByEmail(t *testing.T) {
	ctx := context.Background()
	reconciler := &PocketIDUserReconciler{}

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

	existingUser, err := reconciler.findExistingUser(ctx, mockClient, "newusername", "existing@example.com")
	if err != nil {
		t.Fatalf("findExistingUser returned unexpected error: %v", err)
	}
	if existingUser == nil {
		t.Fatal("expected to find existing user, got nil")
	}
	if existingUser.ID != expectedUser.ID {
		t.Fatalf("expected user ID %q, got %q", expectedUser.ID, existingUser.ID)
	}
	if existingUser.Email != expectedUser.Email {
		t.Fatalf("expected email %q, got %q", expectedUser.Email, existingUser.Email)
	}
}

func TestFindExistingUser_SkipsPlaceholderEmail(t *testing.T) {
	ctx := context.Background()
	reconciler := &PocketIDUserReconciler{}

	callCount := 0
	mockClient := &mockPocketIDClient{
		listUsersFunc: func(ctx context.Context, search string) ([]*pocketid.User, error) {
			callCount++
			// Should only be called once for username, not for placeholder email
			return []*pocketid.User{}, nil
		},
	}

	username := "testuser"
	placeholderEmail := "testuser@placeholder.local"

	existingUser, err := reconciler.findExistingUser(ctx, mockClient, username, placeholderEmail)
	if err != nil {
		t.Fatalf("findExistingUser returned unexpected error: %v", err)
	}
	if existingUser != nil {
		t.Fatalf("expected no existing user, got: %+v", existingUser)
	}
	if callCount != 1 {
		t.Fatalf("expected ListUsers to be called once (username only), got %d calls", callCount)
	}
}

// Test scenarios for user adoption workflow

func TestUserAdoption_ExistingUserByUsername(t *testing.T) {
	ctx := context.Background()

	existingUser := &pocketid.User{
		ID:          "existing-user-id",
		Username:    "bob",
		Email:       testEmailBobGmail,
		FirstName:   "Bob",
		LastName:    "Smith",
		DisplayName: "Bob Smith",
		IsAdmin:     false,
		Disabled:    false,
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

	reconciler := &PocketIDUserReconciler{}

	// Simulate the logic in reconcileUser when UserID is empty
	foundUser, err := reconciler.findExistingUser(ctx, mockClient, "bob", testEmailBobGmail)
	if err != nil {
		t.Fatalf("findExistingUser returned error: %v", err)
	}

	if foundUser == nil {
		t.Fatal("expected to find existing user")
	}

	if foundUser.ID != existingUser.ID {
		t.Fatalf("expected user ID %q, got %q", existingUser.ID, foundUser.ID)
	}

	// Verify CreateUser was not called
	if createCalled {
		t.Fatal("CreateUser should not have been called for existing user")
	}
}

func TestUserAdoption_ExistingUserByEmail(t *testing.T) {
	ctx := context.Background()

	existingUser := &pocketid.User{
		ID:          "existing-user-id",
		Username:    "bob",
		Email:       testEmailBobGmail,
		FirstName:   "Bob",
		LastName:    "Smith",
		DisplayName: "Bob Smith",
		IsAdmin:     false,
		Disabled:    false,
	}

	createCalled := false
	mockClient := &mockPocketIDClient{
		listUsersFunc: func(ctx context.Context, search string) ([]*pocketid.User, error) {
			// First search by username returns nothing
			if search == "bobby" {
				return []*pocketid.User{}, nil
			}
			// Second search by email finds the user
			if search == testEmailBobGmail {
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

	reconciler := &PocketIDUserReconciler{}

	// Try to create user with different username but same email
	foundUser, err := reconciler.findExistingUser(ctx, mockClient, "bobby", testEmailBobGmail)
	if err != nil {
		t.Fatalf("findExistingUser returned error: %v", err)
	}

	if foundUser == nil {
		t.Fatal("expected to find existing user by email")
	}

	if foundUser.Email != testEmailBobGmail {
		t.Fatalf("expected email %q, got %q", testEmailBobGmail, foundUser.Email)
	}

	// Verify CreateUser was not called
	if createCalled {
		t.Fatal("CreateUser should not have been called for existing user")
	}
}

func TestUserAdoption_NewUserCreated(t *testing.T) {
	ctx := context.Background()

	createCalled := false
	var createdInput pocketid.UserInput

	mockClient := &mockPocketIDClient{
		listUsersFunc: func(ctx context.Context, search string) ([]*pocketid.User, error) {
			// No users found
			return []*pocketid.User{}, nil
		},
		createUserFunc: func(ctx context.Context, input pocketid.UserInput) (*pocketid.User, error) {
			createCalled = true
			createdInput = input
			return &pocketid.User{
				ID:          "new-user-id",
				Username:    input.Username,
				Email:       input.Email,
				FirstName:   input.FirstName,
				LastName:    input.LastName,
				DisplayName: input.DisplayName,
				IsAdmin:     input.IsAdmin,
				Disabled:    input.Disabled,
			}, nil
		},
	}

	reconciler := &PocketIDUserReconciler{}

	// Check if user exists
	foundUser, err := reconciler.findExistingUser(ctx, mockClient, "alice", "alice@example.com")
	if err != nil {
		t.Fatalf("findExistingUser returned error: %v", err)
	}

	if foundUser != nil {
		t.Fatalf("expected no existing user, got: %+v", foundUser)
	}

	// Simulate creating new user since none was found
	if foundUser == nil {
		input := pocketid.UserInput{
			Username:    "alice",
			FirstName:   "Alice",
			LastName:    "Johnson",
			Email:       "alice@example.com",
			DisplayName: "Alice Johnson",
			IsAdmin:     false,
			Disabled:    false,
		}
		newUser, err := mockClient.CreateUser(ctx, input)
		if err != nil {
			t.Fatalf("CreateUser returned error: %v", err)
		}

		if !createCalled {
			t.Fatal("CreateUser should have been called for new user")
		}

		if newUser.Username != "alice" {
			t.Fatalf("expected username %q, got %q", "alice", newUser.Username)
		}

		if createdInput.Email != "alice@example.com" {
			t.Fatalf("expected email %q in input, got %q", "alice@example.com", createdInput.Email)
		}
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
				// Username search finds a match
				return []*pocketid.User{userMatchingUsername}, nil
			}
			if search == testEmailBobGmail {
				// Email search would also find something but shouldn't be reached
				t.Fatal("should not search by email when username already matched")
				return nil, nil
			}
			return []*pocketid.User{}, nil
		},
	}

	reconciler := &PocketIDUserReconciler{}

	foundUser, err := reconciler.findExistingUser(ctx, mockClient, "bob", testEmailBobGmail)
	if err != nil {
		t.Fatalf("findExistingUser returned error: %v", err)
	}

	if foundUser == nil {
		t.Fatal("expected to find existing user by username")
	}

	if foundUser.ID != userMatchingUsername.ID {
		t.Fatalf("expected user ID %q, got %q", userMatchingUsername.ID, foundUser.ID)
	}

	// The email in found user doesn't match the search email, confirming username was prioritized
	if foundUser.Email == testEmailBobGmail {
		t.Fatal("unexpected email match - username should have been matched first")
	}
}

func TestFindExistingUser_MultipleUsersInResponse(t *testing.T) {
	ctx := context.Background()
	reconciler := &PocketIDUserReconciler{}

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
				// Return multiple users (e.g., search returned partial matches)
				// but only one with exact username match
				return []*pocketid.User{otherUser, targetUser}, nil
			}
			return []*pocketid.User{}, nil
		},
	}

	existingUser, err := reconciler.findExistingUser(ctx, mockClient, "targetuser", "target@example.com")
	if err != nil {
		t.Fatalf("findExistingUser returned unexpected error: %v", err)
	}
	if existingUser == nil {
		t.Fatal("expected to find existing user, got nil")
	}
	if existingUser.ID != targetUser.ID {
		t.Fatalf("expected target user ID %q, got %q", targetUser.ID, existingUser.ID)
	}
}

func TestFindExistingUser_EmptyEmail(t *testing.T) {
	ctx := context.Background()
	reconciler := &PocketIDUserReconciler{}

	callCount := 0
	mockClient := &mockPocketIDClient{
		listUsersFunc: func(ctx context.Context, search string) ([]*pocketid.User, error) {
			callCount++
			// Should only be called once for username, not for empty email
			return []*pocketid.User{}, nil
		},
	}

	existingUser, err := reconciler.findExistingUser(ctx, mockClient, "testuser", "")
	if err != nil {
		t.Fatalf("findExistingUser returned unexpected error: %v", err)
	}
	if existingUser != nil {
		t.Fatalf("expected no existing user, got: %+v", existingUser)
	}
	if callCount != 1 {
		t.Fatalf("expected ListUsers to be called once (username only), got %d calls", callCount)
	}
}
