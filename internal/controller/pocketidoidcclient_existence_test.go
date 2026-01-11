package controller

import (
	"context"
	"testing"

	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// mockPocketIDOIDCClientClient is a mock implementation for testing OIDC client operations
type mockPocketIDOIDCClientClient struct {
	listOIDCClientsFunc               func(ctx context.Context, search string) ([]*pocketid.OIDCClient, error)
	createOIDCClientFunc              func(ctx context.Context, input pocketid.OIDCClientInput) (*pocketid.OIDCClient, error)
	getOIDCClientFunc                 func(ctx context.Context, id string) (*pocketid.OIDCClient, error)
	updateOIDCClientFunc              func(ctx context.Context, id string, input pocketid.OIDCClientInput) (*pocketid.OIDCClient, error)
	updateOIDCClientAllowedGroupsFunc func(ctx context.Context, id string, groupIDs []string) error
}

func (m *mockPocketIDOIDCClientClient) ListOIDCClients(ctx context.Context, search string) ([]*pocketid.OIDCClient, error) {
	if m.listOIDCClientsFunc != nil {
		return m.listOIDCClientsFunc(ctx, search)
	}
	return nil, nil
}

func (m *mockPocketIDOIDCClientClient) CreateOIDCClient(ctx context.Context, input pocketid.OIDCClientInput) (*pocketid.OIDCClient, error) {
	if m.createOIDCClientFunc != nil {
		return m.createOIDCClientFunc(ctx, input)
	}
	return &pocketid.OIDCClient{
		ID:   input.ID,
		Name: input.Name,
	}, nil
}

func (m *mockPocketIDOIDCClientClient) GetOIDCClient(ctx context.Context, id string) (*pocketid.OIDCClient, error) {
	if m.getOIDCClientFunc != nil {
		return m.getOIDCClientFunc(ctx, id)
	}
	return nil, nil
}

func (m *mockPocketIDOIDCClientClient) UpdateOIDCClient(ctx context.Context, id string, input pocketid.OIDCClientInput) (*pocketid.OIDCClient, error) {
	if m.updateOIDCClientFunc != nil {
		return m.updateOIDCClientFunc(ctx, id, input)
	}
	return &pocketid.OIDCClient{
		ID:   id,
		Name: input.Name,
	}, nil
}

func (m *mockPocketIDOIDCClientClient) UpdateOIDCClientAllowedGroups(ctx context.Context, id string, groupIDs []string) error {
	if m.updateOIDCClientAllowedGroupsFunc != nil {
		return m.updateOIDCClientAllowedGroupsFunc(ctx, id, groupIDs)
	}
	return nil
}

func TestFindExistingOIDCClient_NoMatch(t *testing.T) {
	ctx := context.Background()
	reconciler := &PocketIDOIDCClientReconciler{}

	mockClient := &mockPocketIDOIDCClientClient{
		listOIDCClientsFunc: func(ctx context.Context, search string) ([]*pocketid.OIDCClient, error) {
			return []*pocketid.OIDCClient{}, nil
		},
	}

	existingClient, err := reconciler.findExistingOIDCClient(ctx, mockClient, "new-client")
	if err != nil {
		t.Fatalf("findExistingOIDCClient returned unexpected error: %v", err)
	}
	if existingClient != nil {
		t.Fatalf("expected no existing client, got: %+v", existingClient)
	}
}

func TestFindExistingOIDCClient_MatchByID(t *testing.T) {
	ctx := context.Background()
	reconciler := &PocketIDOIDCClientReconciler{}

	expectedClient := &pocketid.OIDCClient{
		ID:   "my-app",
		Name: "My Application",
	}

	mockClient := &mockPocketIDOIDCClientClient{
		listOIDCClientsFunc: func(ctx context.Context, search string) ([]*pocketid.OIDCClient, error) {
			if search == "my-app" {
				return []*pocketid.OIDCClient{expectedClient}, nil
			}
			return []*pocketid.OIDCClient{}, nil
		},
	}

	existingClient, err := reconciler.findExistingOIDCClient(ctx, mockClient, "my-app")
	if err != nil {
		t.Fatalf("findExistingOIDCClient returned unexpected error: %v", err)
	}
	if existingClient == nil {
		t.Fatal("expected to find existing client, got nil")
	}
	if existingClient.ID != expectedClient.ID {
		t.Fatalf("expected client ID %q, got %q", expectedClient.ID, existingClient.ID)
	}
	if existingClient.Name != expectedClient.Name {
		t.Fatalf("expected name %q, got %q", expectedClient.Name, existingClient.Name)
	}
}

func TestFindExistingOIDCClient_MultipleClientsInResponse(t *testing.T) {
	ctx := context.Background()
	reconciler := &PocketIDOIDCClientReconciler{}

	targetClient := &pocketid.OIDCClient{
		ID:   "grafana",
		Name: "Grafana",
	}

	otherClient := &pocketid.OIDCClient{
		ID:   "grafana-dev",
		Name: "Grafana Development",
	}

	mockClient := &mockPocketIDOIDCClientClient{
		listOIDCClientsFunc: func(ctx context.Context, search string) ([]*pocketid.OIDCClient, error) {
			if search == "grafana" {
				// Return multiple clients (e.g., search returned partial matches)
				return []*pocketid.OIDCClient{otherClient, targetClient}, nil
			}
			return []*pocketid.OIDCClient{}, nil
		},
	}

	existingClient, err := reconciler.findExistingOIDCClient(ctx, mockClient, "grafana")
	if err != nil {
		t.Fatalf("findExistingOIDCClient returned unexpected error: %v", err)
	}
	if existingClient == nil {
		t.Fatal("expected to find existing client, got nil")
	}
	if existingClient.ID != targetClient.ID {
		t.Fatalf("expected target client ID %q, got %q", targetClient.ID, existingClient.ID)
	}
}

func TestOIDCClientAdoption_ExistingClientByID(t *testing.T) {
	ctx := context.Background()

	existingClient := &pocketid.OIDCClient{
		ID:   "grafana",
		Name: "Grafana",
	}

	createCalled := false
	mockClient := &mockPocketIDOIDCClientClient{
		listOIDCClientsFunc: func(ctx context.Context, search string) ([]*pocketid.OIDCClient, error) {
			if search == "grafana" {
				return []*pocketid.OIDCClient{existingClient}, nil
			}
			return []*pocketid.OIDCClient{}, nil
		},
		createOIDCClientFunc: func(ctx context.Context, input pocketid.OIDCClientInput) (*pocketid.OIDCClient, error) {
			createCalled = true
			t.Fatal("CreateOIDCClient should not be called when client exists")
			return nil, nil
		},
	}

	reconciler := &PocketIDOIDCClientReconciler{}

	foundClient, err := reconciler.findExistingOIDCClient(ctx, mockClient, "grafana")
	if err != nil {
		t.Fatalf("findExistingOIDCClient returned error: %v", err)
	}

	if foundClient == nil {
		t.Fatal("expected to find existing client")
	}

	if foundClient.ID != existingClient.ID {
		t.Fatalf("expected client ID %q, got %q", existingClient.ID, foundClient.ID)
	}

	if createCalled {
		t.Fatal("CreateOIDCClient should not have been called for existing client")
	}
}

func TestOIDCClientAdoption_NewClientCreated(t *testing.T) {
	ctx := context.Background()

	createCalled := false
	var createdInput pocketid.OIDCClientInput

	mockClient := &mockPocketIDOIDCClientClient{
		listOIDCClientsFunc: func(ctx context.Context, search string) ([]*pocketid.OIDCClient, error) {
			return []*pocketid.OIDCClient{}, nil
		},
		createOIDCClientFunc: func(ctx context.Context, input pocketid.OIDCClientInput) (*pocketid.OIDCClient, error) {
			createCalled = true
			createdInput = input
			return &pocketid.OIDCClient{
				ID:   input.ID,
				Name: input.Name,
			}, nil
		},
	}

	reconciler := &PocketIDOIDCClientReconciler{}

	foundClient, err := reconciler.findExistingOIDCClient(ctx, mockClient, "new-app")
	if err != nil {
		t.Fatalf("findExistingOIDCClient returned error: %v", err)
	}

	if foundClient != nil {
		t.Fatalf("expected no existing client, got: %+v", foundClient)
	}

	// Simulate creating new client since none was found
	if foundClient == nil {
		input := pocketid.OIDCClientInput{
			ID:   "new-app",
			Name: "New Application",
		}
		newClient, err := mockClient.CreateOIDCClient(ctx, input)
		if err != nil {
			t.Fatalf("CreateOIDCClient returned error: %v", err)
		}

		if !createCalled {
			t.Fatal("CreateOIDCClient should have been called for new client")
		}

		if newClient.ID != "new-app" {
			t.Fatalf("expected ID %q, got %q", "new-app", newClient.ID)
		}

		if createdInput.Name != "New Application" {
			t.Fatalf("expected created name %q in input, got %q", "New Application", createdInput.Name)
		}
	}
}

func TestOIDCClientAdoption_UsesSpecIDIfSet(t *testing.T) {
	ctx := context.Background()

	existingClient := &pocketid.OIDCClient{
		ID:   "custom-id",
		Name: "Custom Client",
	}

	mockClient := &mockPocketIDOIDCClientClient{
		listOIDCClientsFunc: func(ctx context.Context, search string) ([]*pocketid.OIDCClient, error) {
			if search == "custom-id" {
				return []*pocketid.OIDCClient{existingClient}, nil
			}
			return []*pocketid.OIDCClient{}, nil
		},
	}

	reconciler := &PocketIDOIDCClientReconciler{}

	// Search using spec.ID
	foundClient, err := reconciler.findExistingOIDCClient(ctx, mockClient, "custom-id")
	if err != nil {
		t.Fatalf("findExistingOIDCClient returned error: %v", err)
	}

	if foundClient == nil {
		t.Fatal("expected to find existing client by spec.ID")
	}

	if foundClient.ID != "custom-id" {
		t.Fatalf("expected client ID %q, got %q", "custom-id", foundClient.ID)
	}
}

func TestOIDCClientAdoption_FallsBackToMetadataName(t *testing.T) {
	ctx := context.Background()

	existingClient := &pocketid.OIDCClient{
		ID:   "my-client-name",
		Name: "My Client",
	}

	mockClient := &mockPocketIDOIDCClientClient{
		listOIDCClientsFunc: func(ctx context.Context, search string) ([]*pocketid.OIDCClient, error) {
			if search == "my-client-name" {
				return []*pocketid.OIDCClient{existingClient}, nil
			}
			return []*pocketid.OIDCClient{}, nil
		},
	}

	reconciler := &PocketIDOIDCClientReconciler{}

	// Search using metadata.name (when spec.ID is empty)
	foundClient, err := reconciler.findExistingOIDCClient(ctx, mockClient, "my-client-name")
	if err != nil {
		t.Fatalf("findExistingOIDCClient returned error: %v", err)
	}

	if foundClient == nil {
		t.Fatal("expected to find existing client by metadata.name")
	}

	if foundClient.ID != "my-client-name" {
		t.Fatalf("expected client ID %q, got %q", "my-client-name", foundClient.ID)
	}
}
