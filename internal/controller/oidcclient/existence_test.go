package oidcclient

import (
	"context"
	"net/http"
	"testing"

	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
	"github.com/go-openapi/runtime"
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
	reconciler := &Reconciler{}

	mockClient := &mockPocketIDOIDCClientClient{
		listOIDCClientsFunc: func(ctx context.Context, search string) ([]*pocketid.OIDCClient, error) {
			return []*pocketid.OIDCClient{}, nil
		},
	}

	existingClient, err := reconciler.FindExistingOIDCClient(ctx, mockClient, "new-client")
	if err != nil {
		t.Fatalf("FindExistingOIDCClient returned unexpected error: %v", err)
	}
	if existingClient != nil {
		t.Fatalf("expected no existing client, got: %+v", existingClient)
	}
}

func TestFindExistingOIDCClient_MatchByID(t *testing.T) {
	ctx := context.Background()
	reconciler := &Reconciler{}

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

	existingClient, err := reconciler.FindExistingOIDCClient(ctx, mockClient, "my-app")
	if err != nil {
		t.Fatalf("FindExistingOIDCClient returned unexpected error: %v", err)
	}
	if existingClient == nil {
		t.Fatal("expected to find existing client, got nil")
		return
	}
	if existingClient.ID != expectedClient.ID {
		t.Fatalf("expected client ID %q, got %q", expectedClient.ID, existingClient.ID)
	}
}

func TestFindExistingOIDCClient_MultipleClientsInResponse(t *testing.T) {
	ctx := context.Background()
	reconciler := &Reconciler{}

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
				return []*pocketid.OIDCClient{otherClient, targetClient}, nil
			}
			return []*pocketid.OIDCClient{}, nil
		},
	}

	existingClient, err := reconciler.FindExistingOIDCClient(ctx, mockClient, "grafana")
	if err != nil {
		t.Fatalf("FindExistingOIDCClient returned unexpected error: %v", err)
	}
	if existingClient == nil {
		t.Fatal("expected to find existing client, got nil")
		return
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

	reconciler := &Reconciler{}

	foundClient, err := reconciler.FindExistingOIDCClient(ctx, mockClient, "grafana")
	if err != nil {
		t.Fatalf("FindExistingOIDCClient returned error: %v", err)
	}
	if foundClient == nil {
		t.Fatal("expected to find existing client")
		return
	}
	if foundClient.ID != existingClient.ID {
		t.Fatalf("expected client ID %q, got %q", existingClient.ID, foundClient.ID)
	}
	if createCalled {
		t.Fatal("CreateOIDCClient should not have been called for existing client")
	}
}

func TestIsNotFoundError_DetectsAPIError404(t *testing.T) {
	err := runtime.NewAPIError("PutAPIOidcClientsID", nil, http.StatusNotFound)

	if !pocketid.IsNotFoundError(err) {
		t.Error("expected IsNotFoundError to return true for 404 APIError")
	}
}

func TestIsNotFoundError_IgnoresAPIError500(t *testing.T) {
	err := runtime.NewAPIError("PutAPIOidcClientsID", nil, http.StatusInternalServerError)

	if pocketid.IsNotFoundError(err) {
		t.Error("expected IsNotFoundError to return false for 500 APIError")
	}
}
