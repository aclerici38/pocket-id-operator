package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// ClientPoolManager manages a pool of PocketID API clients, one per instance.
// Each client has its own rate-limited HTTP transport to prevent overwhelming PocketID instances.
type ClientPoolManager struct {
	mu      sync.RWMutex
	clients map[string]*pooledClient
}

// pooledClient wraps a pocketid.Client with metadata
type pooledClient struct {
	client      *pocketid.Client
	rateLimiter *rate.Limiter
	instanceKey string
	createdAt   time.Time
}

// NewClientPoolManager creates a new client pool manager
func NewClientPoolManager() *ClientPoolManager {
	return &ClientPoolManager{
		clients: make(map[string]*pooledClient),
	}
}

// GetClient retrieves or creates an API client for the given instance.
// Each instance gets exactly one client with its own rate-limited HTTP transport.
func (m *ClientPoolManager) GetClient(ctx context.Context, k8sClient client.Client, instance *pocketidinternalv1alpha1.PocketIDInstance) (*pocketid.Client, error) {
	log := logf.FromContext(ctx)
	instanceKey := instanceKey(instance)

	// Fast path: check if client exists with read lock
	m.mu.RLock()
	if pooledClient, exists := m.clients[instanceKey]; exists {
		m.mu.RUnlock()
		return pooledClient.client, nil
	}
	m.mu.RUnlock()

	// Slow path: create new client with write lock
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check in case another goroutine created it
	if pooledClient, exists := m.clients[instanceKey]; exists {
		return pooledClient.client, nil
	}

	log.Info("Creating pooled API client with rate limiting", "instance", instanceKey)

	// Get API key for authentication
	apiKey, err := getAPIKeyForInstance(ctx, k8sClient, instance)
	if err != nil {
		return nil, err
	}

	// Create rate-limited HTTP transport
	// Conservative rate limit: 1 request per second with burst of 2
	// This prevents overwhelming the PocketID instance with concurrent reconciliations
	qps := 0.8
	burst := 10
	rateLimiter := rate.NewLimiter(rate.Limit(qps), burst)
	httpTransport := pocketid.NewRateLimitedTransport(qps, burst)

	// Create the PocketID client with the rate-limited transport
	serviceURL := internalServiceURL(instance.Name, instance.Namespace)
	apiClient, err := pocketid.NewClient(serviceURL, apiKey, httpTransport)
	if err != nil {
		return nil, fmt.Errorf("create pocketid client: %w", err)
	}

	pooledClient := &pooledClient{
		client:      apiClient,
		rateLimiter: rateLimiter,
		instanceKey: instanceKey,
		createdAt:   time.Now(),
	}

	m.clients[instanceKey] = pooledClient

	log.Info("Pooled API client created",
		"instance", instanceKey,
		"qps", qps,
		"burst", burst,
	)

	return pooledClient.client, nil
}

// RemoveClient removes a client from the pool when an instance is deleted
func (m *ClientPoolManager) RemoveClient(instance *pocketidinternalv1alpha1.PocketIDInstance) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := instanceKey(instance)
	if _, exists := m.clients[key]; exists {
		delete(m.clients, key)
		logf.Log.Info("Removed client from pool", "instance", key)
	}
}

// instanceKey generates a unique key for a PocketIDInstance
func instanceKey(instance *pocketidinternalv1alpha1.PocketIDInstance) string {
	return fmt.Sprintf("%s/%s", instance.Namespace, instance.Name)
}

// getAPIKeyForInstance retrieves the API key for authenticating with the instance
func getAPIKeyForInstance(ctx context.Context, k8sClient client.Client, instance *pocketidinternalv1alpha1.PocketIDInstance) (string, error) {
	// Try to get API key from spec first
	if instance.Spec.Auth != nil {
		authUser := resolveAuthUserRef(instance)
		apiKeyName := instance.Spec.Auth.APIKeyName
		if apiKeyName == "" {
			apiKeyName = defaultAuthAPIKeyName
		}

		token, err := getAPIKeyToken(ctx, k8sClient, authUser.Namespace, authUser.Name, apiKeyName)
		if err == nil {
			return token, nil
		}

		// Try direct secret lookup as fallback
		token, directErr := getAPIKeyTokenDirect(ctx, k8sClient, authUser.Namespace, authUser.Name, apiKeyName)
		if directErr == nil {
			return token, nil
		}

		// If status is not set, check if errors indicate API key is not ready
		if instance.Status.AuthUserRef == "" || instance.Status.AuthAPIKeyName == "" {
			// Wrap with ErrAPIClientNotReady if it's an errAPIKeyNotReady
			if errors.Is(err, errAPIKeyNotReady) || errors.Is(directErr, errAPIKeyNotReady) {
				return "", fmt.Errorf("%w: %w", ErrAPIClientNotReady, err)
			}
			return "", err
		}
	}

	// Fallback to status
	if authUser, ok := resolveAuthUserRefFromStatus(instance); ok && instance.Status.AuthAPIKeyName != "" {
		token, err := getAPIKeyTokenDirect(ctx, k8sClient, authUser.Namespace, authUser.Name, instance.Status.AuthAPIKeyName)
		if err != nil {
			// Wrap with ErrAPIClientNotReady if it's an errAPIKeyNotReady
			if errors.Is(err, errAPIKeyNotReady) {
				return "", fmt.Errorf("%w: %w", ErrAPIClientNotReady, err)
			}
			return "", err
		}
		return token, nil
	}

	return "", fmt.Errorf("no API key configured for instance")
}

// Global client pool manager instance
var globalClientPool = NewClientPoolManager()

// GetAPIClient retrieves an API client for the given instance from the global pool.
// This ensures only one client exists per instance, with rate limiting applied at the HTTP transport layer.
func GetAPIClient(ctx context.Context, k8sClient client.Client, instance *pocketidinternalv1alpha1.PocketIDInstance) (*pocketid.Client, error) {
	return globalClientPool.GetClient(ctx, k8sClient, instance)
}

// RemoveAPIClient removes a client from the global pool (call when instance is deleted)
func RemoveAPIClient(instance *pocketidinternalv1alpha1.PocketIDInstance) {
	globalClientPool.RemoveClient(instance)
}
