package controller

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
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
	client              *pocketid.Client
	rateLimiter         *rate.Limiter
	instanceKey         string
	createdAt           time.Time
	rateLimitingEnabled bool
}

// NewClientPoolManager creates a new client pool manager
func NewClientPoolManager() *ClientPoolManager {
	return &ClientPoolManager{
		clients: make(map[string]*pooledClient),
	}
}

// GetClient retrieves or creates an API client for the given instance.
// Each instance gets exactly one client with its own rate-limited HTTP transport.
func (m *ClientPoolManager) GetClient(ctx context.Context, k8sClient client.Client, apiReader client.Reader, instance *pocketidinternalv1alpha1.PocketIDInstance) (*pocketid.Client, error) {
	log := logf.FromContext(ctx)
	instanceKey := instanceKey(instance)

	// Fast path: check if client exists with read lock
	m.mu.RLock()
	if pooledClient, exists := m.clients[instanceKey]; exists {
		// Check if rate limiting configuration has changed
		rateLimitingEnabled := !instance.Spec.DisableGlobalRateLimiting
		if pooledClient.rateLimitingEnabled == rateLimitingEnabled {
			m.mu.RUnlock()
			return pooledClient.client, nil
		}
		// Configuration changed, need to recreate client
		log.Info("Rate limiting configuration changed, recreating client",
			"instance", instanceKey,
			"oldRateLimitingEnabled", pooledClient.rateLimitingEnabled,
			"newRateLimitingEnabled", rateLimitingEnabled,
		)
	}
	m.mu.RUnlock()

	// Slow path: create new client with write lock
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check in case another goroutine created it
	if pooledClient, exists := m.clients[instanceKey]; exists {
		return pooledClient.client, nil
	}

	// Get API key for authentication using APIReader to bypass cache
	apiKey, err := getAPIKeyForInstance(ctx, apiReader, instance)
	if err != nil {
		return nil, err
	}

	var httpTransport http.RoundTripper
	var rateLimiter *rate.Limiter
	rateLimitingEnabled := !instance.Spec.DisableGlobalRateLimiting

	// Only create rate-limited transport if rate limiting is not disabled
	if instance.Spec.DisableGlobalRateLimiting {
		log.Info("Creating pooled API client without rate limiting (disabled by spec)", "instance", instanceKey)
		httpTransport = http.DefaultTransport
	} else {
		log.Info("Creating pooled API client with rate limiting", "instance", instanceKey)
		// Conservative rate limit: 0.8 request per second with burst of 10
		// This prevents overwhelming the PocketID instance with concurrent reconciliations
		qps := 0.8
		burst := 10
		rateLimiter = rate.NewLimiter(rate.Limit(qps), burst)
		httpTransport = pocketid.NewRateLimitedTransport(qps, burst)
	}

	// Create the PocketID client with the transport
	serviceURL := internalServiceURL(instance.Name, instance.Namespace)
	apiClient, err := pocketid.NewClient(serviceURL, apiKey, httpTransport)
	if err != nil {
		return nil, fmt.Errorf("create pocketid client: %w", err)
	}

	pooledClient := &pooledClient{
		client:              apiClient,
		rateLimiter:         rateLimiter,
		instanceKey:         instanceKey,
		createdAt:           time.Now(),
		rateLimitingEnabled: rateLimitingEnabled,
	}

	m.clients[instanceKey] = pooledClient

	if instance.Spec.DisableGlobalRateLimiting {
		log.Info("Pooled API client created without rate limiting", "instance", instanceKey)
	} else {
		log.Info("Pooled API client created with rate limiting",
			"instance", instanceKey,
			"qps", 0.8,
			"burst", 10,
		)
	}

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

// getAPIKeyForInstance retrieves the static API key for authenticating with the instance
func getAPIKeyForInstance(ctx context.Context, apiReader client.Reader, instance *pocketidinternalv1alpha1.PocketIDInstance) (string, error) {
	// Check if apiReader is nil (can happen in tests)
	if apiReader == nil {
		return "", fmt.Errorf("%w: apiReader is nil", ErrAPIClientNotReady)
	}

	// Get the static API key secret name
	secretName := staticAPIKeySecretName(instance.Name)

	// Retrieve the secret using APIReader to bypass cache
	secret := &corev1.Secret{}
	if err := apiReader.Get(ctx, client.ObjectKey{Namespace: instance.Namespace, Name: secretName}, secret); err != nil {
		// Wrap with ErrAPIClientNotReady so controllers can handle gracefully
		return "", fmt.Errorf("%w: get static API key secret: %w", ErrAPIClientNotReady, err)
	}

	// Extract the token
	token, ok := secret.Data["token"]
	if !ok {
		return "", fmt.Errorf("static API key secret has no token field")
	}

	return string(token), nil
}

// Global client pool manager instance
var globalClientPool = NewClientPoolManager()

// GetAPIClient retrieves an API client for the given instance from the global pool.
// This ensures only one client exists per instance, with rate limiting applied at the HTTP transport layer.
func GetAPIClient(ctx context.Context, k8sClient client.Client, apiReader client.Reader, instance *pocketidinternalv1alpha1.PocketIDInstance) (*pocketid.Client, error) {
	return globalClientPool.GetClient(ctx, k8sClient, apiReader, instance)
}

// RemoveAPIClient removes a client from the global pool (call when instance is deleted)
func RemoveAPIClient(instance *pocketidinternalv1alpha1.PocketIDInstance) {
	globalClientPool.RemoveClient(instance)
}
