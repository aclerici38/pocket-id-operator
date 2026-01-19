package common

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
	instanceKey := InstanceKey(instance)

	// Fast path: check if client exists with read lock
	m.mu.RLock()
	if pooledClient, exists := m.clients[instanceKey]; exists {
		// Check if rate limiting configuration has changed
		rateLimitingEnabled := !instance.Spec.DisableGlobalRateLimiting
		if pooledClient.rateLimitingEnabled == rateLimitingEnabled {
			m.mu.RUnlock()
			return pooledClient.client, nil
		}
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

	// Double-check in case another goroutine created it with matching config
	rateLimitingEnabled := !instance.Spec.DisableGlobalRateLimiting
	if pooledClient, exists := m.clients[instanceKey]; exists {
		if pooledClient.rateLimitingEnabled == rateLimitingEnabled {
			return pooledClient.client, nil
		}
		// Config doesn't match, continue to recreate
	}

	// Get API key for authentication using APIReader to bypass cache
	apiKey, err := getAPIKeyForInstance(ctx, apiReader, instance)
	if err != nil {
		return nil, err
	}

	var httpTransport http.RoundTripper
	var rateLimiter *rate.Limiter

	if instance.Spec.DisableGlobalRateLimiting {
		log.Info("Creating pooled API client without rate limiting (disabled by spec)", "instance", instanceKey)
		httpTransport = http.DefaultTransport
	} else {
		log.Info("Creating pooled API client with rate limiting", "instance", instanceKey)
		// Pocket-id has a very aggressive rate-limiter we do not want to trigger
		qps := 0.8
		burst := 10
		rateLimiter = rate.NewLimiter(rate.Limit(qps), burst)
		httpTransport = pocketid.NewRateLimitedTransport(qps, burst)
	}

	serviceURL := InternalServiceURL(instance.Name, instance.Namespace)
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
	key := InstanceKey(instance)
	if _, exists := m.clients[key]; exists {
		delete(m.clients, key)
		logf.Log.Info("Removed client from pool", "instance", key)
	}
}

// InstanceKey generates a unique key for a PocketIDInstance
func InstanceKey(instance *pocketidinternalv1alpha1.PocketIDInstance) string {
	return fmt.Sprintf("%s/%s", instance.Namespace, instance.Name)
}

// getAPIKeyForInstance retrieves the static API key for authenticating with the instance
func getAPIKeyForInstance(ctx context.Context, apiReader client.Reader, instance *pocketidinternalv1alpha1.PocketIDInstance) (string, error) {
	if apiReader == nil {
		return "", fmt.Errorf("%w: apiReader is nil", ErrAPIClientNotReady)
	}

	secretName := StaticAPIKeySecretName(instance.Name)

	// Retrieve the secret using APIReader to bypass cache
	secret := &corev1.Secret{}
	if err := apiReader.Get(ctx, client.ObjectKey{Namespace: instance.Namespace, Name: secretName}, secret); err != nil {
		// Wrap with ErrAPIClientNotReady so controllers can handle gracefully
		return "", fmt.Errorf("%w: get static API key secret: %w", ErrAPIClientNotReady, err)
	}

	token, ok := secret.Data["token"]
	if !ok {
		return "", fmt.Errorf("static API key secret has no token field")
	}

	return string(token), nil
}

// StaticAPIKeySecretName returns the secret name for the instance's static API key
func StaticAPIKeySecretName(instanceName string) string {
	return fmt.Sprintf("%s-static-api-key", instanceName)
}

// InternalServiceURL returns the internal Kubernetes service URL for the instance
func InternalServiceURL(instanceName, namespace string) string {
	return fmt.Sprintf("http://%s.%s.svc.cluster.local:1411", instanceName, namespace)
}

// Global client pool manager instance
var globalClientPool = NewClientPoolManager()

// GetAPIClient retrieves an API client for the given instance from the global pool.
// This ensures only one client exists per instance, with rate limiting applied at the HTTP transport layer.
func GetAPIClient(ctx context.Context, k8sClient client.Client, apiReader client.Reader, instance *pocketidinternalv1alpha1.PocketIDInstance) (*pocketid.Client, error) {
	return globalClientPool.GetClient(ctx, k8sClient, apiReader, instance)
}

// RemoveAPIClient removes a client from the global pool
func RemoveAPIClient(instance *pocketidinternalv1alpha1.PocketIDInstance) {
	globalClientPool.RemoveClient(instance)
}
