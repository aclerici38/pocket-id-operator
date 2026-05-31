package common

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// GetAPIClient retrieves an API client for the given instance.
// For external instances the URL and API key come from spec.external; otherwise
// the operator-managed in-cluster service + static API key Secret are used.
func GetAPIClient(ctx context.Context, k8sClient client.Client, apiReader client.Reader, instance *pocketidinternalv1alpha1.PocketIDInstance) (*pocketid.Client, error) {
	url, apiKey, err := resolveAPIClientCredentials(ctx, apiReader, instance)
	if err != nil {
		return nil, err
	}

	apiClient, err := pocketid.NewClient(url, apiKey)
	if err != nil {
		return nil, fmt.Errorf("create pocketid client: %w", err)
	}

	return apiClient, nil
}

// resolveAPIClientCredentials returns the URL + API key for the instance, branching
// between deployed and externally-adopted instances.
func resolveAPIClientCredentials(ctx context.Context, apiReader client.Reader, instance *pocketidinternalv1alpha1.PocketIDInstance) (string, string, error) {
	if instance.Spec.External != nil {
		apiKey, err := getExternalAPIKey(ctx, apiReader, instance)
		if err != nil {
			return "", "", err
		}
		return instance.Spec.External.URL, apiKey, nil
	}
	apiKey, err := getAPIKeyForInstance(ctx, apiReader, instance)
	if err != nil {
		return "", "", err
	}
	return InternalServiceURL(instance.Name, instance.Namespace), apiKey, nil
}

// getExternalAPIKey reads the user-provided API key for an externally-adopted instance.
func getExternalAPIKey(ctx context.Context, apiReader client.Reader, instance *pocketidinternalv1alpha1.PocketIDInstance) (string, error) {
	if apiReader == nil {
		return "", fmt.Errorf("%w: apiReader is nil", ErrAPIClientNotReady)
	}
	ref := instance.Spec.External.APIKeySecretRef
	secret := &corev1.Secret{}
	if err := apiReader.Get(ctx, client.ObjectKey{Namespace: instance.Namespace, Name: ref.Name}, secret); err != nil {
		return "", fmt.Errorf("%w: get external API key secret %q: %w", ErrAPIClientNotReady, ref.Name, err)
	}
	token, ok := secret.Data[ref.Key]
	if !ok || len(token) == 0 {
		return "", fmt.Errorf("%w: external API key secret %q missing key %q", ErrAPIClientNotReady, ref.Name, ref.Key)
	}
	return string(token), nil
}

// getAPIKeyForInstance retrieves the static API key for authenticating with the instance.
func getAPIKeyForInstance(ctx context.Context, apiReader client.Reader, instance *pocketidinternalv1alpha1.PocketIDInstance) (string, error) {
	if apiReader == nil {
		return "", fmt.Errorf("%w: apiReader is nil", ErrAPIClientNotReady)
	}

	secretName := StaticAPIKeySecretName(instance.Name)

	// Retrieve the secret using APIReader to bypass cache.
	secret := &corev1.Secret{}
	if err := apiReader.Get(ctx, client.ObjectKey{Namespace: instance.Namespace, Name: secretName}, secret); err != nil {
		return "", fmt.Errorf("%w: get static API key secret: %w", ErrAPIClientNotReady, err)
	}

	token, ok := secret.Data["token"]
	if !ok || len(token) == 0 {
		return "", fmt.Errorf("%w: static API key secret token is missing", ErrAPIClientNotReady)
	}

	return string(token), nil
}

// StaticAPIKeySecretName returns the secret name for the instance's static API key.
func StaticAPIKeySecretName(instanceName string) string {
	return fmt.Sprintf("%s-static-api-key", instanceName)
}

// InternalServiceURL returns the internal Kubernetes service URL for the instance.
func InternalServiceURL(instanceName, namespace string) string {
	return fmt.Sprintf("http://%s.%s.svc.cluster.local:1411", instanceName, namespace)
}
