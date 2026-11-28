package common

import (
	"cmp"
	"context"
	"crypto/tls"
	"fmt"
	"sync"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// externalCredentials caches client credentials, so their token outlives the API clients
// built every reconcile.
var externalCredentials sync.Map // credentialsKey -> *pid.ClientCredentials

type credentialsKey struct{ baseURL, clientID, secret string }

// GetAPIClient retrieves an API client for the given instance.
// For external instances the URL and credentials come from spec.external; otherwise
// the operator-managed in-cluster service + static API key Secret are used.
func GetAPIClient(ctx context.Context, k8sClient client.Client, apiReader client.Reader, instance *pocketidinternalv1alpha1.PocketIDInstance) (*pocketid.Client, error) {
	baseURL, auth, err := resolveAPIClientAuth(ctx, apiReader, instance)
	if err != nil {
		return nil, err
	}

	apiClient, err := pocketid.NewClient(baseURL, auth, pocketid.WithTLSConfig(internalTLSConfig(instance)))
	if err != nil {
		return nil, fmt.Errorf("create pocketid client: %w", err)
	}

	return apiClient, nil
}

// internalTLSConfig returns the TLS settings for reaching a managed instance that
// terminates TLS itself, and nil when there is nothing to configure.
// Does NOT verify certificates intentionally.
func internalTLSConfig(instance *pocketidinternalv1alpha1.PocketIDInstance) *tls.Config {
	if instance.Spec.External != nil || instance.Spec.TLS == nil {
		return nil
	}
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
}

// resolveAPIClientAuth returns the URL and credential for the instance: an external
// instance's client credentials, or else the API key from resolveAPIClientCredentials.
func resolveAPIClientAuth(ctx context.Context, apiReader client.Reader, instance *pocketidinternalv1alpha1.PocketIDInstance) (string, pid.ClientOption, error) {
	if ext := instance.Spec.External; ext != nil && ext.ClientCredentials != nil {
		clientID := ext.ClientCredentials.ClientID.Value
		if ref := ext.ClientCredentials.ClientID.ValueFrom; clientID == "" && ref != nil {
			var err error
			if clientID, err = getExternalSecret(ctx, apiReader, instance, *ref); err != nil {
				return "", nil, err
			}
		}
		secret, err := getExternalSecret(ctx, apiReader, instance, ext.ClientCredentials.ClientSecretRef)
		if err != nil {
			return "", nil, err
		}
		key := credentialsKey{cmp.Or(ext.APIURL, ext.URL), clientID, secret}
		cc, _ := externalCredentials.LoadOrStore(key, pocketid.NewClientCredentials(key.baseURL, clientID, secret))
		return key.baseURL, pid.WithClientCredentials(cc.(*pid.ClientCredentials)), nil
	}
	baseURL, apiKey, err := resolveAPIClientCredentials(ctx, apiReader, instance)
	return baseURL, pid.WithAPIKey(apiKey), err
}

// resolveAPIClientCredentials returns the URL + API key for the instance, branching
// between deployed and externally-adopted instances.
func resolveAPIClientCredentials(ctx context.Context, apiReader client.Reader, instance *pocketidinternalv1alpha1.PocketIDInstance) (string, string, error) {
	if instance.Spec.External != nil {
		apiKey, err := getExternalSecret(ctx, apiReader, instance, *instance.Spec.External.APIKeySecretRef)
		if err != nil {
			return "", "", err
		}
		return cmp.Or(instance.Spec.External.APIURL, instance.Spec.External.URL), apiKey, nil
	}
	apiKey, err := getAPIKeyForInstance(ctx, apiReader, instance)
	if err != nil {
		return "", "", err
	}
	return InternalServiceURL(instance), apiKey, nil
}

// getExternalSecret reads a user-provided credential for an externally-adopted instance.
func getExternalSecret(ctx context.Context, apiReader client.Reader, instance *pocketidinternalv1alpha1.PocketIDInstance, ref corev1.SecretKeySelector) (string, error) {
	if apiReader == nil {
		return "", fmt.Errorf("%w: apiReader is nil", ErrAPIClientNotReady)
	}
	secret := &corev1.Secret{}
	if err := apiReader.Get(ctx, client.ObjectKey{Namespace: instance.Namespace, Name: ref.Name}, secret); err != nil {
		return "", fmt.Errorf("%w: get external credentials secret %q: %w", ErrAPIClientNotReady, ref.Name, err)
	}
	token, ok := secret.Data[ref.Key]
	if !ok || len(token) == 0 {
		return "", fmt.Errorf("%w: external credentials secret %q missing key %q", ErrAPIClientNotReady, ref.Name, ref.Key)
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
// Pocket-ID serves either plaintext or TLS on the one port, so spec.tls decides the scheme.
func InternalServiceURL(instance *pocketidinternalv1alpha1.PocketIDInstance) string {
	scheme := "http"
	if instance.Spec.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s.%s.svc:1411", scheme, instance.Name, instance.Namespace)
}
