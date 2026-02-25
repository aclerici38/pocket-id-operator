package helpers

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pocketidv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
)

// ResolveStringValue resolves a StringValue to its actual string representation
// It handles three cases:
// 1. Direct value from sv.Value
// 2. Value from a secret reference in sv.ValueFrom (uses apiReader for fresh reads)
// 3. Fallback to a specified secret name and key (uses apiReader for fresh reads)
//
// The apiReader should be used for user-provided secrets to avoid cache delays.
// If apiReader is nil, falls back to the cached client.
func ResolveStringValue(
	ctx context.Context,
	c client.Client,
	apiReader client.Reader,
	namespace string,
	sv pocketidv1alpha1.StringValue,
	fallbackSecretName string,
	fallbackKey string,
) (string, error) {
	// Case 1: Direct value
	if sv.Value != "" {
		return sv.Value, nil
	}

	// Case 2: Value from secret reference
	if sv.ValueFrom != nil {
		return getSecretValue(ctx, c, apiReader, namespace, sv.ValueFrom.Name, sv.ValueFrom.Key, false)
	}

	// Case 3: Fallback secret
	// This is a convenience fallback, so missing keys should return empty string
	if fallbackSecretName != "" && fallbackKey != "" {
		return getSecretValue(ctx, c, apiReader, namespace, fallbackSecretName, fallbackKey, true)
	}

	// No value found
	return "", nil
}

// ResolveSecretKeySelector reads the value of a SecretKeySelector from a Kubernetes Secret.
// Returns an empty string if ref is nil.
func ResolveSecretKeySelector(ctx context.Context, c client.Client, apiReader client.Reader, namespace string, ref *corev1.SecretKeySelector) (string, error) {
	if ref == nil {
		return "", nil
	}
	return getSecretValue(ctx, c, apiReader, namespace, ref.Name, ref.Key, false)
}

// getSecretValue retrieves a value from a secret, preferring apiReader for fresh reads
// If optional is true, missing keys return an empty string rather than an error
func getSecretValue(
	ctx context.Context,
	c client.Client,
	apiReader client.Reader,
	namespace string,
	secretName string,
	key string,
	optional bool,
) (string, error) {
	// Use APIReader for direct reads if available, otherwise use cached client
	reader := apiReader
	if reader == nil {
		reader = c
	}

	secret := &corev1.Secret{}
	if err := common.RetryKubernetesRead(ctx, common.SecretReadRetryAttempts, func() error {
		current := &corev1.Secret{}
		getErr := reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretName}, current)
		if getErr == nil {
			secret = current
		}
		return getErr
	}); err != nil {
		return "", fmt.Errorf("get secret %s: %w", secretName, err)
	}

	val, ok := secret.Data[key]
	if !ok {
		if optional {
			return "", nil
		}
		return "", fmt.Errorf("secret %s missing key %s", secretName, key)
	}

	return string(val), nil
}
