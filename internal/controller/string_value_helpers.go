package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pocketidv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

// ResolveStringValue resolves a StringValue to its actual string representation
// It handles three cases:
// 1. Direct value from sv.Value
// 2. Value from a secret reference in sv.ValueFrom
// 3. Fallback to a specified secret name and key
//
// The apiReader parameter allows using a direct API reader for uncached reads.
// If apiReader is nil, the regular client will be used.
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
		return getSecretValue(ctx, c, apiReader, namespace, sv.ValueFrom.Name, sv.ValueFrom.Key)
	}

	// Case 3: Fallback secret
	if fallbackSecretName != "" && fallbackKey != "" {
		return getSecretValue(ctx, c, apiReader, namespace, fallbackSecretName, fallbackKey)
	}

	// No value found
	return "", nil
}

// getSecretValue retrieves a value from a secret, preferring apiReader over client
func getSecretValue(
	ctx context.Context,
	c client.Client,
	apiReader client.Reader,
	namespace string,
	secretName string,
	key string,
) (string, error) {
	reader := apiReader
	if reader == nil {
		reader = c
	}

	secret := &corev1.Secret{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretName}, secret); err != nil {
		return "", fmt.Errorf("get secret %s: %w", secretName, err)
	}

	val, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("secret %s missing key %s", secretName, key)
	}

	return string(val), nil
}
