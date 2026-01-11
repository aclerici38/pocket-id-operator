package controller

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

var (
	errAPIKeyNotReady    = errors.New("api key not ready")
	ErrAPIClientNotReady = errors.New("api client not ready")
)

func getAPIKeyTokenDirect(ctx context.Context, c client.Client, namespace, userRef, apiKeyName string) (string, error) {
	secretName := apiKeySecretName(userRef, apiKeyName)

	secret := &corev1.Secret{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: secretName}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return "", fmt.Errorf("%w: get secret %s: %w", errAPIKeyNotReady, secretName, err)
		}
		return "", fmt.Errorf("get secret %s: %w", secretName, err)
	}

	token, ok := secret.Data[apiKeySecretKey]
	if !ok {
		return "", fmt.Errorf("secret %s missing key %s", secretName, apiKeySecretKey)
	}

	return string(token), nil
}

func getAPIKeyToken(ctx context.Context, c client.Client, namespace, userRef, apiKeyName string) (string, error) {
	user := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: userRef}, user); err != nil {
		if apierrors.IsNotFound(err) {
			return "", fmt.Errorf("%w: get user %s: %w", errAPIKeyNotReady, userRef, err)
		}
		return "", fmt.Errorf("get user %s: %w", userRef, err)
	}

	var keyStatus *pocketidinternalv1alpha1.APIKeyStatus
	for i := range user.Status.APIKeys {
		if user.Status.APIKeys[i].Name == apiKeyName {
			keyStatus = &user.Status.APIKeys[i]
			break
		}
	}
	if keyStatus == nil {
		return "", fmt.Errorf("%w: API key %s not found in user %s status", errAPIKeyNotReady, apiKeyName, userRef)
	}
	if keyStatus.SecretName == "" {
		return "", fmt.Errorf("%w: API key %s has no secret reference", errAPIKeyNotReady, apiKeyName)
	}

	secret := &corev1.Secret{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: keyStatus.SecretName}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return "", fmt.Errorf("%w: get secret %s: %w", errAPIKeyNotReady, keyStatus.SecretName, err)
		}
		return "", fmt.Errorf("get secret %s: %w", keyStatus.SecretName, err)
	}

	key := keyStatus.SecretKey
	if key == "" {
		key = apiKeySecretKey
	}
	token, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("secret %s missing key %s", keyStatus.SecretName, key)
	}

	return string(token), nil
}
