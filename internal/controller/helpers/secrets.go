package helpers

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// DeleteSecretIfExists deletes a secret, ignoring NotFound errors
func DeleteSecretIfExists(ctx context.Context, c client.Client, namespace, name string) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	if err := c.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("delete secret %s: %w", name, err)
	}
	return nil
}

// DeleteSecretsIfExist deletes multiple secrets, ignoring NotFound errors
func DeleteSecretsIfExist(ctx context.Context, c client.Client, namespace string, secretNames []string) error {
	for _, name := range secretNames {
		if err := DeleteSecretIfExists(ctx, c, namespace, name); err != nil {
			return err
		}
	}
	return nil
}
