package helpers

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
)

// DeleteSecretIfManaged deletes a secret by name only if it exists and is
// managed by the operator
func DeleteSecretIfManaged(ctx context.Context, c client.Client, namespace, name string) error {
	secret := &corev1.Secret{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, secret); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !common.IsManagedByOperator(secret) {
		return nil
	}
	if err := c.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("delete secret %s: %w", name, err)
	}
	return nil
}

// DeleteSecretsIfManaged deletes multiple operator-managed secrets by name,
// skipping any that the operator does not own. See DeleteSecretIfManaged.
func DeleteSecretsIfManaged(ctx context.Context, c client.Client, namespace string, secretNames []string) error {
	for _, name := range secretNames {
		if err := DeleteSecretIfManaged(ctx, c, namespace, name); err != nil {
			return err
		}
	}
	return nil
}
