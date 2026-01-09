package controller

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

func ensureAPIKeySecret(ctx context.Context, c client.Client, scheme *runtime.Scheme, user *pocketidinternalv1alpha1.PocketIDUser, secretName, token string) error {
	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: user.Namespace,
			Labels:    managedByLabels(nil),
		},
	}

	if err := controllerutil.SetControllerReference(user, secret, scheme); err != nil {
		return err
	}

	secret.Type = corev1.SecretTypeOpaque
	secret.Data = map[string][]byte{
		apiKeySecretKey: []byte(token),
	}

	return c.Patch(ctx, secret, client.Apply, client.FieldOwner("pocket-id-operator"))
}

func mergeAPIKeyStatus(user *pocketidinternalv1alpha1.PocketIDUser, keyStatus pocketidinternalv1alpha1.APIKeyStatus) {
	for i := range user.Status.APIKeys {
		if user.Status.APIKeys[i].Name == keyStatus.Name {
			user.Status.APIKeys[i] = keyStatus
			return
		}
	}

	user.Status.APIKeys = append(user.Status.APIKeys, keyStatus)
}
