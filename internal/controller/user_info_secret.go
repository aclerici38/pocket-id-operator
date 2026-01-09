package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const (
	userInfoSecretKeyUsername    = "username"
	userInfoSecretKeyFirstName   = "firstName"
	userInfoSecretKeyLastName    = "lastName"
	userInfoSecretKeyEmail       = "email"
	userInfoSecretKeyDisplayName = "displayName"
)

func userInfoInputSecretName(user *pocketidinternalv1alpha1.PocketIDUser) string {
	if user.Spec.UserInfoSecretRef == nil {
		return ""
	}
	return user.Spec.UserInfoSecretRef.Name
}

func userInfoOutputSecretName(userName string) string {
	return fmt.Sprintf("%s-user-data", userName)
}

func ensureUserInfoSecret(ctx context.Context, c client.Client, scheme *runtime.Scheme, user *pocketidinternalv1alpha1.PocketIDUser, secretName string, pUser *pocketid.User) error {
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
		userInfoSecretKeyUsername:    []byte(pUser.Username),
		userInfoSecretKeyFirstName:   []byte(pUser.FirstName),
		userInfoSecretKeyLastName:    []byte(pUser.LastName),
		userInfoSecretKeyEmail:       []byte(pUser.Email),
		userInfoSecretKeyDisplayName: []byte(pUser.DisplayName),
	}

	return c.Patch(ctx, secret, client.Apply, client.FieldOwner("pocket-id-operator"))
}
