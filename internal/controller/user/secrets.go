package user

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	corev1apply "k8s.io/client-go/applyconfigurations/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const (
	APIKeySecretKey = "token"

	UserInfoSecretKeyUsername    = "username"
	UserInfoSecretKeyFirstName   = "firstName"
	UserInfoSecretKeyLastName    = "lastName"
	UserInfoSecretKeyEmail       = "email"
	UserInfoSecretKeyDisplayName = "displayName"
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

func ensureAPIKeySecret(ctx context.Context, c client.Client, scheme *runtime.Scheme, user *pocketidinternalv1alpha1.PocketIDUser, secretName, token string) error {
	ownerRef, err := common.ControllerOwnerReference(user, scheme)
	if err != nil {
		return err
	}

	secret := corev1apply.Secret(secretName, user.Namespace).
		WithLabels(common.ManagedByLabels(nil)).
		WithOwnerReferences(ownerRef).
		WithType(corev1.SecretTypeOpaque).
		WithData(map[string][]byte{
			APIKeySecretKey: []byte(token),
		})

	return c.Apply(ctx, secret, client.FieldOwner("pocket-id-operator"))
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

func ensureUserInfoSecret(ctx context.Context, c client.Client, scheme *runtime.Scheme, user *pocketidinternalv1alpha1.PocketIDUser, secretName string, pUser *pocketid.User) error {
	ownerRef, err := common.ControllerOwnerReference(user, scheme)
	if err != nil {
		return err
	}

	secret := corev1apply.Secret(secretName, user.Namespace).
		WithLabels(common.ManagedByLabels(nil)).
		WithOwnerReferences(ownerRef).
		WithType(corev1.SecretTypeOpaque).
		WithData(map[string][]byte{
			UserInfoSecretKeyUsername:    []byte(pUser.Username),
			UserInfoSecretKeyFirstName:   []byte(pUser.FirstName),
			UserInfoSecretKeyLastName:    []byte(pUser.LastName),
			UserInfoSecretKeyEmail:       []byte(pUser.Email),
			UserInfoSecretKeyDisplayName: []byte(pUser.DisplayName),
		})

	return c.Apply(ctx, secret, client.FieldOwner("pocket-id-operator"))
}
