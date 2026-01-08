package controller

import pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"

type authUserRef struct {
	Name      string
	Namespace string
}

func resolveAuthUserRef(instance *pocketidinternalv1alpha1.PocketIDInstance) authUserRef {
	name := defaultAuthUserRef
	namespace := instance.Namespace

	if instance.Spec.Auth != nil && instance.Spec.Auth.UserRef != nil {
		if instance.Spec.Auth.UserRef.Name != "" {
			name = instance.Spec.Auth.UserRef.Name
		}
		if instance.Spec.Auth.UserRef.Namespace != "" {
			namespace = instance.Spec.Auth.UserRef.Namespace
		}
	}

	return authUserRef{Name: name, Namespace: namespace}
}

func resolveAuthUserRefFromStatus(instance *pocketidinternalv1alpha1.PocketIDInstance) (authUserRef, bool) {
	if instance.Status.AuthUserRef == "" {
		return authUserRef{}, false
	}

	namespace := instance.Status.AuthUserNamespace
	if namespace == "" {
		namespace = instance.Namespace
	}

	return authUserRef{
		Name:      instance.Status.AuthUserRef,
		Namespace: namespace,
	}, true
}
