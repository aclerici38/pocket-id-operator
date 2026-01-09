package controller

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

func TestReconcileUserFinalizers_AddsAuthFinalizer(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "auth-user",
			Namespace: "default",
		},
	}
	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "instance",
			Namespace: "default",
		},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			Auth: &pocketidinternalv1alpha1.AuthConfig{
				UserRef:    &pocketidinternalv1alpha1.NamespacedUserReference{Name: "auth-user"},
				APIKeyName: "pocket-id-operator",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user, instance).
		Build()

	reconciler := &PocketIDUserReconciler{Client: client, APIReader: client, Scheme: scheme}
	updated, err := reconciler.reconcileUserFinalizers(context.Background(), user, instance)
	if err != nil {
		t.Fatalf("reconcileUserFinalizers returned error: %v", err)
	}
	if !updated {
		t.Fatal("expected finalizers to be updated")
	}

	updatedUser := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updatedUser); err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if !containsFinalizer(updatedUser.Finalizers, userFinalizer) || !containsFinalizer(updatedUser.Finalizers, authUserFinalizer) {
		t.Fatalf("expected both finalizers to be set, got %v", updatedUser.Finalizers)
	}
}

func TestReconcileUserFinalizers_AddsAuthFinalizerFromStatus(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "auth-user",
			Namespace: "default",
		},
	}
	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "instance",
			Namespace: "default",
		},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			Auth: &pocketidinternalv1alpha1.AuthConfig{
				UserRef:    &pocketidinternalv1alpha1.NamespacedUserReference{Name: "other-user"},
				APIKeyName: "pocket-id-operator",
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDInstanceStatus{
			AuthUserRef:       "auth-user",
			AuthUserNamespace: "default",
			AuthAPIKeyName:    "pocket-id-operator",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user, instance).
		Build()

	reconciler := &PocketIDUserReconciler{Client: client, APIReader: client, Scheme: scheme}
	updated, err := reconciler.reconcileUserFinalizers(context.Background(), user, instance)
	if err != nil {
		t.Fatalf("reconcileUserFinalizers returned error: %v", err)
	}
	if !updated {
		t.Fatal("expected finalizers to be updated")
	}

	updatedUser := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updatedUser); err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if !containsFinalizer(updatedUser.Finalizers, userFinalizer) || !containsFinalizer(updatedUser.Finalizers, authUserFinalizer) {
		t.Fatalf("expected both finalizers to be set, got %v", updatedUser.Finalizers)
	}
}

func TestReconcileUserFinalizers_AddsUserGroupFinalizer(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "group-user",
			Namespace: "default",
		},
	}
	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "instance",
			Namespace: "default",
		},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			Auth: &pocketidinternalv1alpha1.AuthConfig{
				UserRef:    &pocketidinternalv1alpha1.NamespacedUserReference{Name: "other-user"},
				APIKeyName: "pocket-id-operator",
			},
		},
	}
	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "group",
			Namespace: "default",
		},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			UserRefs: []pocketidinternalv1alpha1.NamespacedUserReference{
				{Name: user.Name, Namespace: user.Namespace},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user, instance, group).
		Build()

	reconciler := &PocketIDUserReconciler{Client: client, APIReader: client, Scheme: scheme}
	updated, err := reconciler.reconcileUserFinalizers(context.Background(), user, instance)
	if err != nil {
		t.Fatalf("reconcileUserFinalizers returned error: %v", err)
	}
	if !updated {
		t.Fatal("expected finalizers to be updated")
	}

	updatedUser := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updatedUser); err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if !containsFinalizer(updatedUser.Finalizers, userFinalizer) || !containsFinalizer(updatedUser.Finalizers, userGroupUserFinalizer) {
		t.Fatalf("expected user and user-group finalizers to be set, got %v", updatedUser.Finalizers)
	}
	if containsFinalizer(updatedUser.Finalizers, authUserFinalizer) {
		t.Fatalf("expected auth finalizer to be unset, got %v", updatedUser.Finalizers)
	}
}

func TestReconcileUserFinalizers_RemovesUserGroupFinalizerWhenUnreferenced(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "group-user-cleanup",
			Namespace:  "default",
			Finalizers: []string{userFinalizer, userGroupUserFinalizer},
		},
	}
	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "instance",
			Namespace: "default",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user, instance).
		Build()

	reconciler := &PocketIDUserReconciler{Client: client, APIReader: client, Scheme: scheme}
	updated, err := reconciler.reconcileUserFinalizers(context.Background(), user, instance)
	if err != nil {
		t.Fatalf("reconcileUserFinalizers returned error: %v", err)
	}
	if !updated {
		t.Fatal("expected finalizers to be updated")
	}

	updatedUser := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updatedUser); err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if containsFinalizer(updatedUser.Finalizers, userGroupUserFinalizer) {
		t.Fatalf("expected user-group finalizer to be removed, got %v", updatedUser.Finalizers)
	}
}

func TestReconcileDelete_BlocksWhenReferenced(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "auth-user",
			Namespace:         "default",
			Finalizers:        []string{userFinalizer, authUserFinalizer},
			DeletionTimestamp: &now,
		},
	}
	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "instance",
			Namespace: "default",
		},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			Auth: &pocketidinternalv1alpha1.AuthConfig{
				UserRef:    &pocketidinternalv1alpha1.NamespacedUserReference{Name: "auth-user"},
				APIKeyName: "pocket-id-operator",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user, instance).
		Build()

	reconciler := &PocketIDUserReconciler{Client: client, APIReader: client, Scheme: scheme}
	result, err := reconciler.reconcileDelete(context.Background(), user)
	if err != nil {
		t.Fatalf("reconcileDelete returned error: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("expected requeue when referenced, got %s", result.RequeueAfter)
	}

	updatedUser := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updatedUser); err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if !containsFinalizer(updatedUser.Finalizers, userFinalizer) || !containsFinalizer(updatedUser.Finalizers, authUserFinalizer) {
		t.Fatalf("expected finalizers to remain, got %v", updatedUser.Finalizers)
	}
}

func TestReconcileDelete_BlocksWhenStatusReferenced(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "auth-user",
			Namespace:         "default",
			Finalizers:        []string{userFinalizer, authUserFinalizer},
			DeletionTimestamp: &now,
		},
	}
	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "instance",
			Namespace: "default",
		},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			Auth: &pocketidinternalv1alpha1.AuthConfig{
				UserRef:    &pocketidinternalv1alpha1.NamespacedUserReference{Name: "other-user"},
				APIKeyName: "pocket-id-operator",
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDInstanceStatus{
			AuthUserRef:       "auth-user",
			AuthUserNamespace: "default",
			AuthAPIKeyName:    "pocket-id-operator",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user, instance).
		Build()

	reconciler := &PocketIDUserReconciler{Client: client, APIReader: client, Scheme: scheme}
	result, err := reconciler.reconcileDelete(context.Background(), user)
	if err != nil {
		t.Fatalf("reconcileDelete returned error: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("expected requeue when referenced, got %s", result.RequeueAfter)
	}

	updatedUser := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updatedUser); err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if !containsFinalizer(updatedUser.Finalizers, userFinalizer) || !containsFinalizer(updatedUser.Finalizers, authUserFinalizer) {
		t.Fatalf("expected finalizers to remain, got %v", updatedUser.Finalizers)
	}
}

func TestReconcileDelete_RemovesFinalizersWhenUnreferenced(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "auth-user",
			Namespace:         "default",
			Finalizers:        []string{userFinalizer, authUserFinalizer},
			DeletionTimestamp: &now,
		},
	}
	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "instance",
			Namespace: "default",
		},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
			Auth: &pocketidinternalv1alpha1.AuthConfig{
				UserRef:    &pocketidinternalv1alpha1.NamespacedUserReference{Name: "other-user"},
				APIKeyName: "pocket-id-operator",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user, instance).
		Build()

	reconciler := &PocketIDUserReconciler{Client: client, APIReader: client, Scheme: scheme}
	if _, err := reconciler.reconcileDelete(context.Background(), user); err != nil {
		t.Fatalf("reconcileDelete returned error: %v", err)
	}

	updatedUser := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updatedUser); err == nil {
		if containsFinalizer(updatedUser.Finalizers, userFinalizer) || containsFinalizer(updatedUser.Finalizers, authUserFinalizer) {
			t.Fatalf("expected finalizers to be removed, got %v", updatedUser.Finalizers)
		}
	} else if !errors.IsNotFound(err) {
		t.Fatalf("failed to get updated user: %v", err)
	}
}

func TestReconcileDelete_BlocksWhenUserGroupReferences(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "group-referenced-user",
			Namespace:         "default",
			Finalizers:        []string{userFinalizer},
			DeletionTimestamp: &now,
		},
	}
	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "group",
			Namespace: "default",
		},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			UserRefs: []pocketidinternalv1alpha1.NamespacedUserReference{
				{Name: user.Name, Namespace: user.Namespace},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user, group).
		Build()

	reconciler := &PocketIDUserReconciler{Client: client, APIReader: client, Scheme: scheme}
	result, err := reconciler.reconcileDelete(context.Background(), user)
	if err != nil {
		t.Fatalf("reconcileDelete returned error: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("expected requeue when referenced by user group, got %s", result.RequeueAfter)
	}

	updatedUser := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updatedUser); err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if !containsFinalizer(updatedUser.Finalizers, userGroupUserFinalizer) {
		t.Fatalf("expected user-group finalizer to remain, got %v", updatedUser.Finalizers)
	}
}

func containsFinalizer(finalizers []string, target string) bool {
	for _, finalizer := range finalizers {
		if finalizer == target {
			return true
		}
	}
	return false
}
