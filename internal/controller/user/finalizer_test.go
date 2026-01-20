package user

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
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user, instance).
		Build()

	reconciler := &Reconciler{Client: client, APIReader: client, Scheme: scheme}
	updated, err := reconciler.ReconcileUserFinalizers(context.Background(), user)
	if err != nil {
		t.Fatalf("ReconcileUserFinalizers returned error: %v", err)
	}
	if !updated {
		t.Fatal("expected finalizers to be updated")
	}

	updatedUser := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updatedUser); err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if !containsFinalizer(updatedUser.Finalizers, UserFinalizer) {
		t.Fatalf("expected finalizer to be set, got %v", updatedUser.Finalizers)
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
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{},
	}
	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "group",
			Namespace: "default",
		},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			Users: &pocketidinternalv1alpha1.UserGroupUsers{
				UserRefs: []pocketidinternalv1alpha1.NamespacedUserReference{
					{Name: user.Name, Namespace: user.Namespace},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user, instance, group).
		Build()

	reconciler := &Reconciler{Client: client, APIReader: client, Scheme: scheme}
	updated, err := reconciler.ReconcileUserFinalizers(context.Background(), user)
	if err != nil {
		t.Fatalf("ReconcileUserFinalizers returned error: %v", err)
	}
	if !updated {
		t.Fatal("expected finalizers to be updated")
	}

	updatedUser := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updatedUser); err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if !containsFinalizer(updatedUser.Finalizers, UserFinalizer) || !containsFinalizer(updatedUser.Finalizers, UserGroupUserFinalizer) {
		t.Fatalf("expected user and user-group finalizers to be set, got %v", updatedUser.Finalizers)
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
			Finalizers: []string{UserFinalizer, UserGroupUserFinalizer},
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

	reconciler := &Reconciler{Client: client, APIReader: client, Scheme: scheme}
	updated, err := reconciler.ReconcileUserFinalizers(context.Background(), user)
	if err != nil {
		t.Fatalf("ReconcileUserFinalizers returned error: %v", err)
	}
	if !updated {
		t.Fatal("expected finalizers to be updated")
	}

	updatedUser := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updatedUser); err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if containsFinalizer(updatedUser.Finalizers, UserGroupUserFinalizer) {
		t.Fatalf("expected user-group finalizer to be removed, got %v", updatedUser.Finalizers)
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
			Finalizers:        []string{UserFinalizer},
			DeletionTimestamp: &now,
		},
	}
	instance := &pocketidinternalv1alpha1.PocketIDInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "instance",
			Namespace: "default",
		},
		Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user, instance).
		Build()

	reconciler := &Reconciler{Client: client, APIReader: client, Scheme: scheme}
	if _, err := reconciler.ReconcileDelete(context.Background(), user); err != nil {
		t.Fatalf("ReconcileDelete returned error: %v", err)
	}

	updatedUser := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updatedUser); err == nil {
		if containsFinalizer(updatedUser.Finalizers, UserFinalizer) {
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
			Finalizers:        []string{UserFinalizer, UserGroupUserFinalizer},
			DeletionTimestamp: &now,
		},
	}
	group := &pocketidinternalv1alpha1.PocketIDUserGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "group",
			Namespace: "default",
		},
		Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
			Users: &pocketidinternalv1alpha1.UserGroupUsers{
				UserRefs: []pocketidinternalv1alpha1.NamespacedUserReference{
					{Name: user.Name, Namespace: user.Namespace},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user, group).
		Build()

	reconciler := &Reconciler{Client: client, APIReader: client, Scheme: scheme}
	result, err := reconciler.ReconcileDelete(context.Background(), user)
	if err != nil {
		t.Fatalf("ReconcileDelete returned error: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("expected requeue when referenced by user group, got %s", result.RequeueAfter)
	}

	updatedUser := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updatedUser); err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if !containsFinalizer(updatedUser.Finalizers, UserGroupUserFinalizer) {
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

func TestReconcileDelete_SkipsPocketIDDeletionByDefault(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "delete-skip-user",
			Namespace:         "default",
			Finalizers:        []string{UserFinalizer},
			DeletionTimestamp: &now,
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			UserID: "test-user-id",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user).
		WithStatusSubresource(user).
		Build()

	reconciler := &Reconciler{Client: client, APIReader: client, Scheme: scheme}

	// ReconcileDelete should succeed without calling Pocket-ID API
	// (no instance exists, but it should skip deletion anyway due to missing annotation)
	result, err := reconciler.ReconcileDelete(context.Background(), user)
	if err != nil {
		t.Fatalf("ReconcileDelete returned error: %v", err)
	}
	if result.RequeueAfter > 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}

	// User should be deleted (finalizer removed)
	updatedUser := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updatedUser); err == nil {
		if containsFinalizer(updatedUser.Finalizers, UserFinalizer) {
			t.Fatalf("expected finalizer to be removed, got %v", updatedUser.Finalizers)
		}
	} else if !errors.IsNotFound(err) {
		t.Fatalf("failed to get updated user: %v", err)
	}
}

func TestReconcileDelete_SkipsPocketIDDeletionWithWrongAnnotationValue(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "delete-skip-wrong-annotation",
			Namespace:         "default",
			Finalizers:        []string{UserFinalizer},
			DeletionTimestamp: &now,
			Annotations: map[string]string{
				DeleteFromPocketIDAnnotation: "false",
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			UserID: "test-user-id",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user).
		WithStatusSubresource(user).
		Build()

	reconciler := &Reconciler{Client: client, APIReader: client, Scheme: scheme}

	// ReconcileDelete should succeed without calling Pocket-ID API
	result, err := reconciler.ReconcileDelete(context.Background(), user)
	if err != nil {
		t.Fatalf("ReconcileDelete returned error: %v", err)
	}
	if result.RequeueAfter > 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}

	// User should be deleted (finalizer removed)
	updatedUser := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updatedUser); err == nil {
		if containsFinalizer(updatedUser.Finalizers, UserFinalizer) {
			t.Fatalf("expected finalizer to be removed, got %v", updatedUser.Finalizers)
		}
	} else if !errors.IsNotFound(err) {
		t.Fatalf("failed to get updated user: %v", err)
	}
}

func TestReconcileDelete_AttemptsPocketIDDeletionWithAnnotation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = pocketidinternalv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	now := metav1.NewTime(time.Now())
	user := &pocketidinternalv1alpha1.PocketIDUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "delete-with-annotation",
			Namespace:         "default",
			Finalizers:        []string{UserFinalizer},
			DeletionTimestamp: &now,
			Annotations: map[string]string{
				DeleteFromPocketIDAnnotation: "true",
			},
		},
		Status: pocketidinternalv1alpha1.PocketIDUserStatus{
			UserID: "test-user-id",
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user).
		WithStatusSubresource(user).
		Build()

	reconciler := &Reconciler{Client: client, APIReader: client, Scheme: scheme}

	// ReconcileDelete should proceed with deletion attempt
	// Since no instance exists, it will log and continue with finalizer removal
	result, err := reconciler.ReconcileDelete(context.Background(), user)
	if err != nil {
		t.Fatalf("ReconcileDelete returned error: %v", err)
	}
	if result.RequeueAfter > 0 {
		t.Fatalf("expected no requeue, got %s", result.RequeueAfter)
	}

	// User should be deleted (finalizer removed)
	updatedUser := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: user.Name, Namespace: user.Namespace}, updatedUser); err == nil {
		if containsFinalizer(updatedUser.Finalizers, UserFinalizer) {
			t.Fatalf("expected finalizer to be removed, got %v", updatedUser.Finalizers)
		}
	} else if !errors.IsNotFound(err) {
		t.Fatalf("failed to get updated user: %v", err)
	}
}
