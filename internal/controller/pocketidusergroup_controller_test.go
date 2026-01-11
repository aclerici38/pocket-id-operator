/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

var _ = Describe("PocketIDUserGroup Controller", func() {
	const (
		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	var (
		ctx       context.Context
		namespace string
	)

	BeforeEach(func() {
		ctx = context.Background()
		namespace = defaultNamespace
	})

	Context("When no instance exists", func() {
		const resourceName = "test-user-group-no-instance"

		AfterEach(func() {
			resource := &pocketidinternalv1alpha1.PocketIDUserGroup{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: namespace}, resource)
			if err == nil {
				_ = k8sClient.Delete(ctx, resource)
			}
		})

		It("should set Ready condition to InstanceSelectionError", func() {
			resource := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
					Name:         "example-group",
					FriendlyName: "Example Group",
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			Eventually(func() string {
				updated := &pocketidinternalv1alpha1.PocketIDUserGroup{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: namespace}, updated); err != nil {
					return ""
				}
				cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
				if cond == nil {
					return ""
				}
				return cond.Reason
			}, timeout, interval).Should(Equal("InstanceSelectionError"))
		})
	})

	Context("Resolving user refs", func() {
		const (
			userName  = "test-user-group-user"
			groupName = "test-user-group"
		)

		var reconciler *PocketIDUserGroupReconciler

		BeforeEach(func() {
			reconciler = &PocketIDUserGroupReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
		})

		AfterEach(func() {
			user := &pocketidinternalv1alpha1.PocketIDUser{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: userName, Namespace: namespace}, user); err == nil {
				_ = k8sClient.Delete(ctx, user)
			}
		})

		It("should resolve user IDs when users are ready", func() {
			user := &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					Username: pocketidinternalv1alpha1.StringValue{Value: "user"},
				},
			}
			Expect(k8sClient.Create(ctx, user)).To(Succeed())

			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: userName, Namespace: namespace}, user)
			}, timeout, interval).Should(Succeed())

			Eventually(func() error {
				return retry.RetryOnConflict(retry.DefaultRetry, func() error {
					if err := k8sClient.Get(ctx, types.NamespacedName{Name: userName, Namespace: namespace}, user); err != nil {
						return err
					}
					user.Status.UserID = "user-id-1"
					user.Status.Conditions = []metav1.Condition{
						{
							Type:               "Ready",
							Status:             metav1.ConditionTrue,
							Reason:             "Reconciled",
							LastTransitionTime: metav1.Now(),
						},
					}
					return k8sClient.Status().Update(ctx, user)
				})
			}, timeout, interval).Should(Succeed())

			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      groupName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
					Name:         "group",
					FriendlyName: "Group",
					UserRefs: []pocketidinternalv1alpha1.NamespacedUserReference{
						{Name: userName},
					},
				},
			}

			ids, err := reconciler.resolveUserRefs(ctx, group)
			Expect(err).NotTo(HaveOccurred())
			Expect(ids).To(Equal([]string{"user-id-1"}))
		})

		It("should error when a user is missing", func() {
			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      groupName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
					Name:         "group",
					FriendlyName: "Group",
					UserRefs: []pocketidinternalv1alpha1.NamespacedUserReference{
						{Name: "missing-user"},
					},
				},
			}

			_, err := reconciler.resolveUserRefs(ctx, group)
			Expect(err).To(HaveOccurred())
		})

		It("should error when a user ref has an empty name", func() {
			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      groupName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
					Name:         "group",
					FriendlyName: "Group",
					UserRefs: []pocketidinternalv1alpha1.NamespacedUserReference{
						{Name: ""},
					},
				},
			}

			_, err := reconciler.resolveUserRefs(ctx, group)
			Expect(err).To(HaveOccurred())
		})

		It("should error when a user is not ready", func() {
			user := &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "unready-user",
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					Username: pocketidinternalv1alpha1.StringValue{Value: "unready-user"},
				},
			}
			Expect(k8sClient.Create(ctx, user)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, user)
			})

			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      groupName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
					Name:         "group",
					FriendlyName: "Group",
					UserRefs: []pocketidinternalv1alpha1.NamespacedUserReference{
						{Name: user.Name},
					},
				},
			}

			_, err := reconciler.resolveUserRefs(ctx, group)
			Expect(err).To(HaveOccurred())
		})

		It("should resolve user IDs across namespaces", func() {
			otherNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "usergroup-other-ns"}}
			Expect(k8sClient.Create(ctx, otherNamespace)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, otherNamespace)
			})

			user := &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cross-ns-user",
					Namespace: otherNamespace.Name,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					Username: pocketidinternalv1alpha1.StringValue{Value: "cross-ns-user"},
				},
			}
			Expect(k8sClient.Create(ctx, user)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, user)
			})

			Eventually(func() error {
				return retry.RetryOnConflict(retry.DefaultRetry, func() error {
					if err := k8sClient.Get(ctx, types.NamespacedName{Name: user.Name, Namespace: otherNamespace.Name}, user); err != nil {
						return err
					}
					user.Status.UserID = "cross-ns-id"
					user.Status.Conditions = []metav1.Condition{
						{
							Type:               "Ready",
							Status:             metav1.ConditionTrue,
							Reason:             "Reconciled",
							LastTransitionTime: metav1.Now(),
						},
					}
					return k8sClient.Status().Update(ctx, user)
				})
			}, timeout, interval).Should(Succeed())

			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      groupName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
					Name:         "group",
					FriendlyName: "Group",
					UserRefs: []pocketidinternalv1alpha1.NamespacedUserReference{
						{Name: user.Name, Namespace: otherNamespace.Name},
					},
				},
			}

			ids, err := reconciler.resolveUserRefs(ctx, group)
			Expect(err).NotTo(HaveOccurred())
			Expect(ids).To(Equal([]string{"cross-ns-id"}))
		})
	})

	Context("When instance is not ready", func() {
		const (
			instanceName = "test-user-group-instance-not-ready"
			groupName    = "test-user-group-not-ready"
		)

		AfterEach(func() {
			group := &pocketidinternalv1alpha1.PocketIDUserGroup{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: groupName, Namespace: namespace}, group); err == nil {
				_ = k8sClient.Delete(ctx, group)
			}
			instance := &pocketidinternalv1alpha1.PocketIDInstance{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: instanceName, Namespace: namespace}, instance); err == nil {
				_ = k8sClient.Delete(ctx, instance)
			}
		})

		It("should set Ready condition to InstanceNotReady", func() {
			instance := &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{Value: "0123456789abcdef"},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())

			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      groupName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
					Name:         "example-group",
					FriendlyName: "Example Group",
				},
			}
			Expect(k8sClient.Create(ctx, group)).To(Succeed())

			Eventually(func() string {
				updated := &pocketidinternalv1alpha1.PocketIDUserGroup{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: groupName, Namespace: namespace}, updated); err != nil {
					return ""
				}
				cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
				if cond == nil {
					return ""
				}
				return cond.Reason
			}, timeout, interval).Should(Equal("InstanceNotReady"))
		})
	})

	Context("When multiple instances exist", func() {
		const (
			instanceNameA = "test-user-group-instance-a"
			instanceNameB = "test-user-group-instance-b"
			groupName     = "test-user-group-multi-instance"
		)

		AfterEach(func() {
			group := &pocketidinternalv1alpha1.PocketIDUserGroup{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: groupName, Namespace: namespace}, group); err == nil {
				_ = k8sClient.Delete(ctx, group)
			}
			instance := &pocketidinternalv1alpha1.PocketIDInstance{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: instanceNameA, Namespace: namespace}, instance); err == nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			instance = &pocketidinternalv1alpha1.PocketIDInstance{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: instanceNameB, Namespace: namespace}, instance); err == nil {
				_ = k8sClient.Delete(ctx, instance)
			}
		})

		It("should set Ready condition to InstanceSelectionError", func() {
			instance := &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceNameA,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{Value: "0123456789abcdef"},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceNameB,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{Value: "fedcba9876543210"},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())

			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      groupName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
					Name:         "example-group",
					FriendlyName: "Example Group",
				},
			}
			Expect(k8sClient.Create(ctx, group)).To(Succeed())

			Eventually(func() string {
				updated := &pocketidinternalv1alpha1.PocketIDUserGroup{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: groupName, Namespace: namespace}, updated); err != nil {
					return ""
				}
				cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
				if cond == nil {
					return ""
				}
				return cond.Reason
			}, timeout, interval).Should(Equal("InstanceSelectionError"))
		})
	})

	Context("When API client cannot be created", func() {
		const (
			instanceName = "test-user-group-api-client-error"
			groupName    = "test-user-group-api-client-error"
		)

		It("should set Ready condition to APIClientNotReady", func() {
			scheme := runtime.NewScheme()
			_ = pocketidinternalv1alpha1.AddToScheme(scheme)
			_ = corev1.AddToScheme(scheme)

			instance := &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					Auth: &pocketidinternalv1alpha1.AuthConfig{
						UserRef:    &pocketidinternalv1alpha1.NamespacedUserReference{Name: "missing-user"},
						APIKeyName: "missing-key",
					},
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{Value: "0123456789abcdef"},
				},
				Status: pocketidinternalv1alpha1.PocketIDInstanceStatus{
					Bootstrapped: true,
					Conditions: []metav1.Condition{
						{
							Type:               "Available",
							Status:             metav1.ConditionTrue,
							Reason:             "Ready",
							Message:            "Instance is ready",
							LastTransitionTime: metav1.Now(),
						},
						{
							Type:               "Ready",
							Status:             metav1.ConditionTrue,
							Reason:             "Ready",
							Message:            "Instance is ready with auth configured",
							LastTransitionTime: metav1.Now(),
						},
					},
				},
			}

			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      groupName,
					Namespace: namespace,
					Finalizers: []string{
						userGroupFinalizer,
					},
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
					Name:         "example-group",
					FriendlyName: "Example Group",
				},
			}
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithStatusSubresource(group).
				WithObjects(instance, group).
				Build()

			reconciler := &PocketIDUserGroupReconciler{
				Client: fakeClient,
				Scheme: scheme,
			}

			_, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: groupName, Namespace: namespace},
			})
			Expect(err).NotTo(HaveOccurred())

			updated := &pocketidinternalv1alpha1.PocketIDUserGroup{}
			Expect(fakeClient.Get(ctx, types.NamespacedName{Name: groupName, Namespace: namespace}, updated)).To(Succeed())
			cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
			Expect(cond).NotTo(BeNil())
			Expect(cond.Reason).To(Equal("APIClientNotReady"))
		})
	})

	Context("Updating user group status", func() {
		const groupName = "test-user-group-status-update"

		AfterEach(func() {
			group := &pocketidinternalv1alpha1.PocketIDUserGroup{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: groupName, Namespace: namespace}, group); err == nil {
				_ = k8sClient.Delete(ctx, group)
			}
		})

		It("should patch status from Pocket-ID response", func() {
			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      groupName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
					Name:         "group",
					FriendlyName: "Group",
				},
			}
			Expect(k8sClient.Create(ctx, group)).To(Succeed())

			reconciler := &PocketIDUserGroupReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			current := &pocketid.UserGroup{
				ID:           "group-id",
				Name:         "group",
				FriendlyName: "Group",
				CreatedAt:    "2026-01-01T00:00:00Z",
				LdapID:       "ldap-id",
				UserCount:    2,
				CustomClaims: []pocketid.CustomClaim{{Key: "role", Value: "admin"}},
			}
			Expect(reconciler.updateUserGroupStatus(ctx, group, current)).To(Succeed())

			updated := &pocketidinternalv1alpha1.PocketIDUserGroup{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: groupName, Namespace: namespace}, updated)).To(Succeed())
			Expect(updated.Status.GroupID).To(Equal("group-id"))
			Expect(updated.Status.FriendlyName).To(Equal("Group"))
			Expect(updated.Status.UserCount).To(Equal(2))
			Expect(updated.Status.CustomClaims).To(Equal([]pocketidinternalv1alpha1.CustomClaim{
				{Key: "role", Value: "admin"},
			}))
		})
	})

	Context("OIDC client finalizers", func() {
		It("should add OIDC client finalizer when referenced", func() {
			scheme := runtime.NewScheme()
			_ = pocketidinternalv1alpha1.AddToScheme(scheme)

			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "finalizer-group",
					Namespace: namespace,
				},
			}

			oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "finalizer-oidc-client",
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
						{Name: group.Name},
					},
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(group, oidcClient).
				Build()

			reconciler := &PocketIDUserGroupReconciler{Client: fakeClient, Scheme: scheme}
			updated, err := reconciler.reconcileUserGroupFinalizers(context.Background(), group)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated).To(BeTrue())

			updatedGroup := &pocketidinternalv1alpha1.PocketIDUserGroup{}
			Expect(fakeClient.Get(context.Background(), types.NamespacedName{Name: group.Name, Namespace: group.Namespace}, updatedGroup)).To(Succeed())
			Expect(updatedGroup.Finalizers).To(ContainElement(userGroupFinalizer))
			Expect(updatedGroup.Finalizers).To(ContainElement(oidcClientUserGroupFinalizer))
		})

		It("should remove OIDC client finalizer when unreferenced", func() {
			scheme := runtime.NewScheme()
			_ = pocketidinternalv1alpha1.AddToScheme(scheme)

			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "finalizer-group-cleanup",
					Namespace:  namespace,
					Finalizers: []string{userGroupFinalizer, oidcClientUserGroupFinalizer},
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(group).
				Build()

			reconciler := &PocketIDUserGroupReconciler{Client: fakeClient, Scheme: scheme}
			updated, err := reconciler.reconcileUserGroupFinalizers(context.Background(), group)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated).To(BeTrue())

			updatedGroup := &pocketidinternalv1alpha1.PocketIDUserGroup{}
			Expect(fakeClient.Get(context.Background(), types.NamespacedName{Name: group.Name, Namespace: group.Namespace}, updatedGroup)).To(Succeed())
			Expect(updatedGroup.Finalizers).To(ContainElement(userGroupFinalizer))
			Expect(updatedGroup.Finalizers).NotTo(ContainElement(oidcClientUserGroupFinalizer))
		})

		It("should block deletion when referenced by an OIDC client", func() {
			scheme := runtime.NewScheme()
			_ = pocketidinternalv1alpha1.AddToScheme(scheme)

			now := metav1.NewTime(time.Now())
			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "finalizer-group-delete",
					Namespace:         namespace,
					Finalizers:        []string{userGroupFinalizer},
					DeletionTimestamp: &now,
				},
			}

			oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "finalizer-oidc-client-delete",
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
						{Name: group.Name},
					},
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(group, oidcClient).
				Build()

			reconciler := &PocketIDUserGroupReconciler{Client: fakeClient, Scheme: scheme}
			result, err := reconciler.reconcileDelete(context.Background(), group)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			updatedGroup := &pocketidinternalv1alpha1.PocketIDUserGroup{}
			Expect(fakeClient.Get(context.Background(), types.NamespacedName{Name: group.Name, Namespace: group.Namespace}, updatedGroup)).To(Succeed())
			Expect(updatedGroup.Finalizers).To(ContainElement(oidcClientUserGroupFinalizer))
		})
	})

	Context("Delete behavior", func() {
		It("should remove finalizer when no instance exists", func() {
			scheme := runtime.NewScheme()
			_ = pocketidinternalv1alpha1.AddToScheme(scheme)

			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "delete-no-instance-group",
					Namespace:  namespace,
					Finalizers: []string{userGroupFinalizer},
				},
				Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{
					GroupID: "group-id",
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(group).
				Build()

			reconciler := &PocketIDUserGroupReconciler{Client: fakeClient, Scheme: scheme}
			_, err := reconciler.reconcileDelete(context.Background(), group)
			Expect(err).NotTo(HaveOccurred())

			updated := &pocketidinternalv1alpha1.PocketIDUserGroup{}
			Expect(fakeClient.Get(context.Background(), types.NamespacedName{Name: group.Name, Namespace: group.Namespace}, updated)).To(Succeed())
			Expect(updated.Finalizers).NotTo(ContainElement(userGroupFinalizer))
		})

		It("should keep finalizer when API client lookup is not ready", func() {
			scheme := runtime.NewScheme()
			_ = pocketidinternalv1alpha1.AddToScheme(scheme)

			instance := &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "delete-instance",
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					Auth: &pocketidinternalv1alpha1.AuthConfig{
						UserRef:    &pocketidinternalv1alpha1.NamespacedUserReference{Name: "missing-user"},
						APIKeyName: "missing-key",
					},
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{Value: "0123456789abcdef"},
				},
			}

			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "delete-api-client-error-group",
					Namespace:  namespace,
					Finalizers: []string{userGroupFinalizer},
				},
				Status: pocketidinternalv1alpha1.PocketIDUserGroupStatus{
					GroupID: "group-id",
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(instance, group).
				Build()

			reconciler := &PocketIDUserGroupReconciler{Client: fakeClient, Scheme: scheme}
			_, err := reconciler.reconcileDelete(context.Background(), group)
			Expect(err).NotTo(HaveOccurred())

			updated := &pocketidinternalv1alpha1.PocketIDUserGroup{}
			Expect(fakeClient.Get(context.Background(), types.NamespacedName{Name: group.Name, Namespace: group.Namespace}, updated)).To(Succeed())
			Expect(updated.Finalizers).To(ContainElement(userGroupFinalizer))
		})
	})

})
