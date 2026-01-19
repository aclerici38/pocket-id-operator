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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/oidcclient"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

// PocketIDOIDCClientReconciler is an alias for tests
type PocketIDOIDCClientReconciler = oidcclient.Reconciler

var _ = Describe("PocketIDOIDCClient Controller", func() {
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
		const resourceName = "test-oidc-client-no-instance"

		AfterEach(func() {
			resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: namespace}, resource)
			if err == nil {
				_ = k8sClient.Delete(ctx, resource)
			}
		})

		It("should set Ready condition to InstanceSelectionError", func() {
			resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			Eventually(func() string {
				updated := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
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

	Context("Resolving allowed user groups", func() {
		const (
			groupName  = "test-oidc-group"
			clientName = "test-oidc-group-client"
		)

		var reconciler *PocketIDOIDCClientReconciler

		BeforeEach(func() {
			reconciler = &PocketIDOIDCClientReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
		})

		AfterEach(func() {
			group := &pocketidinternalv1alpha1.PocketIDUserGroup{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: groupName, Namespace: namespace}, group); err == nil {
				_ = k8sClient.Delete(ctx, group)
			}
		})

		It("should resolve group IDs when group is ready", func() {
			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      groupName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
					Name:         "group-name",
					FriendlyName: "Group Name",
				},
			}
			Expect(k8sClient.Create(ctx, group)).To(Succeed())

			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: groupName, Namespace: namespace}, group)
			}, timeout, interval).Should(Succeed())

			// Set up the status - use Eventually because the controller may be racing with us
			Eventually(func() error {
				return retry.RetryOnConflict(retry.DefaultRetry, func() error {
					if err := k8sClient.Get(ctx, types.NamespacedName{Name: groupName, Namespace: namespace}, group); err != nil {
						return err
					}
					group.Status.GroupID = "group-id-1"
					group.Status.Conditions = []metav1.Condition{
						{
							Type:               "Ready",
							Status:             metav1.ConditionTrue,
							Reason:             "Reconciled",
							LastTransitionTime: metav1.Now(),
						},
					}
					return k8sClient.Status().Update(ctx, group)
				})
			}, timeout, interval).Should(Succeed())

			client := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
						{Name: groupName},
					},
				},
			}

			// Use Eventually because the controller may overwrite our status update
			Eventually(func() ([]string, error) {
				return reconciler.ResolveAllowedUserGroups(ctx, client)
			}, timeout, interval).Should(Equal([]string{"group-id-1"}))
		})

		It("should error when a group is missing", func() {
			client := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
						{Name: "missing-group"},
					},
				},
			}

			_, err := reconciler.ResolveAllowedUserGroups(ctx, client)
			Expect(err).To(HaveOccurred())
		})

		It("should error when a group ref has an empty name", func() {
			client := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
						{Name: ""},
					},
				},
			}

			_, err := reconciler.ResolveAllowedUserGroups(ctx, client)
			Expect(err).To(HaveOccurred())
		})

		It("should error when a group is not ready", func() {
			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "unready-group",
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
					Name:         "group-name",
					FriendlyName: "Group Name",
				},
			}
			Expect(k8sClient.Create(ctx, group)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, group)
			})

			client := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
						{Name: group.Name},
					},
				},
			}

			_, err := reconciler.ResolveAllowedUserGroups(ctx, client)
			Expect(err).To(HaveOccurred())
		})

		It("should resolve group IDs across namespaces", func() {
			otherNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "oidc-other-ns"}}
			Expect(k8sClient.Create(ctx, otherNamespace)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, otherNamespace)
			})

			group := &pocketidinternalv1alpha1.PocketIDUserGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cross-ns-group",
					Namespace: otherNamespace.Name,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserGroupSpec{
					Name:         "group-name",
					FriendlyName: "Group Name",
				},
			}
			Expect(k8sClient.Create(ctx, group)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, group)
			})

			Eventually(func() error {
				return retry.RetryOnConflict(retry.DefaultRetry, func() error {
					if err := k8sClient.Get(ctx, types.NamespacedName{Name: group.Name, Namespace: otherNamespace.Name}, group); err != nil {
						return err
					}
					group.Status.GroupID = "cross-ns-group-id"
					group.Status.Conditions = []metav1.Condition{
						{
							Type:               "Ready",
							Status:             metav1.ConditionTrue,
							Reason:             "Reconciled",
							LastTransitionTime: metav1.Now(),
						},
					}
					return k8sClient.Status().Update(ctx, group)
				})
			}, timeout, interval).Should(Succeed())

			client := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
						{Name: group.Name, Namespace: otherNamespace.Name},
					},
				},
			}

			ids, err := reconciler.ResolveAllowedUserGroups(ctx, client)
			Expect(err).NotTo(HaveOccurred())
			Expect(ids).To(Equal([]string{"cross-ns-group-id"}))
		})
	})

	Context("When instance is not ready", func() {
		const (
			instanceName = "test-oidc-instance-not-ready"
			clientName   = "test-oidc-client-not-ready"
		)

		AfterEach(func() {
			resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: clientName, Namespace: namespace}, resource); err == nil {
				_ = k8sClient.Delete(ctx, resource)
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

			resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			Eventually(func() string {
				updated := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: clientName, Namespace: namespace}, updated); err != nil {
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
			instanceNameA = "test-oidc-instance-a"
			instanceNameB = "test-oidc-instance-b"
			clientName    = "test-oidc-client-multi-instance"
		)

		AfterEach(func() {
			resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: clientName, Namespace: namespace}, resource); err == nil {
				_ = k8sClient.Delete(ctx, resource)
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

			resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			Eventually(func() string {
				updated := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: clientName, Namespace: namespace}, updated); err != nil {
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

	Context("ClientID immutability", func() {
		It("should reject updates when clientId is changed", func() {
			clientName := "test-oidc-clientid-change"
			resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					ClientID: "client-one",
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, resource)
			})

			err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				current := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: clientName, Namespace: namespace}, current); err != nil {
					return err
				}
				current.Spec.ClientID = "client-two"
				return k8sClient.Update(ctx, current)
			})

			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsInvalid(err)).To(BeTrue())
		})

		It("should reject updates when clientId is set after creation", func() {
			clientName := "test-oidc-clientid-set"
			resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			DeferCleanup(func() {
				_ = k8sClient.Delete(ctx, resource)
			})

			err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				current := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: clientName, Namespace: namespace}, current); err != nil {
					return err
				}
				current.Spec.ClientID = "client-new"
				return k8sClient.Update(ctx, current)
			})

			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsInvalid(err)).To(BeTrue())
		})
	})

	Context("Updating OIDC client status", func() {
		const clientName = "test-oidc-status-update"

		AfterEach(func() {
			resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: clientName, Namespace: namespace}, resource); err == nil {
				_ = k8sClient.Delete(ctx, resource)
			}
		})

		It("should patch status from Pocket-ID response", func() {
			resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			reconciler := &PocketIDOIDCClientReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			current := &pocketid.OIDCClient{
				ID:                  "client-id",
				Name:                "Test OIDC Client",
				AllowedUserGroupIDs: []string{"group-1"},
			}
			Expect(reconciler.UpdateOIDCClientStatus(ctx, resource, current)).To(Succeed())

			updated := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: clientName, Namespace: namespace}, updated)).To(Succeed())
			Expect(updated.Status.ClientID).To(Equal("client-id"))
			Expect(updated.Status.AllowedUserGroupIDs).To(Equal([]string{"group-1"}))
		})
	})
})
