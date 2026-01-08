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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

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
		namespace = "default"
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
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					Name: "Test OIDC Client",
				},
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

			Eventually(func() error {
				return retry.RetryOnConflict(retry.DefaultRetry, func() error {
					if err := k8sClient.Get(ctx, types.NamespacedName{Name: groupName, Namespace: namespace}, group); err != nil {
						return err
					}
					group.Status.GroupID = "group-id-1"
					return k8sClient.Status().Update(ctx, group)
				})
			}, timeout, interval).Should(Succeed())

			client := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					Name: "Client",
					AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
						{Name: groupName},
					},
				},
			}

			ids, err := reconciler.resolveAllowedUserGroups(ctx, client)
			Expect(err).NotTo(HaveOccurred())
			Expect(ids).To(Equal([]string{"group-id-1"}))
		})

		It("should error when a group is missing", func() {
			client := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					Name: "Client",
					AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
						{Name: "missing-group"},
					},
				},
			}

			_, err := reconciler.resolveAllowedUserGroups(ctx, client)
			Expect(err).To(HaveOccurred())
		})
	})

})
