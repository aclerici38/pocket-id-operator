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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
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
		namespace = "default"
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
	})

})
