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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/usergroup"
)

// Type alias for backward compatibility with tests
type PocketIDUserGroupReconciler = usergroup.Reconciler

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
					EncryptionKey: pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
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
					EncryptionKey: pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceNameB,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.SensitiveValue{Value: "fedcba9876543210"},
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
})
