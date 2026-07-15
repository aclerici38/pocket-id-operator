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

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

var _ = Describe("PocketIDAPI Controller", func() {
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
		const resourceName = "test-api-no-instance"

		AfterEach(func() {
			resource := &pocketidinternalv1alpha1.PocketIDAPI{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: namespace}, resource); err == nil {
				_ = k8sClient.Delete(ctx, resource)
			}
		})

		It("should set Ready condition to InstanceSelectionError", func() {
			resource := &pocketidinternalv1alpha1.PocketIDAPI{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: namespace},
				Spec: pocketidinternalv1alpha1.PocketIDAPISpec{
					Name:     "Orders API",
					Resource: "https://orders.example.com",
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			Eventually(func() string {
				updated := &pocketidinternalv1alpha1.PocketIDAPI{}
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

	Context("Validation", func() {
		It("should reject changing the immutable resource field", func() {
			resource := &pocketidinternalv1alpha1.PocketIDAPI{
				ObjectMeta: metav1.ObjectMeta{Name: "test-api-immutable", Namespace: namespace},
				Spec:       pocketidinternalv1alpha1.PocketIDAPISpec{Resource: "https://orders.example.com"},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, resource) })

			resource.Spec.Resource = "https://changed.example.com"
			err := k8sClient.Update(ctx, resource)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("resource is immutable"))
		})

		It("should reject a permission key that reuses a reserved OIDC scope", func() {
			resource := &pocketidinternalv1alpha1.PocketIDAPI{
				ObjectMeta: metav1.ObjectMeta{Name: "test-api-reserved-key", Namespace: namespace},
				Spec: pocketidinternalv1alpha1.PocketIDAPISpec{
					Resource: "https://reserved.example.com",
					Permissions: []pocketidinternalv1alpha1.APIPermission{
						{Key: "openid", Name: "Bad"},
					},
				},
			}
			err := k8sClient.Create(ctx, resource)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("reserved by Pocket ID"))
		})

		It("should reject a permission key with invalid scope-token characters", func() {
			resource := &pocketidinternalv1alpha1.PocketIDAPI{
				ObjectMeta: metav1.ObjectMeta{Name: "test-api-invalid-key", Namespace: namespace},
				Spec: pocketidinternalv1alpha1.PocketIDAPISpec{
					Resource: "https://invalid.example.com",
					Permissions: []pocketidinternalv1alpha1.APIPermission{
						{Key: "read orders", Name: "Bad"},
					},
				},
			}
			err := k8sClient.Create(ctx, resource)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("should match"))
		})

		It("should reject clientPermissions on a public OIDC client", func() {
			oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{Name: "test-public-client-m2m", Namespace: namespace},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					IsPublic: true,
					APIAccess: []pocketidinternalv1alpha1.OIDCClientAPIAccess{{
						APIRef:            pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders"},
						ClientPermissions: []string{"sync:orders"},
					}},
				},
			}
			err := k8sClient.Create(ctx, oidcClient)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("confidential client"))
		})

		It("should allow delegatedPermissions on a public OIDC client", func() {
			oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{Name: "test-public-client-delegated", Namespace: namespace},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					IsPublic: true,
					APIAccess: []pocketidinternalv1alpha1.OIDCClientAPIAccess{{
						APIRef:               pocketidinternalv1alpha1.NamespacedAPIReference{Name: "orders"},
						DelegatedPermissions: []string{"read:orders"},
					}},
				},
			}
			Expect(k8sClient.Create(ctx, oidcClient)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, oidcClient) })
		})
	})
})
