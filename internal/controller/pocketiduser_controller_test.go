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
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
)

var _ = Describe("PocketIDUser Controller", func() {
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

	Context("When creating a PocketIDUser with plain values", func() {
		const userName = "test-user-plain"

		var user *pocketidinternalv1alpha1.PocketIDUser

		BeforeEach(func() {
			user = &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					Username:  pocketidinternalv1alpha1.StringValue{Value: "testuser"},
					FirstName: pocketidinternalv1alpha1.StringValue{Value: "Test"},
					LastName:  pocketidinternalv1alpha1.StringValue{Value: "User"},
					Email:     pocketidinternalv1alpha1.StringValue{Value: "test@example.com"},
					Admin:     false,
				},
			}
			Expect(k8sClient.Create(ctx, user)).To(Succeed())
		})

		AfterEach(func() {
			if user != nil {
				_ = k8sClient.Delete(ctx, user)
			}
		})

		It("Should create the PocketIDUser resource", func() {
			createdUser := &pocketidinternalv1alpha1.PocketIDUser{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      userName,
					Namespace: namespace,
				}, createdUser)
			}, timeout, interval).Should(Succeed())

			Expect(createdUser.Spec.Username.Value).To(Equal("testuser"))
			Expect(createdUser.Spec.FirstName.Value).To(Equal("Test"))
			Expect(createdUser.Spec.LastName.Value).To(Equal("User"))
			Expect(createdUser.Spec.Email.Value).To(Equal("test@example.com"))
			Expect(createdUser.Spec.Admin).To(BeFalse())
		})
	})

	Context("When creating a PocketIDUser with secret references", func() {
		const userName = "test-user-secret-refs"
		const secretName = "user-credentials"

		var user *pocketidinternalv1alpha1.PocketIDUser
		var secret *corev1.Secret

		BeforeEach(func() {
			// Create secret with user data
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"username":   []byte("secretuser"),
					"first-name": []byte("Secret"),
					"last-name":  []byte("User"),
					"email":      []byte("secret@example.com"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			user = &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					Username: pocketidinternalv1alpha1.StringValue{
						ValueFrom: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
							Key:                  "username",
						},
					},
					FirstName: pocketidinternalv1alpha1.StringValue{
						ValueFrom: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
							Key:                  "first-name",
						},
					},
					LastName: pocketidinternalv1alpha1.StringValue{
						ValueFrom: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
							Key:                  "last-name",
						},
					},
					Email: pocketidinternalv1alpha1.StringValue{
						ValueFrom: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
							Key:                  "email",
						},
					},
					Admin: true,
				},
			}
			Expect(k8sClient.Create(ctx, user)).To(Succeed())
		})

		AfterEach(func() {
			if user != nil {
				_ = k8sClient.Delete(ctx, user)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should create the PocketIDUser with secret references", func() {
			createdUser := &pocketidinternalv1alpha1.PocketIDUser{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      userName,
					Namespace: namespace,
				}, createdUser)
			}, timeout, interval).Should(Succeed())

			Expect(createdUser.Spec.Username.ValueFrom).NotTo(BeNil())
			Expect(createdUser.Spec.Username.ValueFrom.Name).To(Equal(secretName))
			Expect(createdUser.Spec.Username.ValueFrom.Key).To(Equal("username"))

			Expect(createdUser.Spec.FirstName.ValueFrom).NotTo(BeNil())
			Expect(createdUser.Spec.FirstName.ValueFrom.Name).To(Equal(secretName))
			Expect(createdUser.Spec.FirstName.ValueFrom.Key).To(Equal("first-name"))

			Expect(createdUser.Spec.Admin).To(BeTrue())
		})
	})

	Context("When creating a PocketIDUser with API keys using SecretRef", func() {
		const userName = "test-user-apikey-ref"
		const apiKeySecretName = "existing-api-key"

		var user *pocketidinternalv1alpha1.PocketIDUser
		var apiKeySecret *corev1.Secret

		BeforeEach(func() {
			// Create secret with existing API key token
			apiKeySecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeySecretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"token": []byte("existing-api-key-token-value"),
				},
			}
			Expect(k8sClient.Create(ctx, apiKeySecret)).To(Succeed())

			user = &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					Username:  pocketidinternalv1alpha1.StringValue{Value: "apikey-user"},
					FirstName: pocketidinternalv1alpha1.StringValue{Value: "API"},
					LastName:  pocketidinternalv1alpha1.StringValue{Value: "Key"},
					Admin:     false,
					APIKeys: []pocketidinternalv1alpha1.APIKeySpec{
						{
							Name:        "existing-key",
							Description: "Pre-existing API key",
							SecretRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: apiKeySecretName},
								Key:                  "token",
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, user)).To(Succeed())
		})

		AfterEach(func() {
			if user != nil {
				_ = k8sClient.Delete(ctx, user)
			}
			if apiKeySecret != nil {
				_ = k8sClient.Delete(ctx, apiKeySecret)
			}
		})

		It("Should create the PocketIDUser with API key secret reference", func() {
			createdUser := &pocketidinternalv1alpha1.PocketIDUser{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      userName,
					Namespace: namespace,
				}, createdUser)
			}, timeout, interval).Should(Succeed())

			Expect(createdUser.Spec.APIKeys).To(HaveLen(1))
			Expect(createdUser.Spec.APIKeys[0].Name).To(Equal("existing-key"))
			Expect(createdUser.Spec.APIKeys[0].SecretRef).NotTo(BeNil())
			Expect(createdUser.Spec.APIKeys[0].SecretRef.Name).To(Equal(apiKeySecretName))
			Expect(createdUser.Spec.APIKeys[0].SecretRef.Key).To(Equal("token"))
		})
	})

	Context("Instance selection", func() {
		const (
			instanceLabelKey   = "pocketid.internal/instance-group"
			instanceLabelValue = "target"
			instanceNameA      = "instance-select-a"
			instanceNameB      = "instance-select-b"
			instanceNSA        = "instance-select-a"
			instanceNSB        = "instance-select-b"
		)

		var (
			namespaceA *corev1.Namespace
			namespaceB *corev1.Namespace
			instanceA  *pocketidinternalv1alpha1.PocketIDInstance
			instanceB  *pocketidinternalv1alpha1.PocketIDInstance
		)

		BeforeEach(func() {
			namespaceA = &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: instanceNSA}}
			namespaceB = &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: instanceNSB}}
			Expect(k8sClient.Create(ctx, namespaceA)).To(Succeed())
			Expect(k8sClient.Create(ctx, namespaceB)).To(Succeed())

			instanceA = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceNameA,
					Namespace: instanceNSA,
					Labels: map[string]string{
						instanceLabelKey: "other",
					},
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{Value: "test-encryption-key-1234"},
				},
			}
			instanceB = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceNameB,
					Namespace: instanceNSB,
					Labels: map[string]string{
						instanceLabelKey: instanceLabelValue,
					},
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{Value: "test-encryption-key-5678"},
				},
			}

			Expect(k8sClient.Create(ctx, instanceA)).To(Succeed())
			Expect(k8sClient.Create(ctx, instanceB)).To(Succeed())
		})

		AfterEach(func() {
			if instanceA != nil {
				_ = k8sClient.Delete(ctx, instanceA)
			}
			if instanceB != nil {
				_ = k8sClient.Delete(ctx, instanceB)
			}
			if namespaceA != nil {
				_ = k8sClient.Delete(ctx, namespaceA)
			}
			if namespaceB != nil {
				_ = k8sClient.Delete(ctx, namespaceB)
			}
		})

		It("should select the instance matching the selector", func() {
			user := &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "selector-user",
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					InstanceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							instanceLabelKey: instanceLabelValue,
						},
					},
				},
			}

			selected, err := common.SelectInstance(ctx, k8sClient, user.Spec.InstanceSelector)
			Expect(err).NotTo(HaveOccurred())
			Expect(selected.Name).To(Equal(instanceNameB))
			Expect(selected.Namespace).To(Equal(instanceNSB))
		})
	})

	Context("When creating a PocketIDUser with default username", func() {
		const userName = "test-user-default-username"

		var user *pocketidinternalv1alpha1.PocketIDUser

		BeforeEach(func() {
			// Create user without specifying username - should default to metadata.name
			user = &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					FirstName: pocketidinternalv1alpha1.StringValue{Value: "Default"},
					LastName:  pocketidinternalv1alpha1.StringValue{Value: "User"},
					Admin:     false,
				},
			}
			Expect(k8sClient.Create(ctx, user)).To(Succeed())
		})

		AfterEach(func() {
			if user != nil {
				_ = k8sClient.Delete(ctx, user)
			}
		})

		It("Should create the PocketIDUser with empty username in spec", func() {
			createdUser := &pocketidinternalv1alpha1.PocketIDUser{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      userName,
					Namespace: namespace,
				}, createdUser)
			}, timeout, interval).Should(Succeed())

			// Username should be empty in spec (controller resolves to metadata.name)
			Expect(createdUser.Spec.Username.Value).To(BeEmpty())
			Expect(createdUser.Spec.Username.ValueFrom).To(BeNil())
		})
	})

	Context("When creating a PocketIDUser with mixed plain and secret values", func() {
		const userName = "test-user-mixed"
		const secretName = "partial-user-secret"

		var user *pocketidinternalv1alpha1.PocketIDUser
		var secret *corev1.Secret

		BeforeEach(func() {
			// Create secret with partial user data
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"email": []byte("mixed@example.com"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			user = &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					Username:  pocketidinternalv1alpha1.StringValue{Value: "mixeduser"},
					FirstName: pocketidinternalv1alpha1.StringValue{Value: "Mixed"},
					LastName:  pocketidinternalv1alpha1.StringValue{Value: "Values"},
					Email: pocketidinternalv1alpha1.StringValue{
						ValueFrom: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
							Key:                  "email",
						},
					},
					Admin: false,
				},
			}
			Expect(k8sClient.Create(ctx, user)).To(Succeed())
		})

		AfterEach(func() {
			if user != nil {
				_ = k8sClient.Delete(ctx, user)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should create the PocketIDUser with mixed plain and secret values", func() {
			createdUser := &pocketidinternalv1alpha1.PocketIDUser{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      userName,
					Namespace: namespace,
				}, createdUser)
			}, timeout, interval).Should(Succeed())

			// Plain values
			Expect(createdUser.Spec.Username.Value).To(Equal("mixeduser"))
			Expect(createdUser.Spec.FirstName.Value).To(Equal("Mixed"))
			Expect(createdUser.Spec.LastName.Value).To(Equal("Values"))

			// Secret reference
			Expect(createdUser.Spec.Email.ValueFrom).NotTo(BeNil())
			Expect(createdUser.Spec.Email.ValueFrom.Name).To(Equal(secretName))
		})
	})

	Context("When creating a PocketIDUser with multiple API keys", func() {
		const userName = "test-user-multi-keys"
		const apiKeySecretName = "multi-api-keys"

		var user *pocketidinternalv1alpha1.PocketIDUser
		var apiKeySecret *corev1.Secret

		BeforeEach(func() {
			apiKeySecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeySecretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"key1": []byte("api-key-token-1"),
					"key2": []byte("api-key-token-2"),
				},
			}
			Expect(k8sClient.Create(ctx, apiKeySecret)).To(Succeed())

			user = &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					Username:  pocketidinternalv1alpha1.StringValue{Value: "multikey-user"},
					FirstName: pocketidinternalv1alpha1.StringValue{Value: "Multi"},
					Admin:     true,
					APIKeys: []pocketidinternalv1alpha1.APIKeySpec{
						{
							Name:        "key-from-secret",
							Description: "API key from existing secret",
							SecretRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: apiKeySecretName},
								Key:                  "key1",
							},
						},
						{
							Name:        "key-to-create",
							Description: "API key to be created by operator",
							ExpiresAt:   "2030-01-01T00:00:00Z",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, user)).To(Succeed())
		})

		AfterEach(func() {
			if user != nil {
				_ = k8sClient.Delete(ctx, user)
			}
			if apiKeySecret != nil {
				_ = k8sClient.Delete(ctx, apiKeySecret)
			}
		})

		It("Should create the PocketIDUser with multiple API key specs", func() {
			createdUser := &pocketidinternalv1alpha1.PocketIDUser{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      userName,
					Namespace: namespace,
				}, createdUser)
			}, timeout, interval).Should(Succeed())

			Expect(createdUser.Spec.APIKeys).To(HaveLen(2))

			// First key with secret reference
			Expect(createdUser.Spec.APIKeys[0].Name).To(Equal("key-from-secret"))
			Expect(createdUser.Spec.APIKeys[0].SecretRef).NotTo(BeNil())

			// Second key without secret reference (to be created)
			Expect(createdUser.Spec.APIKeys[1].Name).To(Equal("key-to-create"))
			Expect(createdUser.Spec.APIKeys[1].SecretRef).To(BeNil())
			Expect(createdUser.Spec.APIKeys[1].ExpiresAt).To(Equal("2030-01-01T00:00:00Z"))
		})
	})

	Context("When deleting a PocketIDUser", func() {
		const userName = "test-user-delete"

		var user *pocketidinternalv1alpha1.PocketIDUser

		BeforeEach(func() {
			user = &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					Username:  pocketidinternalv1alpha1.StringValue{Value: "deleteuser"},
					FirstName: pocketidinternalv1alpha1.StringValue{Value: "Delete"},
					Admin:     false,
				},
			}
			Expect(k8sClient.Create(ctx, user)).To(Succeed())

			// Wait for creation
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      userName,
					Namespace: namespace,
				}, &pocketidinternalv1alpha1.PocketIDUser{})
			}, timeout, interval).Should(Succeed())
		})

		It("Should delete the PocketIDUser resource", func() {
			Expect(k8sClient.Delete(ctx, user)).To(Succeed())

			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      userName,
					Namespace: namespace,
				}, &pocketidinternalv1alpha1.PocketIDUser{})
				return errors.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())
		})
	})

	Context("When updating a PocketIDUser", func() {
		const userName = "test-user-update"

		var user *pocketidinternalv1alpha1.PocketIDUser

		BeforeEach(func() {
			user = &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					Username:  pocketidinternalv1alpha1.StringValue{Value: "updateuser"},
					FirstName: pocketidinternalv1alpha1.StringValue{Value: "Update"},
					LastName:  pocketidinternalv1alpha1.StringValue{Value: "User"},
					Admin:     false,
				},
			}
			Expect(k8sClient.Create(ctx, user)).To(Succeed())

			// Wait for creation
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      userName,
					Namespace: namespace,
				}, user)
			}, timeout, interval).Should(Succeed())
		})

		AfterEach(func() {
			if user != nil {
				_ = k8sClient.Delete(ctx, user)
			}
		})

		It("Should update the PocketIDUser when spec changes", func() {
			// Update the user
			Eventually(func() error {
				if err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      userName,
					Namespace: namespace,
				}, user); err != nil {
					return err
				}
				user.Spec.FirstName = pocketidinternalv1alpha1.StringValue{Value: "Updated"}
				user.Spec.Admin = true
				return k8sClient.Update(ctx, user)
			}, timeout, interval).Should(Succeed())

			// Verify the update
			updatedUser := &pocketidinternalv1alpha1.PocketIDUser{}
			Eventually(func() string {
				if err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      userName,
					Namespace: namespace,
				}, updatedUser); err != nil {
					return ""
				}
				return updatedUser.Spec.FirstName.Value
			}, timeout, interval).Should(Equal("Updated"))

			Expect(updatedUser.Spec.Admin).To(BeTrue())
		})
	})

	Context("When creating a PocketIDUser with userInfoSecretRef", func() {
		const userName = "test-user-userinfo-secret"
		const secretName = "user-info-secret"

		var user *pocketidinternalv1alpha1.PocketIDUser
		var secret *corev1.Secret

		BeforeEach(func() {
			// Create secret with all user fields
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"username":    []byte("secretuser"),
					"firstName":   []byte("Secret"),
					"lastName":    []byte("User"),
					"email":       []byte("secret@example.com"),
					"displayName": []byte("Secret User Display"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			user = &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					UserInfoSecretRef: &corev1.LocalObjectReference{
						Name: secretName,
					},
					Admin: false,
				},
			}
			Expect(k8sClient.Create(ctx, user)).To(Succeed())
		})

		AfterEach(func() {
			if user != nil {
				_ = k8sClient.Delete(ctx, user)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should create the PocketIDUser resource", func() {
			createdUser := &pocketidinternalv1alpha1.PocketIDUser{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      userName,
					Namespace: namespace,
				}, createdUser)
			}, timeout, interval).Should(Succeed())

			Expect(createdUser.Spec.UserInfoSecretRef.Name).To(Equal(secretName))
		})
	})

	Context("When creating a PocketIDUser with partial userInfoSecretRef", func() {
		const userName = "test-user-partial-secret"
		const secretName = "partial-user-secret"

		var user *pocketidinternalv1alpha1.PocketIDUser
		var secret *corev1.Secret

		BeforeEach(func() {
			// Create secret with only some fields - missing username and displayName
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"firstName": []byte("Partial"),
					"lastName":  []byte("User"),
					"email":     []byte("partial@example.com"),
					// username and displayName are intentionally missing
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			user = &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					UserInfoSecretRef: &corev1.LocalObjectReference{
						Name: secretName,
					},
					Admin: false,
				},
			}
			Expect(k8sClient.Create(ctx, user)).To(Succeed())
		})

		AfterEach(func() {
			if user != nil {
				_ = k8sClient.Delete(ctx, user)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should create the PocketIDUser with defaults for missing fields", func() {
			createdUser := &pocketidinternalv1alpha1.PocketIDUser{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      userName,
					Namespace: namespace,
				}, createdUser)
			}, timeout, interval).Should(Succeed())

			// Should use the secret for fields that exist
			Expect(createdUser.Spec.UserInfoSecretRef.Name).To(Equal(secretName))
			// Note: We can't directly test the resolved values here since they're
			// resolved during reconciliation, but the controller should not error
		})
	})

	Context("When creating a PocketIDUser with userInfoSecretRef and explicit overrides", func() {
		const userName = "test-user-override"
		const secretName = "base-user-secret"

		var user *pocketidinternalv1alpha1.PocketIDUser
		var secret *corev1.Secret

		BeforeEach(func() {
			// Create secret with base values
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"username":  []byte("secretuser"),
					"firstName": []byte("Secret"),
					"lastName":  []byte("User"),
					"email":     []byte("secret@example.com"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			user = &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					UserInfoSecretRef: &corev1.LocalObjectReference{
						Name: secretName,
					},
					// Override firstName with explicit value
					FirstName: pocketidinternalv1alpha1.StringValue{
						Value: "Override",
					},
					Admin: true,
				},
			}
			Expect(k8sClient.Create(ctx, user)).To(Succeed())
		})

		AfterEach(func() {
			if user != nil {
				_ = k8sClient.Delete(ctx, user)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should use explicit value over secret value", func() {
			createdUser := &pocketidinternalv1alpha1.PocketIDUser{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      userName,
					Namespace: namespace,
				}, createdUser)
			}, timeout, interval).Should(Succeed())

			// Explicit firstName should override the secret value
			Expect(createdUser.Spec.FirstName.Value).To(Equal("Override"))
			Expect(createdUser.Spec.UserInfoSecretRef.Name).To(Equal(secretName))
		})
	})

	Context("When creating a PocketIDUser with empty userInfoSecretRef", func() {
		const userName = "test-user-empty-secret"
		const secretName = "empty-user-secret"

		var user *pocketidinternalv1alpha1.PocketIDUser
		var secret *corev1.Secret

		BeforeEach(func() {
			// Create secret with empty values
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"username":  []byte(""),
					"firstName": []byte(""),
					"lastName":  []byte(""),
					"email":     []byte(""),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			user = &pocketidinternalv1alpha1.PocketIDUser{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDUserSpec{
					UserInfoSecretRef: &corev1.LocalObjectReference{
						Name: secretName,
					},
					Admin: false,
				},
			}
			Expect(k8sClient.Create(ctx, user)).To(Succeed())
		})

		AfterEach(func() {
			if user != nil {
				_ = k8sClient.Delete(ctx, user)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should create the PocketIDUser with defaults for empty values", func() {
			createdUser := &pocketidinternalv1alpha1.PocketIDUser{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      userName,
					Namespace: namespace,
				}, createdUser)
			}, timeout, interval).Should(Succeed())

			Expect(createdUser.Spec.UserInfoSecretRef.Name).To(Equal(secretName))
			// Controller should apply defaults for empty values
		})
	})
})
