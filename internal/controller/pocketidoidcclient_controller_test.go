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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
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
					AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
						{Name: "missing-group"},
					},
				},
			}

			_, err := reconciler.resolveAllowedUserGroups(ctx, client)
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

			_, err := reconciler.resolveAllowedUserGroups(ctx, client)
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

			_, err := reconciler.resolveAllowedUserGroups(ctx, client)
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

			ids, err := reconciler.resolveAllowedUserGroups(ctx, client)
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

	Context("When API client cannot be created", func() {
		const (
			instanceName = "test-oidc-instance-api-client-error"
			clientName   = "test-oidc-client-api-client-error"
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
					},
				},
			}

			resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: namespace,
					Finalizers: []string{
						oidcClientFinalizer,
					},
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{},
			}
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithStatusSubresource(resource).
				WithObjects(instance, resource).
				Build()

			reconciler := &PocketIDOIDCClientReconciler{
				Client: fakeClient,
				Scheme: scheme,
			}

			_, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: clientName, Namespace: namespace},
			})
			Expect(err).NotTo(HaveOccurred())

			updated := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
			Expect(fakeClient.Get(ctx, types.NamespacedName{Name: clientName, Namespace: namespace}, updated)).To(Succeed())
			cond := meta.FindStatusCondition(updated.Status.Conditions, "Ready")
			Expect(cond).NotTo(BeNil())
			Expect(cond.Reason).To(Equal("APIClientNotReady"))
		})
	})

	Context("OIDC client input mapping", func() {
		It("should map spec fields to API input", func() {
			reconciler := &PocketIDOIDCClientReconciler{}
			oidc := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name: "fallback-name",
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					ID:                       "client-id",
					CallbackURLs:             []string{"https://example.com/callback"},
					LogoutCallbackURLs:       []string{"https://example.com/logout"},
					LaunchURL:                "https://example.com",
					LogoURL:                  "https://example.com/logo.png",
					DarkLogoURL:              "https://example.com/logo-dark.png",
					IsPublic:                 true,
					PKCEEnabled:              true,
					RequiresReauthentication: true,
					FederatedIdentities: []pocketidinternalv1alpha1.OIDCClientFederatedIdentity{
						{
							Issuer:   "https://issuer.example.com",
							Subject:  "subject",
							Audience: "audience",
							JWKS:     "https://issuer.example.com/jwks",
						},
					},
					AllowedUserGroups: []pocketidinternalv1alpha1.NamespacedUserGroupReference{
						{Name: "group"},
					},
				},
			}

			input := reconciler.oidcClientInput(oidc)
			Expect(input.Name).To(Equal("fallback-name"))
			Expect(input.HasLogo).To(BeTrue())
			Expect(input.HasDarkLogo).To(BeTrue())
			Expect(input.IsGroupRestricted).To(BeTrue())
			Expect(input.Credentials).NotTo(BeNil())
			Expect(input.Credentials.FederatedIdentities).To(Equal([]pocketid.OIDCClientFederatedIdentity{
				{
					Issuer:   "https://issuer.example.com",
					Subject:  "subject",
					Audience: "audience",
					JWKS:     "https://issuer.example.com/jwks",
				},
			}))
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
			Expect(reconciler.updateOIDCClientStatus(ctx, resource, current)).To(Succeed())

			updated := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: clientName, Namespace: namespace}, updated)).To(Succeed())
			Expect(updated.Status.ClientID).To(Equal("client-id"))
			Expect(updated.Status.AllowedUserGroupIDs).To(Equal([]string{"group-1"}))
		})
	})

	Context("Secret helper functions", func() {
		var reconciler *PocketIDOIDCClientReconciler

		BeforeEach(func() {
			reconciler = &PocketIDOIDCClientReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
		})

		Describe("getSecretName", func() {
			It("should return default name when not specified", func() {
				oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
					ObjectMeta: metav1.ObjectMeta{
						Name: "my-client",
					},
				}
				name := reconciler.getSecretName(oidcClient)
				Expect(name).To(Equal("my-client-oidc-credentials"))
			})

			It("should return custom name when specified", func() {
				oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
					ObjectMeta: metav1.ObjectMeta{
						Name: "my-client",
					},
					Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
						Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{
							Name: "custom-secret",
						},
					},
				}
				name := reconciler.getSecretName(oidcClient)
				Expect(name).To(Equal("custom-secret"))
			})

			It("should return default when secret spec exists but name is empty", func() {
				oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
					ObjectMeta: metav1.ObjectMeta{
						Name: "my-client",
					},
					Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
						Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{
							Name: "",
						},
					},
				}
				name := reconciler.getSecretName(oidcClient)
				Expect(name).To(Equal("my-client-oidc-credentials"))
			})
		})

		Describe("getSecretKeys", func() {
			It("should return defaults when not specified", func() {
				oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
					ObjectMeta: metav1.ObjectMeta{
						Name: "my-client",
					},
				}
				keys := reconciler.getSecretKeys(oidcClient)
				Expect(keys.ClientID).To(Equal("client_id"))
				Expect(keys.ClientSecret).To(Equal("client_secret"))
				Expect(keys.IssuerURL).To(Equal("issuer_url"))
				Expect(keys.CallbackURLs).To(Equal("callback_urls"))
				Expect(keys.LogoutCallbackURLs).To(Equal("logout_callback_urls"))
			})

			It("should return custom keys when specified", func() {
				oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
					ObjectMeta: metav1.ObjectMeta{
						Name: "my-client",
					},
					Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
						Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{
							Keys: &pocketidinternalv1alpha1.OIDCClientSecretKeys{
								ClientID:           "custom_client_id",
								ClientSecret:       "custom_client_secret",
								IssuerURL:          "custom_issuer",
								CallbackURLs:       "custom_callbacks",
								LogoutCallbackURLs: "custom_logout",
							},
						},
					},
				}
				keys := reconciler.getSecretKeys(oidcClient)
				Expect(keys.ClientID).To(Equal("custom_client_id"))
				Expect(keys.ClientSecret).To(Equal("custom_client_secret"))
				Expect(keys.IssuerURL).To(Equal("custom_issuer"))
				Expect(keys.CallbackURLs).To(Equal("custom_callbacks"))
				Expect(keys.LogoutCallbackURLs).To(Equal("custom_logout"))
			})

			It("should use defaults for unspecified custom keys", func() {
				oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
					ObjectMeta: metav1.ObjectMeta{
						Name: "my-client",
					},
					Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
						Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{
							Keys: &pocketidinternalv1alpha1.OIDCClientSecretKeys{
								ClientID: "custom_client_id",
								// Other keys not specified
							},
						},
					},
				}
				keys := reconciler.getSecretKeys(oidcClient)
				Expect(keys.ClientID).To(Equal("custom_client_id"))
				Expect(keys.ClientSecret).To(Equal("client_secret"))
				Expect(keys.IssuerURL).To(Equal("issuer_url"))
				Expect(keys.CallbackURLs).To(Equal("callback_urls"))
				Expect(keys.LogoutCallbackURLs).To(Equal("logout_callback_urls"))
			})
		})
	})

	Context("Secret reconciliation", func() {
		It("should delete secret when disabled", func() {
			scheme := runtime.NewScheme()
			_ = pocketidinternalv1alpha1.AddToScheme(scheme)
			_ = corev1.AddToScheme(scheme)

			enabled := false
			oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-disabled-secret",
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{
						Enabled: &enabled,
					},
				},
				Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
					ClientID: "client-123",
				},
			}

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-disabled-secret-oidc-credentials",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"client_id": []byte("client-123"),
				},
			}

			instance := &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					AppURL:        "http://test.example.com",
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{Value: "0123456789abcdef"},
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(oidcClient, secret, instance).
				Build()

			reconciler := &PocketIDOIDCClientReconciler{
				Client: fakeClient,
				Scheme: scheme,
			}

			err := reconciler.reconcileSecret(ctx, oidcClient, instance, nil)
			Expect(err).NotTo(HaveOccurred())

			deletedSecret := &corev1.Secret{}
			err = fakeClient.Get(ctx, client.ObjectKey{Name: secret.Name, Namespace: namespace}, deletedSecret)
			Expect(err).To(HaveOccurred())
		})

		It("should not error when disabling non-existent secret", func() {
			scheme := runtime.NewScheme()
			_ = pocketidinternalv1alpha1.AddToScheme(scheme)
			_ = corev1.AddToScheme(scheme)

			enabled := false
			oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-no-secret",
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					Secret: &pocketidinternalv1alpha1.OIDCClientSecretSpec{
						Enabled: &enabled,
					},
				},
			}

			instance := &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					AppURL:        "http://test.example.com",
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{Value: "0123456789abcdef"},
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(oidcClient, instance).
				Build()

			reconciler := &PocketIDOIDCClientReconciler{
				Client: fakeClient,
				Scheme: scheme,
			}

			err := reconciler.reconcileSecret(ctx, oidcClient, instance, nil)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should create secret with default settings for public clients", func() {
			scheme := runtime.NewScheme()
			_ = pocketidinternalv1alpha1.AddToScheme(scheme)
			_ = corev1.AddToScheme(scheme)

			oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-public-enabled",
					Namespace: namespace,
					UID:       "test-uid-public",
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					IsPublic:     true,
					CallbackURLs: []string{"https://example.com/callback"},
				},
				Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
					ClientID: "client-789",
				},
			}

			instance := &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance",
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					AppURL:        "http://test.example.com",
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{Value: "0123456789abcdef"},
				},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(oidcClient, instance).
				Build()

			reconciler := &PocketIDOIDCClientReconciler{
				Client: fakeClient,
				Scheme: scheme,
			}

			// For public clients, no API client call is needed since there's no client_secret
			err := reconciler.reconcileSecret(ctx, oidcClient, instance, nil)
			Expect(err).NotTo(HaveOccurred())

			// Verify secret was created
			secret := &corev1.Secret{}
			err = fakeClient.Get(ctx, client.ObjectKey{
				Name:      "test-public-enabled-oidc-credentials",
				Namespace: namespace,
			}, secret)
			Expect(err).NotTo(HaveOccurred())

			// Verify it contains client_id but not client_secret
			Expect(secret.Data).To(HaveKey("client_id"))
			Expect(secret.Data).NotTo(HaveKey("client_secret"))
			Expect(secret.Data).To(HaveKey("issuer_url"))
		})
	})

	Context("Delete behavior", func() {
		It("should remove finalizer when no instance exists", func() {
			scheme := runtime.NewScheme()
			_ = pocketidinternalv1alpha1.AddToScheme(scheme)

			resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "delete-oidc-no-instance",
					Namespace:  namespace,
					Finalizers: []string{oidcClientFinalizer},
				},
				Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
					ClientID: "client-id",
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(resource).
				Build()

			reconciler := &PocketIDOIDCClientReconciler{Client: fakeClient, Scheme: scheme}
			_, err := reconciler.reconcileDelete(context.Background(), resource)
			Expect(err).NotTo(HaveOccurred())

			updated := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
			Expect(fakeClient.Get(context.Background(), types.NamespacedName{Name: resource.Name, Namespace: resource.Namespace}, updated)).To(Succeed())
			Expect(updated.Finalizers).NotTo(ContainElement(oidcClientFinalizer))
		})

		It("should keep finalizer when API client lookup is not ready", func() {
			scheme := runtime.NewScheme()
			_ = pocketidinternalv1alpha1.AddToScheme(scheme)

			instance := &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "delete-oidc-instance",
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

			resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "delete-oidc-api-client-error",
					Namespace:  namespace,
					Finalizers: []string{oidcClientFinalizer},
				},
				Status: pocketidinternalv1alpha1.PocketIDOIDCClientStatus{
					ClientID: "client-id",
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{},
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(instance, resource).
				Build()

			reconciler := &PocketIDOIDCClientReconciler{Client: fakeClient, Scheme: scheme}
			_, err := reconciler.reconcileDelete(context.Background(), resource)
			Expect(err).NotTo(HaveOccurred())

			updated := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
			Expect(fakeClient.Get(context.Background(), types.NamespacedName{Name: resource.Name, Namespace: resource.Namespace}, updated)).To(Succeed())
			Expect(updated.Finalizers).To(ContainElement(oidcClientFinalizer))
		})
	})

})
