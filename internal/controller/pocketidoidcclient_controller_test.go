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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/helpers"
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

			oidcClient := &pocketidinternalv1alpha1.PocketIDOIDCClient{
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

			// The UserGroup controller reconciles in the background and will keep overwriting
			// the status with InstanceSelectionError (no instance in envtest). To avoid losing
			// the race, we force the status and call ResolveUserGroupReferences atomically
			// inside a single Eventually retry so we win the window between reconciles.
			Eventually(func() ([]string, error) {
				if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
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
				}); err != nil {
					return nil, err
				}
				return helpers.ResolveUserGroupReferences(ctx, k8sClient, nil, oidcClient.Spec.AllowedUserGroups, oidcClient.Namespace)
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

			_, err := helpers.ResolveUserGroupReferences(ctx, k8sClient, nil, client.Spec.AllowedUserGroups, client.Namespace)
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

			_, err := helpers.ResolveUserGroupReferences(ctx, k8sClient, nil, client.Spec.AllowedUserGroups, client.Namespace)
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

			_, err := helpers.ResolveUserGroupReferences(ctx, k8sClient, nil, client.Spec.AllowedUserGroups, client.Namespace)
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

			ids, err := helpers.ResolveUserGroupReferences(ctx, k8sClient, nil, client.Spec.AllowedUserGroups, client.Namespace)
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
					EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
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
					EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "0123456789abcdef"},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceNameB,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: &pocketidinternalv1alpha1.SensitiveValue{Value: "fedcba9876543210"},
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

	Context("ClientSecretRef validation", func() {
		secretRef := &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "app-creds"},
			Key:                  "secret",
		}
		newClient := func(name string, mutate func(*pocketidinternalv1alpha1.PocketIDOIDCClientSpec)) *pocketidinternalv1alpha1.PocketIDOIDCClient {
			spec := pocketidinternalv1alpha1.PocketIDOIDCClientSpec{ClientSecretRef: secretRef}
			mutate(&spec)
			return &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec:       spec,
			}
		}

		It("should accept a confidential client with clientSecretRef and no rotation", func() {
			resource := newClient("test-oidc-declared-secret", func(*pocketidinternalv1alpha1.PocketIDOIDCClientSpec) {})
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, resource) })
		})

		It("should reject clientSecretRef on a public client", func() {
			resource := newClient("test-oidc-declared-public", func(s *pocketidinternalv1alpha1.PocketIDOIDCClientSpec) {
				s.IsPublic = true
			})
			err := k8sClient.Create(ctx, resource)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("clientSecretRef requires a confidential client"))
		})

		It("should reject enabling clientSecretRotation alongside clientSecretRef", func() {
			resource := newClient("test-oidc-declared-rotation", func(s *pocketidinternalv1alpha1.PocketIDOIDCClientSpec) {
				s.ClientSecretRotation = &pocketidinternalv1alpha1.ClientSecretRotation{
					Enabled:  true,
					Interval: &metav1.Duration{Duration: 720 * time.Hour},
				}
			})
			err := k8sClient.Create(ctx, resource)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("clientSecretRotation cannot be enabled when clientSecretRef is set"))
		})

		It("should accept clientSecretRef with rotation present but disabled", func() {
			resource := newClient("test-oidc-declared-rotation-off", func(s *pocketidinternalv1alpha1.PocketIDOIDCClientSpec) {
				s.ClientSecretRotation = &pocketidinternalv1alpha1.ClientSecretRotation{Enabled: false}
			})
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, resource) })
		})
	})

	Context("AllowedUserGroups reference validation", func() {
		newClient := func(name string, refs ...pocketidinternalv1alpha1.NamespacedUserGroupReference) *pocketidinternalv1alpha1.PocketIDOIDCClient {
			return &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec:       pocketidinternalv1alpha1.PocketIDOIDCClientSpec{AllowedUserGroups: refs},
			}
		}
		expectAccepted := func(resource *pocketidinternalv1alpha1.PocketIDOIDCClient) {
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, resource) })
		}
		expectRejected := func(resource *pocketidinternalv1alpha1.PocketIDOIDCClient) {
			err := k8sClient.Create(ctx, resource)
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsInvalid(err)).To(BeTrue())
		}

		It("accepts a CR reference with a namespace", func() {
			expectAccepted(newClient("ug-cel-cr",
				pocketidinternalv1alpha1.NamespacedUserGroupReference{Name: "group-a", Namespace: namespace}))
		})

		It("accepts a groupName reference", func() {
			expectAccepted(newClient("ug-cel-name",
				pocketidinternalv1alpha1.NamespacedUserGroupReference{GroupName: "developers"}))
		})

		It("accepts a groupID reference", func() {
			expectAccepted(newClient("ug-cel-id",
				pocketidinternalv1alpha1.NamespacedUserGroupReference{GroupID: "gid-dev"}))
		})

		It("accepts CR and external references in the same list", func() {
			expectAccepted(newClient("ug-cel-mixed",
				pocketidinternalv1alpha1.NamespacedUserGroupReference{Name: "group-a"},
				pocketidinternalv1alpha1.NamespacedUserGroupReference{GroupName: "developers"}))
		})

		It("rejects an empty reference", func() {
			expectRejected(newClient("ug-cel-empty", pocketidinternalv1alpha1.NamespacedUserGroupReference{}))
		})

		It("rejects a reference setting both name and groupName", func() {
			expectRejected(newClient("ug-cel-both",
				pocketidinternalv1alpha1.NamespacedUserGroupReference{Name: "group-a", GroupName: "developers"}))
		})

		It("rejects a reference setting both groupName and groupID", func() {
			expectRejected(newClient("ug-cel-both-external",
				pocketidinternalv1alpha1.NamespacedUserGroupReference{GroupName: "developers", GroupID: "gid-dev"}))
		})

		It("rejects a namespace without a CR name", func() {
			expectRejected(newClient("ug-cel-ns-only",
				pocketidinternalv1alpha1.NamespacedUserGroupReference{GroupName: "developers", Namespace: namespace}))
		})

		It("rejects a namespace alongside groupID", func() {
			expectRejected(newClient("ug-cel-ns-id",
				pocketidinternalv1alpha1.NamespacedUserGroupReference{GroupID: "gid-dev", Namespace: namespace}))
		})

		It("rejects a reference setting both name and groupID", func() {
			expectRejected(newClient("ug-cel-name-id",
				pocketidinternalv1alpha1.NamespacedUserGroupReference{Name: "group-a", GroupID: "gid-dev"}))
		})

		It("rejects a reference setting all three", func() {
			expectRejected(newClient("ug-cel-all-three",
				pocketidinternalv1alpha1.NamespacedUserGroupReference{Name: "group-a", GroupName: "developers", GroupID: "gid-dev"}))
		})

		// The length bounds are not cosmetic: without them the exactly-one-of rule
		// exceeds the API server's CEL cost budget and the CRD is rejected outright.
		It("rejects a groupName shorter than the minimum", func() {
			expectRejected(newClient("ug-cel-short-name",
				pocketidinternalv1alpha1.NamespacedUserGroupReference{GroupName: "d"}))
		})

		It("rejects a groupName longer than the maximum", func() {
			expectRejected(newClient("ug-cel-long-name",
				pocketidinternalv1alpha1.NamespacedUserGroupReference{GroupName: strings.Repeat("d", 256)}))
		})

		It("rejects a groupID longer than the maximum", func() {
			expectRejected(newClient("ug-cel-long-id",
				pocketidinternalv1alpha1.NamespacedUserGroupReference{GroupID: strings.Repeat("g", 65)}))
		})

		It("accepts a groupID at the maximum length", func() {
			expectAccepted(newClient("ug-cel-max-id",
				pocketidinternalv1alpha1.NamespacedUserGroupReference{GroupID: strings.Repeat("g", 64)}))
		})
	})

	Context("ClientSecretRotation validation", func() {
		newClient := func(name string, rot *pocketidinternalv1alpha1.ClientSecretRotation) *pocketidinternalv1alpha1.PocketIDOIDCClient {
			return &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec:       pocketidinternalv1alpha1.PocketIDOIDCClientSpec{ClientSecretRotation: rot},
			}
		}
		dur := func(d time.Duration) *metav1.Duration { return &metav1.Duration{Duration: d} }
		win := func(closesAfter time.Duration) *pocketidinternalv1alpha1.RotationWindow {
			return &pocketidinternalv1alpha1.RotationWindow{Opens: "0 1 * * *", ClosesAfter: metav1.Duration{Duration: closesAfter}}
		}
		expectAccepted := func(resource *pocketidinternalv1alpha1.PocketIDOIDCClient) {
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, resource) })
		}
		expectRejected := func(resource *pocketidinternalv1alpha1.PocketIDOIDCClient) {
			err := k8sClient.Create(ctx, resource)
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsInvalid(err)).To(BeTrue())
		}

		It("rejects enabled rotation with neither interval nor window", func() {
			expectRejected(newClient("rot-cel-neither", &pocketidinternalv1alpha1.ClientSecretRotation{Enabled: true}))
		})

		It("accepts disabled rotation with neither interval nor window", func() {
			expectAccepted(newClient("rot-cel-disabled", &pocketidinternalv1alpha1.ClientSecretRotation{Enabled: false}))
		})

		It("accepts interval-only rotation", func() {
			expectAccepted(newClient("rot-cel-interval", &pocketidinternalv1alpha1.ClientSecretRotation{Enabled: true, Interval: dur(24 * time.Hour)}))
		})

		It("accepts window-only rotation", func() {
			expectAccepted(newClient("rot-cel-window", &pocketidinternalv1alpha1.ClientSecretRotation{Enabled: true, Window: win(time.Hour)}))
		})

		It("accepts interval and window when closesAfter does not exceed interval", func() {
			expectAccepted(newClient("rot-cel-both-ok", &pocketidinternalv1alpha1.ClientSecretRotation{Enabled: true, Interval: dur(24 * time.Hour), Window: win(time.Hour)}))
		})

		It("rejects interval and window when closesAfter exceeds interval", func() {
			expectRejected(newClient("rot-cel-both-bad", &pocketidinternalv1alpha1.ClientSecretRotation{Enabled: true, Interval: dur(time.Hour), Window: win(2 * time.Hour)}))
		})

		It("rejects an interval below the allowed minimum", func() {
			expectRejected(newClient("rot-cel-interval-min", &pocketidinternalv1alpha1.ClientSecretRotation{Enabled: true, Interval: dur(30 * time.Minute)}))
		})

		It("rejects a window closesAfter below 5m", func() {
			expectRejected(newClient("rot-cel-window-min", &pocketidinternalv1alpha1.ClientSecretRotation{Enabled: true, Window: win(time.Minute)}))
		})
	})

	// Admission is what keeps a CIMD resource from declaring fields its metadata document
	// owns. Without these rules the operator would silently ignore them instead.
	Context("CIMD client validation", func() {
		const metadataURL = "https://apps.example.com/myapp/client-metadata.json"

		newClient := func(name string, mutate func(*pocketidinternalv1alpha1.PocketIDOIDCClientSpec)) *pocketidinternalv1alpha1.PocketIDOIDCClient {
			spec := pocketidinternalv1alpha1.PocketIDOIDCClientSpec{ClientID: metadataURL}
			mutate(&spec)
			return &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec:       spec,
			}
		}
		expectRejectedWith := func(resource *pocketidinternalv1alpha1.PocketIDOIDCClient, substring string) {
			err := k8sClient.Create(ctx, resource)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(substring))
		}

		It("accepts a CIMD client setting only the fields Pocket-ID persists", func() {
			resource := newClient("cimd-cel-ok", func(s *pocketidinternalv1alpha1.PocketIDOIDCClientSpec) {
				s.Description = "Self-registered app"
				s.LaunchURL = "https://apps.example.com/myapp"
				s.SkipConsent = true
				s.RequiresReauthentication = true
				s.AccessTokenDurationMinutes = 15
				s.AllowedUserGroups = []pocketidinternalv1alpha1.NamespacedUserGroupReference{{GroupName: "platform"}}
			})
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, resource) })
		})

		DescribeTable("rejects metadata-owned fields",
			func(mutate func(*pocketidinternalv1alpha1.PocketIDOIDCClientSpec)) {
				expectRejectedWith(newClient("cimd-cel-owned", mutate),
					"owned by the client ID metadata document")
			},
			Entry("name", func(s *pocketidinternalv1alpha1.PocketIDOIDCClientSpec) { s.Name = "My App" }),
			Entry("callbackUrls", func(s *pocketidinternalv1alpha1.PocketIDOIDCClientSpec) {
				s.CallbackURLs = []string{"https://apps.example.com/cb"}
			}),
			Entry("logoutCallbackUrls", func(s *pocketidinternalv1alpha1.PocketIDOIDCClientSpec) {
				s.LogoutCallbackURLs = []string{"https://apps.example.com/logout"}
			}),
			Entry("isPublic", func(s *pocketidinternalv1alpha1.PocketIDOIDCClientSpec) { s.IsPublic = true }),
			Entry("pkceEnabled", func(s *pocketidinternalv1alpha1.PocketIDOIDCClientSpec) { s.PKCEEnabled = true }),
			Entry("federatedIdentities", func(s *pocketidinternalv1alpha1.PocketIDOIDCClientSpec) {
				s.FederatedIdentities = []pocketidinternalv1alpha1.OIDCClientFederatedIdentity{{Issuer: "https://issuer.example.com"}}
			}),
		)

		It("rejects clientSecretRef on a CIMD client", func() {
			expectRejectedWith(newClient("cimd-cel-secret-ref", func(s *pocketidinternalv1alpha1.PocketIDOIDCClientSpec) {
				s.ClientSecretRef = &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "creds"},
					Key:                  "secret",
				}
			}), "always public and has no client secret")
		})

		It("rejects enabling clientSecretRotation on a CIMD client", func() {
			expectRejectedWith(newClient("cimd-cel-rotation", func(s *pocketidinternalv1alpha1.PocketIDOIDCClientSpec) {
				s.ClientSecretRotation = &pocketidinternalv1alpha1.ClientSecretRotation{
					Enabled:  true,
					Interval: &metav1.Duration{Duration: 720 * time.Hour},
				}
			}), "always public and has no client secret")
		})

		// The pre-existing clientPermissions rule keys on spec.isPublic, which a CIMD
		// client must leave false even though the client itself is public.
		It("rejects apiAccess clientPermissions on a CIMD client", func() {
			expectRejectedWith(newClient("cimd-cel-client-perms", func(s *pocketidinternalv1alpha1.PocketIDOIDCClientSpec) {
				s.APIAccess = []pocketidinternalv1alpha1.OIDCClientAPIAccess{{
					APIRef:            pocketidinternalv1alpha1.NamespacedAPIReference{Name: "my-api"},
					ClientPermissions: []string{"read"},
				}}
			}), "clientPermissions require a confidential client")
		})

		It("accepts apiAccess delegatedPermissions on a CIMD client", func() {
			resource := newClient("cimd-cel-delegated-perms", func(s *pocketidinternalv1alpha1.PocketIDOIDCClientSpec) {
				s.APIAccess = []pocketidinternalv1alpha1.OIDCClientAPIAccess{{
					APIRef:               pocketidinternalv1alpha1.NamespacedAPIReference{Name: "my-api"},
					DelegatedPermissions: []string{"read"},
				}}
			})
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, resource) })
		})

		It("allows an ordinary client ID up to 128 characters and rejects longer ones", func() {
			ok := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{Name: "cimd-cel-len-ok", Namespace: namespace},
				Spec:       pocketidinternalv1alpha1.PocketIDOIDCClientSpec{ClientID: strings.Repeat("a", 128)},
			}
			Expect(k8sClient.Create(ctx, ok)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, ok) })

			long := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{Name: "cimd-cel-len-bad", Namespace: namespace},
				Spec:       pocketidinternalv1alpha1.PocketIDOIDCClientSpec{ClientID: strings.Repeat("a", 129)},
			}
			err := k8sClient.Create(ctx, long)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("at most 128 characters"))
		})

		It("allows a metadata document URL longer than 128 characters", func() {
			resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{Name: "cimd-cel-long-url", Namespace: namespace},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{
					ClientID: "https://apps.example.com/" + strings.Repeat("deep/", 25) + "client-metadata.json",
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, resource) })
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
				PKCESupported:       true,
			}
			Expect(reconciler.UpdateOIDCClientStatus(ctx, resource, current)).To(Succeed())

			updated := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: clientName, Namespace: namespace}, updated)).To(Succeed())
			Expect(updated.Status.ClientID).To(Equal("client-id"))
			Expect(updated.Status.AllowedUserGroupIDs).To(Equal([]string{"group-1"}))
			Expect(updated.Status.PKCESupported).To(HaveValue(BeTrue()))
		})

		It("should not flag PKCESupported when PKCE is already enabled", func() {
			const enabledName = "test-oidc-status-pkce-enabled"
			resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      enabledName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDOIDCClientSpec{},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, resource) })

			reconciler := &PocketIDOIDCClientReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			// Pocket-ID leaves PKCESupported set once a client has used PKCE, even
			// after PKCE is enabled, so this must not be surfaced as "can enable".
			current := &pocketid.OIDCClient{
				ID:            "client-id",
				Name:          "Test OIDC Client",
				PKCESupported: true,
				PKCEEnabled:   true,
			}
			Expect(reconciler.UpdateOIDCClientStatus(ctx, resource, current)).To(Succeed())

			updated := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: enabledName, Namespace: namespace}, updated)).To(Succeed())
			Expect(updated.Status.PKCESupported).To(BeNil())
		})
	})

	Context("Logo status reachability", func() {
		It("should persist logoReachable=false explicitly in the API server", func() {
			clientName := "logo-reachable-test"
			resource := &pocketidinternalv1alpha1.PocketIDOIDCClient{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clientName,
					Namespace: namespace,
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			// Patch status with light=true, dark=false
			base := resource.DeepCopy()
			logoTrue := true
			darkFalse := false
			resource.Status.LogoURL = "https://example.com/logo.png"
			resource.Status.LogoReachable = &logoTrue
			resource.Status.DarkLogoURL = "https://example.com/logo-dark.png"
			resource.Status.DarkLogoReachable = &darkFalse
			Expect(k8sClient.Status().Patch(ctx, resource, client.MergeFrom(base))).To(Succeed())

			// Re-fetch from the real API server
			fetched := &pocketidinternalv1alpha1.PocketIDOIDCClient{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: clientName, Namespace: namespace}, fetched)).To(Succeed())

			Expect(fetched.Status.LogoURL).To(Equal("https://example.com/logo.png"))
			Expect(fetched.Status.LogoReachable).NotTo(BeNil())
			Expect(*fetched.Status.LogoReachable).To(BeTrue())

			Expect(fetched.Status.DarkLogoURL).To(Equal("https://example.com/logo-dark.png"))
			Expect(fetched.Status.DarkLogoReachable).NotTo(BeNil(), "darkLogoReachable should be explicitly set, not nil")
			Expect(*fetched.Status.DarkLogoReachable).To(BeFalse())
		})
	})
})
