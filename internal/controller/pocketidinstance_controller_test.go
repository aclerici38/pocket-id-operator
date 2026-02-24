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
	"encoding/base64"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

// Environment variable names used in tests (mirrors instance controller constants)
const (
	envEncryptionKey      = "ENCRYPTION_KEY"
	envDBConnectionString = "DB_CONNECTION_STRING"
	envAppURL             = "APP_URL"
)

var _ = Describe("PocketIDInstance Controller", func() {
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

	Context("When creating a PocketIDInstance with Deployment type", func() {
		const instanceName = "test-deployment-instance"

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret

		BeforeEach(func() {
			// Create secret for encryption key
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"encryption-key": []byte("test-encryption-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			// Create the Instance
			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					DeploymentType: "Deployment",
					Image:          "ghcr.io/pocket-id/pocket-id:v2.3.0-distroless@sha256:85a7485108325e34679b0fbca0baeb8418401f6d6cf59944d50f3ec013aafd09",
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
					AppURL: "https://auth.example.com",
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		})

		AfterEach(func() {
			// Clean up Instance
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			// Clean up Secret
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should create a Deployment", func() {
			deployment := &appsv1.Deployment{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, deployment)
			}, timeout, interval).Should(Succeed())

			Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(deployment.Spec.Template.Spec.Containers[0].Image).To(Equal("ghcr.io/pocket-id/pocket-id:v2.3.0-distroless@sha256:85a7485108325e34679b0fbca0baeb8418401f6d6cf59944d50f3ec013aafd09"))
			Expect(deployment.Spec.Template.Spec.Containers[0].Name).To(Equal("pocket-id"))

			// Verify owner reference is set
			Expect(deployment.OwnerReferences).To(HaveLen(1))
			Expect(deployment.OwnerReferences[0].Name).To(Equal(instanceName))
		})

		It("Should create a Service", func() {
			service := &corev1.Service{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, service)
			}, timeout, interval).Should(Succeed())

			Expect(service.Spec.Ports).To(HaveLen(1))
			Expect(service.Spec.Ports[0].Port).To(Equal(int32(1411)))
			Expect(service.Spec.Selector["app.kubernetes.io/instance"]).To(Equal(instanceName))

			// Verify owner reference is set
			Expect(service.OwnerReferences).To(HaveLen(1))
			Expect(service.OwnerReferences[0].Name).To(Equal(instanceName))
		})

		It("Should set environment variables correctly", func() {
			deployment := &appsv1.Deployment{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, deployment)
			}, timeout, interval).Should(Succeed())

			envVars := deployment.Spec.Template.Spec.Containers[0].Env

			// Check ENCRYPTION_KEY is set from secret
			var encryptionKeyEnv *corev1.EnvVar
			var appURLEnv *corev1.EnvVar
			for i := range envVars {
				if envVars[i].Name == envEncryptionKey {
					encryptionKeyEnv = &envVars[i]
				}
				if envVars[i].Name == envAppURL {
					appURLEnv = &envVars[i]
				}
			}

			Expect(encryptionKeyEnv).NotTo(BeNil())
			Expect(encryptionKeyEnv.ValueFrom).NotTo(BeNil())
			Expect(encryptionKeyEnv.ValueFrom.SecretKeyRef.Name).To(Equal(secret.Name))

			Expect(appURLEnv).NotTo(BeNil())
			Expect(appURLEnv.Value).To(Equal("https://auth.example.com"))
		})
	})

	Context("When creating a PocketIDInstance with HTTPRoute enabled", func() {
		const (
			instanceName = "test-httproute-instance"
			routeName    = "test-httproute-instance-route"
		)

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret

		BeforeEach(func() {
			group := gatewayv1.Group("gateway.networking.k8s.io")
			kind := gatewayv1.Kind("Gateway")

			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"encryption-key": []byte("test-encryption-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					DeploymentType: "Deployment",
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
					AppURL: "https://route.example.com",
					Route: &pocketidinternalv1alpha1.HTTPRouteConfig{
						Enabled: true,
						Name:    routeName,
						Labels: map[string]string{
							"custom-label": "custom-value",
						},
						Annotations: map[string]string{
							"custom-annotation": "custom-value",
						},
						ParentRefs: []gatewayv1.ParentReference{
							{
								Group: &group,
								Kind:  &kind,
								Name:  gatewayv1.ObjectName("gateway"),
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should create an HTTPRoute from route config", func() {
			httpRoute := &gatewayv1.HTTPRoute{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      routeName,
					Namespace: namespace,
				}, httpRoute)
			}, timeout, interval).Should(Succeed())

			Expect(httpRoute.Spec.ParentRefs).To(HaveLen(1))
			Expect(httpRoute.Spec.ParentRefs[0].Name).To(Equal(gatewayv1.ObjectName("gateway")))
			Expect(httpRoute.Spec.Hostnames).To(ContainElement(gatewayv1.Hostname("route.example.com")))
			Expect(httpRoute.Spec.Rules).To(HaveLen(1))
			Expect(httpRoute.Spec.Rules[0].BackendRefs).To(HaveLen(1))
			Expect(httpRoute.Spec.Rules[0].BackendRefs[0].Name).To(Equal(gatewayv1.ObjectName(instanceName)))
			Expect(httpRoute.Spec.Rules[0].BackendRefs[0].Port).NotTo(BeNil())
			Expect(*httpRoute.Spec.Rules[0].BackendRefs[0].Port).To(Equal(gatewayv1.PortNumber(1411)))
			Expect(httpRoute.Labels).To(HaveKeyWithValue("custom-label", "custom-value"))
			Expect(httpRoute.Annotations).To(HaveKeyWithValue("custom-annotation", "custom-value"))
		})

		It("Should update HTTPRoute when route hostnames change", func() {
			Eventually(func() error {
				current := &pocketidinternalv1alpha1.PocketIDInstance{}
				if err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, current); err != nil {
					return err
				}

				current.Spec.Route.Hostnames = []gatewayv1.Hostname{gatewayv1.Hostname("custom.route.example.com")}
				return k8sClient.Update(ctx, current)
			}, timeout, interval).Should(Succeed())

			httpRoute := &gatewayv1.HTTPRoute{}
			Eventually(func() []gatewayv1.Hostname {
				if err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      routeName,
					Namespace: namespace,
				}, httpRoute); err != nil {
					return nil
				}
				return httpRoute.Spec.Hostnames
			}, timeout, interval).Should(Equal([]gatewayv1.Hostname{gatewayv1.Hostname("custom.route.example.com")}))
		})

		It("Should delete HTTPRoute when route is disabled", func() {
			httpRoute := &gatewayv1.HTTPRoute{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      routeName,
					Namespace: namespace,
				}, httpRoute)
			}, timeout, interval).Should(Succeed())

			Eventually(func() error {
				current := &pocketidinternalv1alpha1.PocketIDInstance{}
				if err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, current); err != nil {
					return err
				}

				current.Spec.Route.Enabled = false
				return k8sClient.Update(ctx, current)
			}, timeout, interval).Should(Succeed())

			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      routeName,
					Namespace: namespace,
				}, &gatewayv1.HTTPRoute{})
				return apierrors.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())
		})
	})

	Context("When creating a PocketIDInstance with StatefulSet type", func() {
		const instanceName = "test-statefulset-instance"

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret

		BeforeEach(func() {
			// Create secret for encryption key
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"encryption-key": []byte("test-encryption-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			// Create the Instance with StatefulSet type
			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					DeploymentType: "StatefulSet",
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should create a StatefulSet instead of Deployment", func() {
			// Verify StatefulSet is created
			sts := &appsv1.StatefulSet{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, sts)
			}, timeout, interval).Should(Succeed())

			Expect(sts.Spec.Template.Spec.Containers).To(HaveLen(1))
			Expect(sts.Spec.Template.Spec.Containers[0].Name).To(Equal("pocket-id"))

			// Verify Deployment is NOT created
			deployment := &appsv1.Deployment{}
			err := k8sClient.Get(ctx, types.NamespacedName{
				Name:      instanceName,
				Namespace: namespace,
			}, deployment)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("When creating a PocketIDInstance with persistence enabled", func() {
		const instanceName = "test-persistence-instance"

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret

		BeforeEach(func() {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"encryption-key": []byte("test-encryption-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
					Persistence: pocketidinternalv1alpha1.PersistenceConfig{
						Enabled: true,
						Size:    resource.MustParse("2Gi"),
					},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should create a PersistentVolumeClaim", func() {
			pvc := &corev1.PersistentVolumeClaim{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName + "-data",
					Namespace: namespace,
				}, pvc)
			}, timeout, interval).Should(Succeed())

			Expect(pvc.Spec.Resources.Requests[corev1.ResourceStorage]).To(Equal(instance.Spec.Persistence.Size))
			Expect(pvc.Spec.AccessModes).To(ContainElement(corev1.ReadWriteOnce))

			// Verify owner reference
			Expect(pvc.OwnerReferences).To(HaveLen(1))
			Expect(pvc.OwnerReferences[0].Name).To(Equal(instanceName))
		})

		It("Should mount the PVC in the Deployment", func() {
			deployment := &appsv1.Deployment{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, deployment)
			}, timeout, interval).Should(Succeed())

			// Check volume is defined
			volumes := deployment.Spec.Template.Spec.Volumes
			Expect(volumes).To(HaveLen(1))
			Expect(volumes[0].Name).To(Equal("data"))
			Expect(volumes[0].VolumeSource.PersistentVolumeClaim).NotTo(BeNil())
			Expect(volumes[0].VolumeSource.PersistentVolumeClaim.ClaimName).To(Equal(instanceName + "-data"))

			// Check volume mount
			volumeMounts := deployment.Spec.Template.Spec.Containers[0].VolumeMounts
			Expect(volumeMounts).To(HaveLen(1))
			Expect(volumeMounts[0].Name).To(Equal("data"))
			Expect(volumeMounts[0].MountPath).To(Equal("/app/data"))
		})
	})

	Context("When creating a PocketIDInstance with persistence disabled", func() {
		const instanceName = "test-no-persistence-instance"

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret

		BeforeEach(func() {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"encryption-key": []byte("test-encryption-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
					Persistence: pocketidinternalv1alpha1.PersistenceConfig{
						Enabled: false,
					},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should NOT create a PersistentVolumeClaim", func() {
			pvc := &corev1.PersistentVolumeClaim{}
			Consistently(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName + "-data",
					Namespace: namespace,
				}, pvc)
			}, time.Second*2, interval).ShouldNot(Succeed())
		})

		It("Should use an emptyDir volume", func() {
			deployment := &appsv1.Deployment{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, deployment)
			}, timeout, interval).Should(Succeed())

			volumes := deployment.Spec.Template.Spec.Volumes
			Expect(volumes).To(HaveLen(1))
			Expect(volumes[0].Name).To(Equal("data"))
			Expect(volumes[0].VolumeSource.EmptyDir).NotTo(BeNil())

			volumeMounts := deployment.Spec.Template.Spec.Containers[0].VolumeMounts
			Expect(volumeMounts).To(HaveLen(1))
			Expect(volumeMounts[0].MountPath).To(Equal("/app/data"))
		})
	})

	Context("When creating a PocketIDInstance with existing PVC", func() {
		var instanceName string
		var existingPVCName string

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret
		var existingPVC *corev1.PersistentVolumeClaim

		BeforeEach(func() {
			// Generate unique names to avoid conflicts
			instanceName = "test-existing-pvc-instance-" + time.Now().Format("150405")
			existingPVCName = "my-existing-pvc-" + time.Now().Format("150405")

			// Create an existing PVC
			existingPVC = &corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      existingPVCName,
					Namespace: namespace,
				},
				Spec: corev1.PersistentVolumeClaimSpec{
					AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					Resources: corev1.VolumeResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceStorage: resource.MustParse("5Gi"),
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, existingPVC)).To(Succeed())

			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"encryption-key": []byte("test-encryption-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
					Persistence: pocketidinternalv1alpha1.PersistenceConfig{
						Enabled:       true,
						ExistingClaim: existingPVC.Name,
					},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
			if existingPVC != nil {
				_ = k8sClient.Delete(ctx, existingPVC)
			}
		})

		It("Should NOT create a new PVC", func() {
			pvc := &corev1.PersistentVolumeClaim{}
			Consistently(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName + "-data",
					Namespace: namespace,
				}, pvc)
			}, time.Second*2, interval).ShouldNot(Succeed())
		})

		It("Should mount the existing PVC", func() {
			deployment := &appsv1.Deployment{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, deployment)
			}, timeout, interval).Should(Succeed())

			volumes := deployment.Spec.Template.Spec.Volumes
			Expect(volumes).To(HaveLen(1))
			Expect(volumes[0].VolumeSource.PersistentVolumeClaim).NotTo(BeNil())
			Expect(volumes[0].VolumeSource.PersistentVolumeClaim.ClaimName).To(Equal(existingPVCName))
		})
	})

	Context("When creating a StatefulSet with persistence enabled", func() {
		const instanceName = "test-sts-persistence-instance"

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret

		BeforeEach(func() {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"encryption-key": []byte("test-encryption-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					DeploymentType: "StatefulSet",
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
					Persistence: pocketidinternalv1alpha1.PersistenceConfig{
						Enabled:     true,
						Size:        resource.MustParse("3Gi"),
						AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should create a StatefulSet with volumeClaimTemplates", func() {
			sts := &appsv1.StatefulSet{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, sts)
			}, timeout, interval).Should(Succeed())

			// Verify volumeClaimTemplates is configured
			Expect(sts.Spec.VolumeClaimTemplates).To(HaveLen(1))
			Expect(sts.Spec.VolumeClaimTemplates[0].Name).To(Equal("data"))
			Expect(sts.Spec.VolumeClaimTemplates[0].Spec.AccessModes).To(Equal([]corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}))
			Expect(sts.Spec.VolumeClaimTemplates[0].Spec.Resources.Requests[corev1.ResourceStorage]).To(Equal(resource.MustParse("3Gi")))

			// Verify volume mount is configured
			volumeMounts := sts.Spec.Template.Spec.Containers[0].VolumeMounts
			Expect(volumeMounts).To(HaveLen(1))
			Expect(volumeMounts[0].Name).To(Equal("data"))
			Expect(volumeMounts[0].MountPath).To(Equal("/app/data"))

			// Verify NO volumes in pod template (because volumeClaimTemplates handles it)
			volumes := sts.Spec.Template.Spec.Volumes
			Expect(volumes).To(BeEmpty())
		})

		It("Should NOT create a separate PersistentVolumeClaim", func() {
			// StatefulSets manage their own PVCs via volumeClaimTemplates
			pvc := &corev1.PersistentVolumeClaim{}
			Consistently(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName + "-data",
					Namespace: namespace,
				}, pvc)
			}, time.Second*2, interval).ShouldNot(Succeed())
		})
	})

	Context("When creating a StatefulSet with an existing PVC", func() {
		const instanceName = "test-sts-existing-claim"

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret
		var existingPVC *corev1.PersistentVolumeClaim

		BeforeEach(func() {
			existingPVC = &corev1.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "existing-sts-pvc-",
					Namespace:    namespace,
				},
				Spec: corev1.PersistentVolumeClaimSpec{
					AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					Resources: corev1.VolumeResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceStorage: resource.MustParse("2Gi"),
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, existingPVC)).To(Succeed())

			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"encryption-key": []byte("test-encryption-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					DeploymentType: "StatefulSet",
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
					Persistence: pocketidinternalv1alpha1.PersistenceConfig{
						Enabled:       true,
						ExistingClaim: existingPVC.Name,
					},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
			if existingPVC != nil {
				_ = k8sClient.Delete(ctx, existingPVC)
			}
		})

		It("Should mount the existing PVC and not create templates", func() {
			sts := &appsv1.StatefulSet{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, sts)
			}, timeout, interval).Should(Succeed())

			Expect(sts.Spec.VolumeClaimTemplates).To(BeEmpty())

			volumes := sts.Spec.Template.Spec.Volumes
			Expect(volumes).To(HaveLen(1))
			Expect(volumes[0].VolumeSource.PersistentVolumeClaim).NotTo(BeNil())
			Expect(volumes[0].VolumeSource.PersistentVolumeClaim.ClaimName).To(Equal(existingPVC.Name))
		})

		It("Should NOT create a separate PersistentVolumeClaim", func() {
			pvc := &corev1.PersistentVolumeClaim{}
			Consistently(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName + "-data",
					Namespace: namespace,
				}, pvc)
			}, time.Second*2, interval).ShouldNot(Succeed())
		})
	})

	Context("When creating a StatefulSet with persistence disabled", func() {
		const instanceName = "test-sts-no-persistence-instance"

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret

		BeforeEach(func() {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"encryption-key": []byte("test-encryption-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					DeploymentType: "StatefulSet",
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
					Persistence: pocketidinternalv1alpha1.PersistenceConfig{
						Enabled: false,
					},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should use an emptyDir volume in StatefulSet", func() {
			sts := &appsv1.StatefulSet{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, sts)
			}, timeout, interval).Should(Succeed())

			// Verify emptyDir volume is configured
			volumes := sts.Spec.Template.Spec.Volumes
			Expect(volumes).To(HaveLen(1))
			Expect(volumes[0].Name).To(Equal("data"))
			Expect(volumes[0].VolumeSource.EmptyDir).NotTo(BeNil())

			// Verify volume mount
			volumeMounts := sts.Spec.Template.Spec.Containers[0].VolumeMounts
			Expect(volumeMounts).To(HaveLen(1))
			Expect(volumeMounts[0].Name).To(Equal("data"))
			Expect(volumeMounts[0].MountPath).To(Equal("/app/data"))

			// Verify NO volumeClaimTemplates
			Expect(sts.Spec.VolumeClaimTemplates).To(BeEmpty())
		})

		It("Should NOT create any PersistentVolumeClaim", func() {
			pvc := &corev1.PersistentVolumeClaim{}
			Consistently(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName + "-data",
					Namespace: namespace,
				}, pvc)
			}, time.Second*2, interval).ShouldNot(Succeed())
		})
	})

	Context("When using plaintext environment variables", func() {
		const instanceName = "test-plaintext-env"

		var instance *pocketidinternalv1alpha1.PocketIDInstance

		BeforeEach(func() {
			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						Value: "my-plaintext-encryption-key",
					},
					DatabaseUrl: &pocketidinternalv1alpha1.EnvValue{
						Value: "sqlite:///app/data/pocket-id.db",
					},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
		})

		It("Should create a Deployment with plaintext environment variables", func() {
			deployment := &appsv1.Deployment{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, deployment)
			}, timeout, interval).Should(Succeed())

			envVars := deployment.Spec.Template.Spec.Containers[0].Env

			// Check ENCRYPTION_KEY is set as plaintext
			var encKeyEnv *corev1.EnvVar
			var dbUrlEnv *corev1.EnvVar
			for i := range envVars {
				if envVars[i].Name == envEncryptionKey {
					encKeyEnv = &envVars[i]
				}
				if envVars[i].Name == envDBConnectionString {
					dbUrlEnv = &envVars[i]
				}
			}

			Expect(encKeyEnv).NotTo(BeNil())
			Expect(encKeyEnv.Value).To(Equal("my-plaintext-encryption-key"))
			Expect(encKeyEnv.ValueFrom).To(BeNil())

			Expect(dbUrlEnv).NotTo(BeNil())
			Expect(dbUrlEnv.Value).To(Equal("sqlite:///app/data/pocket-id.db"))
			Expect(dbUrlEnv.ValueFrom).To(BeNil())
		})
	})

	Context("When mixing plaintext and secret references", func() {
		const instanceName = "test-mixed-env"

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret

		BeforeEach(func() {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"db-password": []byte("super-secret-password"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						Value: "plaintext-key-with-16-chars",
					},
					DatabaseUrl: &pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "db-password",
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should handle mixed plaintext and secret references", func() {
			deployment := &appsv1.Deployment{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, deployment)
			}, timeout, interval).Should(Succeed())

			envVars := deployment.Spec.Template.Spec.Containers[0].Env

			var encKeyEnv *corev1.EnvVar
			var dbUrlEnv *corev1.EnvVar
			for i := range envVars {
				if envVars[i].Name == envEncryptionKey {
					encKeyEnv = &envVars[i]
				}
				if envVars[i].Name == envDBConnectionString {
					dbUrlEnv = &envVars[i]
				}
			}

			// EncryptionKey should be plaintext
			Expect(encKeyEnv).NotTo(BeNil())
			Expect(encKeyEnv.Value).To(Equal("plaintext-key-with-16-chars"))
			Expect(encKeyEnv.ValueFrom).To(BeNil())

			// DatabaseUrl should be from secret
			Expect(dbUrlEnv).NotTo(BeNil())
			Expect(dbUrlEnv.ValueFrom).NotTo(BeNil())
			Expect(dbUrlEnv.ValueFrom.SecretKeyRef).NotTo(BeNil())
			Expect(dbUrlEnv.ValueFrom.SecretKeyRef.Name).To(Equal(secret.Name))
			Expect(dbUrlEnv.ValueFrom.SecretKeyRef.Key).To(Equal("db-password"))
			Expect(dbUrlEnv.Value).To(BeEmpty())
		})
	})

	Context("When creating a PocketIDInstance with encryption key shorter than 16 bytes", func() {
		const instanceName = "test-short-key"

		It("Should reject the PocketIDInstance with validation error", func() {
			instance := &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						Value: "short-key",
					},
				},
			}

			err := k8sClient.Create(ctx, instance)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.encryptionKey.value"))
			Expect(err.Error()).To(ContainSubstring("should be at least 16 chars long"))
		})
	})

	Context("When updating a PocketIDInstance", func() {
		const instanceName = "test-update-instance"

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret

		BeforeEach(func() {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"encryption-key": []byte("test-encryption-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					Image: "ghcr.io/pocket-id/pocket-id:v2.3.0-distroless@sha256:85a7485108325e34679b0fbca0baeb8418401f6d6cf59944d50f3ec013aafd09",
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())

			// Wait for initial deployment
			deployment := &appsv1.Deployment{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, deployment)
			}, timeout, interval).Should(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should update Deployment when image changes", func() {
			// Update the instance image
			Eventually(func() error {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(instance), instance); err != nil {
					return err
				}
				instance.Spec.Image = "ghcr.io/pocket-id/pocket-id:v2.3.0-distroless@sha256:85a7485108325e34679b0fbca0baeb8418401f6d6cf59944d50f3ec013aafd09"
				return k8sClient.Update(ctx, instance)
			}, timeout, interval).Should(Succeed())

			// Verify deployment is updated
			deployment := &appsv1.Deployment{}
			Eventually(func() string {
				if err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, deployment); err != nil {
					return ""
				}
				return deployment.Spec.Template.Spec.Containers[0].Image
			}, timeout, interval).Should(Equal("ghcr.io/pocket-id/pocket-id:v2.3.0-distroless@sha256:85a7485108325e34679b0fbca0baeb8418401f6d6cf59944d50f3ec013aafd09"))
		})

		It("Should reject changes to deploymentType", func() {
			// Attempt to change deploymentType from Deployment to StatefulSet
			Eventually(func() error {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(instance), instance); err != nil {
					return err
				}
				instance.Spec.DeploymentType = "StatefulSet"
				return k8sClient.Update(ctx, instance)
			}, timeout, interval).ShouldNot(Succeed())
		})
	})

	Context("When disabling persistence after it was enabled", func() {
		const instanceName = "test-disable-persistence"

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret

		BeforeEach(func() {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"encryption-key": []byte("test-encryption-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
					Persistence: pocketidinternalv1alpha1.PersistenceConfig{
						Enabled:     true,
						Size:        resource.MustParse("1Gi"),
						AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())

			// Wait for PVC to be created
			pvc := &corev1.PersistentVolumeClaim{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName + "-data",
					Namespace: namespace,
				}, pvc)
			}, timeout, interval).Should(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should delete the PVC when persistence is disabled", func() {
			// Disable persistence
			Eventually(func() error {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(instance), instance); err != nil {
					return err
				}
				instance.Spec.Persistence.Enabled = false
				return k8sClient.Update(ctx, instance)
			}, timeout, interval).Should(Succeed())

			// Verify PVC is marked for deletion (has deletion timestamp)
			pvc := &corev1.PersistentVolumeClaim{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName + "-data",
					Namespace: namespace,
				}, pvc)
				if err != nil {
					// PVC is gone
					return true
				}
				// PVC has deletion timestamp
				return !pvc.DeletionTimestamp.IsZero()
			}, timeout, interval).Should(BeTrue())
		})
	})

	Context("When creating a PocketIDInstance with default security contexts", func() {
		const instanceName = "test-security-defaults"

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret

		BeforeEach(func() {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"encryption-key": []byte("test-encryption-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should apply secure default security contexts", func() {
			deployment := &appsv1.Deployment{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, deployment)
			}, timeout, interval).Should(Succeed())

			// Verify pod security context defaults
			podSecCtx := deployment.Spec.Template.Spec.SecurityContext
			Expect(podSecCtx).NotTo(BeNil())
			Expect(podSecCtx.RunAsNonRoot).NotTo(BeNil())
			Expect(*podSecCtx.RunAsNonRoot).To(BeTrue())
			Expect(podSecCtx.RunAsUser).NotTo(BeNil())
			Expect(*podSecCtx.RunAsUser).To(Equal(int64(65534)))
			Expect(podSecCtx.FSGroup).NotTo(BeNil())
			Expect(*podSecCtx.FSGroup).To(Equal(int64(65534)))
			Expect(podSecCtx.SeccompProfile).NotTo(BeNil())
			Expect(podSecCtx.SeccompProfile.Type).To(Equal(corev1.SeccompProfileTypeRuntimeDefault))

			// Verify container security context defaults
			containerSecCtx := deployment.Spec.Template.Spec.Containers[0].SecurityContext
			Expect(containerSecCtx).NotTo(BeNil())
			Expect(containerSecCtx.AllowPrivilegeEscalation).NotTo(BeNil())
			Expect(*containerSecCtx.AllowPrivilegeEscalation).To(BeFalse())
			Expect(containerSecCtx.RunAsNonRoot).NotTo(BeNil())
			Expect(*containerSecCtx.RunAsNonRoot).To(BeTrue())
			Expect(containerSecCtx.ReadOnlyRootFilesystem).NotTo(BeNil())
			Expect(*containerSecCtx.ReadOnlyRootFilesystem).To(BeTrue())
			Expect(containerSecCtx.Capabilities).NotTo(BeNil())
			Expect(containerSecCtx.Capabilities.Drop).To(ContainElement(corev1.Capability("ALL")))
		})
	})

	Context("When creating a PocketIDInstance with custom security contexts", func() {
		const instanceName = "test-security-custom"

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret

		BeforeEach(func() {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"encryption-key": []byte("test-encryption-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			customRunAsUser := int64(1000)
			customFSGroup := int64(2000)
			readOnlyRootFS := true

			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
					PodSecurityContext: &corev1.PodSecurityContext{
						FSGroup: &customFSGroup,
					},
					ContainerSecurityContext: &corev1.SecurityContext{
						RunAsUser:              &customRunAsUser,
						ReadOnlyRootFilesystem: &readOnlyRootFS,
					},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should merge custom values with defaults", func() {
			deployment := &appsv1.Deployment{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, deployment)
			}, timeout, interval).Should(Succeed())

			// Verify pod security context - custom FSGroup, default RunAsUser
			podSecCtx := deployment.Spec.Template.Spec.SecurityContext
			Expect(podSecCtx).NotTo(BeNil())
			Expect(*podSecCtx.FSGroup).To(Equal(int64(2000)))    // Custom value
			Expect(*podSecCtx.RunAsUser).To(Equal(int64(65534))) // Default value
			Expect(*podSecCtx.RunAsNonRoot).To(BeTrue())         // Default value

			// Verify container security context - custom RunAsUser and ReadOnlyRootFilesystem, default AllowPrivilegeEscalation
			containerSecCtx := deployment.Spec.Template.Spec.Containers[0].SecurityContext
			Expect(containerSecCtx).NotTo(BeNil())
			Expect(*containerSecCtx.RunAsUser).To(Equal(int64(1000)))                              // Custom value
			Expect(*containerSecCtx.ReadOnlyRootFilesystem).To(BeTrue())                           // Custom value
			Expect(*containerSecCtx.AllowPrivilegeEscalation).To(BeFalse())                        // Default value
			Expect(containerSecCtx.Capabilities.Drop).To(ContainElement(corev1.Capability("ALL"))) // Default value
		})
	})

	Context("When creating a PocketIDInstance with custom labels and annotations", func() {
		const instanceName = "test-labels-annotations"

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret

		BeforeEach(func() {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"encryption-key": []byte("test-encryption-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
					Labels: map[string]string{
						"custom-label":  "custom-value",
						"another-label": "another-value",
						"team":          "platform",
					},
					Annotations: map[string]string{
						"custom-annotation":    "custom-annotation-value",
						"prometheus.io/scrape": "true",
					},
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should apply labels and annotations to Deployment and pod template", func() {
			deployment := &appsv1.Deployment{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, deployment)
			}, timeout, interval).Should(Succeed())

			// Verify labels on Deployment
			Expect(deployment.Labels).To(HaveKeyWithValue("custom-label", "custom-value"))
			Expect(deployment.Labels).To(HaveKeyWithValue("another-label", "another-value"))
			Expect(deployment.Labels).To(HaveKeyWithValue("team", "platform"))

			// Verify annotations on Deployment
			Expect(deployment.Annotations).To(HaveKeyWithValue("custom-annotation", "custom-annotation-value"))
			Expect(deployment.Annotations).To(HaveKeyWithValue("prometheus.io/scrape", "true"))

			// Verify labels on pod template (should include both default and custom)
			podLabels := deployment.Spec.Template.Labels
			Expect(podLabels).To(HaveKeyWithValue("app.kubernetes.io/name", "pocket-id"))
			Expect(podLabels).To(HaveKeyWithValue("app.kubernetes.io/instance", instanceName))
			Expect(podLabels).To(HaveKeyWithValue("custom-label", "custom-value"))
			Expect(podLabels).To(HaveKeyWithValue("team", "platform"))

			// Verify annotations on pod template
			podAnnotations := deployment.Spec.Template.Annotations
			Expect(podAnnotations).To(HaveKeyWithValue("custom-annotation", "custom-annotation-value"))
			Expect(podAnnotations).To(HaveKeyWithValue("prometheus.io/scrape", "true"))
		})
	})

	Context("When creating a PocketIDInstance with explicit auth config", func() {
		const instanceName = "test-auth-explicit"

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret

		BeforeEach(func() {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"encryption-key": []byte("test-encryption-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
					AppURL: "https://auth.example.com",
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should create the instance with explicit auth config", func() {
			createdInstance := &pocketidinternalv1alpha1.PocketIDInstance{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, createdInstance)
			}, timeout, interval).Should(Succeed())
		})
	})

	Context("When creating a PocketIDInstance without auth config (defaults)", func() {
		const instanceName = "test-auth-default"

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret

		BeforeEach(func() {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"encryption-key": []byte("test-encryption-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			// Create instance WITHOUT auth config - should use defaults
			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
					AppURL: "https://auth.example.com",
					// Auth is intentionally nil - controller should use defaults
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should create the instance without auth config (controller uses defaults)", func() {
			createdInstance := &pocketidinternalv1alpha1.PocketIDInstance{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, createdInstance)
			}, timeout, interval).Should(Succeed())
		})
	})

	Context("When creating a PocketIDInstance with auth using default values", func() {
		const instanceName = "test-auth-with-defaults"

		var instance *pocketidinternalv1alpha1.PocketIDInstance
		var secret *corev1.Secret

		BeforeEach(func() {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName + "-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"encryption-key": []byte("test-encryption-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			// Create with explicit auth using kubebuilder defaults
			instance = &pocketidinternalv1alpha1.PocketIDInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
					EncryptionKey: pocketidinternalv1alpha1.EnvValue{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
					AppURL: "https://auth.example.com",
				},
			}
			Expect(k8sClient.Create(ctx, instance)).To(Succeed())
		})

		AfterEach(func() {
			if instance != nil {
				_ = k8sClient.Delete(ctx, instance)
			}
			if secret != nil {
				_ = k8sClient.Delete(ctx, secret)
			}
		})

		It("Should create the instance with default auth values", func() {
			createdInstance := &pocketidinternalv1alpha1.PocketIDInstance{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, createdInstance)
			}, timeout, interval).Should(Succeed())
		})
	})

	Context("Static API Key Secret Lifecycle", func() {
		Context("When creating a PocketIDInstance", func() {
			const instanceName = "test-static-api-key-creation"

			var instance *pocketidinternalv1alpha1.PocketIDInstance
			var secret *corev1.Secret

			BeforeEach(func() {
				secret = &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      instanceName + "-secret",
						Namespace: namespace,
					},
					Data: map[string][]byte{
						"encryption-key": []byte("test-encryption-key-value"),
					},
				}
				Expect(k8sClient.Create(ctx, secret)).To(Succeed())

				instance = &pocketidinternalv1alpha1.PocketIDInstance{
					ObjectMeta: metav1.ObjectMeta{
						Name:      instanceName,
						Namespace: namespace,
					},
					Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
						EncryptionKey: pocketidinternalv1alpha1.EnvValue{
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: secret.Name,
									},
									Key: "encryption-key",
								},
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, instance)).To(Succeed())
			})

			AfterEach(func() {
				if instance != nil {
					_ = k8sClient.Delete(ctx, instance)
				}
				if secret != nil {
					_ = k8sClient.Delete(ctx, secret)
				}
			})

			It("Should automatically create a static API key secret", func() {
				staticSecret := &corev1.Secret{}
				Eventually(func() error {
					return k8sClient.Get(ctx, types.NamespacedName{
						Name:      instanceName + "-static-api-key",
						Namespace: namespace,
					}, staticSecret)
				}, timeout, interval).Should(Succeed())

				// Verify secret has a token field
				Expect(staticSecret.Data).To(HaveKey("token"))
				token := string(staticSecret.Data["token"])
				Expect(token).NotTo(BeEmpty())

				// Verify token is a valid base64-encoded string
				_, err := base64.URLEncoding.DecodeString(token)
				Expect(err).NotTo(HaveOccurred())
			})

			It("Should set controller reference on the static API key secret", func() {
				staticSecret := &corev1.Secret{}
				Eventually(func() error {
					return k8sClient.Get(ctx, types.NamespacedName{
						Name:      instanceName + "-static-api-key",
						Namespace: namespace,
					}, staticSecret)
				}, timeout, interval).Should(Succeed())

				// Verify owner reference is set
				Expect(staticSecret.OwnerReferences).To(HaveLen(1))
				Expect(staticSecret.OwnerReferences[0].Name).To(Equal(instanceName))
				Expect(staticSecret.OwnerReferences[0].Kind).To(Equal("PocketIDInstance"))
				Expect(*staticSecret.OwnerReferences[0].Controller).To(BeTrue())
			})

			It("Should inject STATIC_API_KEY env var referencing the secret", func() {
				deployment := &appsv1.Deployment{}
				Eventually(func() error {
					return k8sClient.Get(ctx, types.NamespacedName{
						Name:      instanceName,
						Namespace: namespace,
					}, deployment)
				}, timeout, interval).Should(Succeed())

				envVars := deployment.Spec.Template.Spec.Containers[0].Env

				var staticAPIKeyEnv *corev1.EnvVar
				for i := range envVars {
					if envVars[i].Name == "STATIC_API_KEY" {
						staticAPIKeyEnv = &envVars[i]
						break
					}
				}

				Expect(staticAPIKeyEnv).NotTo(BeNil())
				Expect(staticAPIKeyEnv.ValueFrom).NotTo(BeNil())
				Expect(staticAPIKeyEnv.ValueFrom.SecretKeyRef).NotTo(BeNil())
				Expect(staticAPIKeyEnv.ValueFrom.SecretKeyRef.Name).To(Equal(instanceName + "-static-api-key"))
				Expect(staticAPIKeyEnv.ValueFrom.SecretKeyRef.Key).To(Equal("token"))
			})
		})

		Context("When deleting a PocketIDInstance", func() {
			const instanceName = "test-static-api-key-deletion"

			var instance *pocketidinternalv1alpha1.PocketIDInstance
			var secret *corev1.Secret

			It("Should have owner reference set for garbage collection", func() {
				secret = &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      instanceName + "-secret",
						Namespace: namespace,
					},
					Data: map[string][]byte{
						"encryption-key": []byte("test-encryption-key-value"),
					},
				}
				Expect(k8sClient.Create(ctx, secret)).To(Succeed())

				instance = &pocketidinternalv1alpha1.PocketIDInstance{
					ObjectMeta: metav1.ObjectMeta{
						Name:      instanceName,
						Namespace: namespace,
					},
					Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
						EncryptionKey: pocketidinternalv1alpha1.EnvValue{
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: secret.Name,
									},
									Key: "encryption-key",
								},
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, instance)).To(Succeed())

				// Wait for static API key secret to be created
				staticSecret := &corev1.Secret{}
				Eventually(func() error {
					return k8sClient.Get(ctx, types.NamespacedName{
						Name:      instanceName + "-static-api-key",
						Namespace: namespace,
					}, staticSecret)
				}, timeout, interval).Should(Succeed())

				// Verify owner reference ensures deletion with instance
				Expect(staticSecret.OwnerReferences).To(HaveLen(1))
				Expect(staticSecret.OwnerReferences[0].Name).To(Equal(instanceName))
				Expect(*staticSecret.OwnerReferences[0].Controller).To(BeTrue())
				Expect(*staticSecret.OwnerReferences[0].BlockOwnerDeletion).To(BeTrue())

				// Clean up
				_ = k8sClient.Delete(ctx, instance)
				_ = k8sClient.Delete(ctx, secret)
			})
		})

		Context("When static API key secret is deleted externally", func() {
			const instanceName = "test-static-api-key-regeneration"

			var instance *pocketidinternalv1alpha1.PocketIDInstance
			var secret *corev1.Secret

			BeforeEach(func() {
				secret = &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      instanceName + "-secret",
						Namespace: namespace,
					},
					Data: map[string][]byte{
						"encryption-key": []byte("test-encryption-key-value"),
					},
				}
				Expect(k8sClient.Create(ctx, secret)).To(Succeed())

				instance = &pocketidinternalv1alpha1.PocketIDInstance{
					ObjectMeta: metav1.ObjectMeta{
						Name:      instanceName,
						Namespace: namespace,
					},
					Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
						EncryptionKey: pocketidinternalv1alpha1.EnvValue{
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: secret.Name,
									},
									Key: "encryption-key",
								},
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, instance)).To(Succeed())

				// Wait for static API key secret to be created
				staticSecret := &corev1.Secret{}
				Eventually(func() error {
					return k8sClient.Get(ctx, types.NamespacedName{
						Name:      instanceName + "-static-api-key",
						Namespace: namespace,
					}, staticSecret)
				}, timeout, interval).Should(Succeed())
			})

			AfterEach(func() {
				if instance != nil {
					_ = k8sClient.Delete(ctx, instance)
				}
				if secret != nil {
					_ = k8sClient.Delete(ctx, secret)
				}
			})

			It("Should regenerate the static API key secret if deleted", func() {
				// Get the original secret token
				staticSecret := &corev1.Secret{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName + "-static-api-key",
					Namespace: namespace,
				}, staticSecret)).To(Succeed())

				originalToken := string(staticSecret.Data["token"])
				Expect(originalToken).NotTo(BeEmpty())

				// Delete the static API key secret
				Expect(k8sClient.Delete(ctx, staticSecret)).To(Succeed())

				// Verify secret is recreated by controller
				newSecret := &corev1.Secret{}
				Eventually(func() error {
					return k8sClient.Get(ctx, types.NamespacedName{
						Name:      instanceName + "-static-api-key",
						Namespace: namespace,
					}, newSecret)
				}, timeout, interval).Should(Succeed())

				// Verify the new secret has a token
				Expect(newSecret.Data).To(HaveKey("token"))
				newToken := string(newSecret.Data["token"])
				Expect(newToken).NotTo(BeEmpty())

				// Verify it's a different token (regenerated)
				Expect(newToken).NotTo(Equal(originalToken))

				// Verify owner reference is still set
				Expect(newSecret.OwnerReferences).To(HaveLen(1))
				Expect(newSecret.OwnerReferences[0].Name).To(Equal(instanceName))
			})

			It("Should maintain the same secret name after regeneration", func() {
				// Delete the static API key secret
				staticSecret := &corev1.Secret{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName + "-static-api-key",
					Namespace: namespace,
				}, staticSecret)).To(Succeed())

				Expect(k8sClient.Delete(ctx, staticSecret)).To(Succeed())

				// Verify secret is recreated with the same name
				newSecret := &corev1.Secret{}
				Eventually(func() error {
					return k8sClient.Get(ctx, types.NamespacedName{
						Name:      instanceName + "-static-api-key",
						Namespace: namespace,
					}, newSecret)
				}, timeout, interval).Should(Succeed())

				Expect(newSecret.Name).To(Equal(instanceName + "-static-api-key"))
			})
		})

		Context("When multiple reconciliations occur concurrently", func() {
			const instanceName = "test-static-api-key-concurrent"

			var instance *pocketidinternalv1alpha1.PocketIDInstance
			var secret *corev1.Secret

			BeforeEach(func() {
				secret = &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      instanceName + "-secret",
						Namespace: namespace,
					},
					Data: map[string][]byte{
						"encryption-key": []byte("test-encryption-key-value"),
					},
				}
				Expect(k8sClient.Create(ctx, secret)).To(Succeed())

				instance = &pocketidinternalv1alpha1.PocketIDInstance{
					ObjectMeta: metav1.ObjectMeta{
						Name:      instanceName,
						Namespace: namespace,
					},
					Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
						EncryptionKey: pocketidinternalv1alpha1.EnvValue{
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: secret.Name,
									},
									Key: "encryption-key",
								},
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, instance)).To(Succeed())
			})

			AfterEach(func() {
				if instance != nil {
					_ = k8sClient.Delete(ctx, instance)
				}
				if secret != nil {
					_ = k8sClient.Delete(ctx, secret)
				}
			})

			It("Should only create one static API key secret", func() {
				// Wait for secret to be created
				staticSecret := &corev1.Secret{}
				Eventually(func() error {
					return k8sClient.Get(ctx, types.NamespacedName{
						Name:      instanceName + "-static-api-key",
						Namespace: namespace,
					}, staticSecret)
				}, timeout, interval).Should(Succeed())

				// Get the token
				originalToken := string(staticSecret.Data["token"])
				Expect(originalToken).NotTo(BeEmpty())

				// Trigger another reconciliation by updating the instance
				Eventually(func() error {
					if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(instance), instance); err != nil {
						return err
					}
					if instance.Annotations == nil {
						instance.Annotations = make(map[string]string)
					}
					instance.Annotations["test"] = "trigger-reconcile"
					return k8sClient.Update(ctx, instance)
				}, timeout, interval).Should(Succeed())

				// Wait a bit for reconciliation
				time.Sleep(time.Second)

				// Verify the token hasn't changed (same secret reused)
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName + "-static-api-key",
					Namespace: namespace,
				}, staticSecret)).To(Succeed())

				currentToken := string(staticSecret.Data["token"])
				Expect(currentToken).To(Equal(originalToken))
			})
		})

		Context("When static API key secret changes", func() {
			const instanceName = "test-static-api-key-hash-rollout"

			var instance *pocketidinternalv1alpha1.PocketIDInstance
			var secret *corev1.Secret

			BeforeEach(func() {
				secret = &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      instanceName + "-secret",
						Namespace: namespace,
					},
					Data: map[string][]byte{
						"encryption-key": []byte("test-encryption-key-value"),
					},
				}
				Expect(k8sClient.Create(ctx, secret)).To(Succeed())

				instance = &pocketidinternalv1alpha1.PocketIDInstance{
					ObjectMeta: metav1.ObjectMeta{
						Name:      instanceName,
						Namespace: namespace,
					},
					Spec: pocketidinternalv1alpha1.PocketIDInstanceSpec{
						EncryptionKey: pocketidinternalv1alpha1.EnvValue{
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: secret.Name,
									},
									Key: "encryption-key",
								},
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, instance)).To(Succeed())

				// Wait for deployment to be created
				deployment := &appsv1.Deployment{}
				Eventually(func() error {
					return k8sClient.Get(ctx, types.NamespacedName{
						Name:      instanceName,
						Namespace: namespace,
					}, deployment)
				}, timeout, interval).Should(Succeed())
			})

			AfterEach(func() {
				if instance != nil {
					_ = k8sClient.Delete(ctx, instance)
				}
				if secret != nil {
					_ = k8sClient.Delete(ctx, secret)
				}
			})

			It("Should add static API key hash annotation to pod template", func() {
				deployment := &appsv1.Deployment{}
				Eventually(func() error {
					return k8sClient.Get(ctx, types.NamespacedName{
						Name:      instanceName,
						Namespace: namespace,
					}, deployment)
				}, timeout, interval).Should(Succeed())

				// Verify the hash annotation exists
				annotations := deployment.Spec.Template.Annotations
				Expect(annotations).To(HaveKey("pocketid.internal/static-api-key-hash"))
				Expect(annotations["pocketid.internal/static-api-key-hash"]).NotTo(BeEmpty())
			})

			It("Should update hash annotation when secret is regenerated", func() {
				// Get the original hash annotation
				deployment := &appsv1.Deployment{}
				Eventually(func() error {
					return k8sClient.Get(ctx, types.NamespacedName{
						Name:      instanceName,
						Namespace: namespace,
					}, deployment)
				}, timeout, interval).Should(Succeed())

				originalHash := deployment.Spec.Template.Annotations["pocketid.internal/static-api-key-hash"]
				Expect(originalHash).NotTo(BeEmpty())

				// Delete the static API key secret to trigger regeneration
				staticSecret := &corev1.Secret{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName + "-static-api-key",
					Namespace: namespace,
				}, staticSecret)).To(Succeed())

				Expect(k8sClient.Delete(ctx, staticSecret)).To(Succeed())

				// Wait for secret to be regenerated and hash to change
				Eventually(func() string {
					if err := k8sClient.Get(ctx, types.NamespacedName{
						Name:      instanceName,
						Namespace: namespace,
					}, deployment); err != nil {
						return ""
					}
					return deployment.Spec.Template.Annotations["pocketid.internal/static-api-key-hash"]
				}, timeout, interval).ShouldNot(Equal(originalHash))

				// Verify the new hash is not empty
				newHash := deployment.Spec.Template.Annotations["pocketid.internal/static-api-key-hash"]
				Expect(newHash).NotTo(BeEmpty())
				Expect(newHash).NotTo(Equal(originalHash))
			})
		})
	})
})
