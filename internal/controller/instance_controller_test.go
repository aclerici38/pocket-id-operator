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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

var _ = Describe("Instance Controller", func() {
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

	Context("When creating an Instance with Deployment type", func() {
		const instanceName = "test-deployment-instance"

		var instance *pocketidinternalv1alpha1.Instance
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
			instance = &pocketidinternalv1alpha1.Instance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.InstanceSpec{
					DeploymentType: "Deployment",
					Image:          "ghcr.io/pocket-id/pocket-id:v1.0.0",
					EncryptionKey: corev1.EnvVar{
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
			Expect(deployment.Spec.Template.Spec.Containers[0].Image).To(Equal("ghcr.io/pocket-id/pocket-id:v1.0.0"))
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
				if envVars[i].Name == "ENCRYPTION_KEY" {
					encryptionKeyEnv = &envVars[i]
				}
				if envVars[i].Name == "APP_URL" {
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

	Context("When creating an Instance with StatefulSet type", func() {
		const instanceName = "test-statefulset-instance"

		var instance *pocketidinternalv1alpha1.Instance
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
			instance = &pocketidinternalv1alpha1.Instance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.InstanceSpec{
					DeploymentType: "StatefulSet",
					EncryptionKey: corev1.EnvVar{
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

	Context("When creating an Instance with HTTPRoute enabled", func() {
		const instanceName = "test-route-instance"

		var instance *pocketidinternalv1alpha1.Instance
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

			gatewayName := gwapiv1.ObjectName("my-gateway")
			instance = &pocketidinternalv1alpha1.Instance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.InstanceSpec{
					EncryptionKey: corev1.EnvVar{
						ValueFrom: &corev1.EnvVarSource{
							SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: secret.Name,
								},
								Key: "encryption-key",
							},
						},
					},
					Route: pocketidinternalv1alpha1.HttpRouteConfig{
						Enabled: true,
						ParentRefs: []gwapiv1.ParentReference{
							{
								Name: gatewayName,
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

		It("Should create an HTTPRoute", func() {
			httpRoute := &gwapiv1.HTTPRoute{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      instanceName,
					Namespace: namespace,
				}, httpRoute)
			}, timeout, interval).Should(Succeed())

			Expect(httpRoute.Spec.ParentRefs).To(HaveLen(1))
			Expect(httpRoute.Spec.ParentRefs[0].Name).To(Equal(gwapiv1.ObjectName("my-gateway")))
			Expect(httpRoute.Spec.Rules).To(HaveLen(1))
			Expect(httpRoute.Spec.Rules[0].BackendRefs).To(HaveLen(1))
			Expect(httpRoute.Spec.Rules[0].BackendRefs[0].Name).To(Equal(gwapiv1.ObjectName(instanceName)))
		})
	})

	Context("When creating an Instance with persistence enabled", func() {
		const instanceName = "test-persistence-instance"

		var instance *pocketidinternalv1alpha1.Instance
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

			instance = &pocketidinternalv1alpha1.Instance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.InstanceSpec{
					EncryptionKey: corev1.EnvVar{
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

	Context("When creating an Instance with persistence disabled", func() {
		const instanceName = "test-no-persistence-instance"

		var instance *pocketidinternalv1alpha1.Instance
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

			instance = &pocketidinternalv1alpha1.Instance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.InstanceSpec{
					EncryptionKey: corev1.EnvVar{
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

	Context("When creating an Instance with existing PVC", func() {
		var instanceName string
		var existingPVCName string

		var instance *pocketidinternalv1alpha1.Instance
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

			instance = &pocketidinternalv1alpha1.Instance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.InstanceSpec{
					EncryptionKey: corev1.EnvVar{
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
						ExistingClaim: existingPVCName,
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

	Context("When using plaintext environment variables", func() {
		const instanceName = "test-plaintext-env"

		var instance *pocketidinternalv1alpha1.Instance

		BeforeEach(func() {
			instance = &pocketidinternalv1alpha1.Instance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.InstanceSpec{
					EncryptionKey: corev1.EnvVar{
						Value: "my-plaintext-encryption-key",
					},
					DatabaseUrl: &corev1.EnvVar{
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
				if envVars[i].Name == "ENCRYPTION_KEY" {
					encKeyEnv = &envVars[i]
				}
				if envVars[i].Name == "DB_CONNECTION_STRING" {
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

		var instance *pocketidinternalv1alpha1.Instance
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

			instance = &pocketidinternalv1alpha1.Instance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.InstanceSpec{
					EncryptionKey: corev1.EnvVar{
						Value: "plaintext-key",
					},
					DatabaseUrl: &corev1.EnvVar{
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
				if envVars[i].Name == "ENCRYPTION_KEY" {
					encKeyEnv = &envVars[i]
				}
				if envVars[i].Name == "DB_CONNECTION_STRING" {
					dbUrlEnv = &envVars[i]
				}
			}

			// EncryptionKey should be plaintext
			Expect(encKeyEnv).NotTo(BeNil())
			Expect(encKeyEnv.Value).To(Equal("plaintext-key"))
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

	Context("When updating an Instance", func() {
		const instanceName = "test-update-instance"

		var instance *pocketidinternalv1alpha1.Instance
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

			instance = &pocketidinternalv1alpha1.Instance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      instanceName,
					Namespace: namespace,
				},
				Spec: pocketidinternalv1alpha1.InstanceSpec{
					Image: "ghcr.io/pocket-id/pocket-id:v1.0.0",
					EncryptionKey: corev1.EnvVar{
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
				instance.Spec.Image = "ghcr.io/pocket-id/pocket-id:v2.0.0"
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
			}, timeout, interval).Should(Equal("ghcr.io/pocket-id/pocket-id:v2.0.0"))
		})
	})
})
