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
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"maps"
	"reflect"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

const (
	// Environment variable mapping
	envEncryptionKey      = "ENCRYPTION_KEY"
	envDBConnectionString = "DB_CONNECTION_STRING"
	envAppURL             = "APP_URL"
	envStaticAPIKey       = "STATIC_API_KEY"

	deploymentTypeDeployment  = "Deployment"
	deploymentTypeStatefulSet = "StatefulSet"
)

// PocketIDInstanceReconciler reconciles a PocketIDInstance object
type PocketIDInstanceReconciler struct {
	client.Client
	APIReader client.Reader
	Scheme    *runtime.Scheme
}

// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidinstances,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidinstances/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidinstances/finalizers,verbs=update
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pocketid.internal,resources=pocketidusers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the PocketIDInstance object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.22.4/pkg/reconcile
func (r *PocketIDInstanceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	instance := &pocketidinternalv1alpha1.PocketIDInstance{}
	if err := r.Get(ctx, req.NamespacedName, instance); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("Reconciling PocketIDInstance", "name", instance.Name)

	// Ensure static API key secret exists
	secretCreated, err := r.ensureStaticAPIKeySecret(ctx, instance)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure static API key secret: %w", err)
	}

	// If we just created the secret, requeue to give kubelet time to sync it
	if secretCreated {
		log.Info("Static API key secret just created, requeuing to allow kubelet sync", "name", instance.Name)
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}

	if err := r.reconcileWorkload(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.reconcileService(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.reconcileVolume(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.updateStatus(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	return applyResync(ctrl.Result{}), nil
}

// Helpers
func (r *PocketIDInstanceReconciler) reconcileWorkload(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance) error {
	podTemplate := r.buildPodTemplate(instance)

	if instance.Spec.DeploymentType == deploymentTypeStatefulSet {
		return r.reconcileStatefulSet(ctx, instance, podTemplate)
	}
	return r.reconcileDeployment(ctx, instance, podTemplate)
}

func (r *PocketIDInstanceReconciler) buildPodTemplate(instance *pocketidinternalv1alpha1.PocketIDInstance) corev1.PodTemplateSpec {
	labels := managedByLabels(instance.Spec.Labels)
	labels["app.kubernetes.io/name"] = "pocket-id"
	labels["app.kubernetes.io/instance"] = instance.Name
	labels["app.kubernetes.io/managed-by"] = "pocket-id-operator"

	annotations := make(map[string]string)
	maps.Copy(annotations, instance.Spec.Annotations)

	encryptionKeyEnv := corev1.EnvVar{
		Name: envEncryptionKey,
	}
	if instance.Spec.EncryptionKey.Value != "" {
		encryptionKeyEnv.Value = instance.Spec.EncryptionKey.Value
	} else if instance.Spec.EncryptionKey.ValueFrom != nil {
		encryptionKeyEnv.ValueFrom = instance.Spec.EncryptionKey.ValueFrom
	}

	env := []corev1.EnvVar{encryptionKeyEnv}

	if instance.Spec.DatabaseUrl != nil {
		dbUrlEnv := corev1.EnvVar{
			Name: envDBConnectionString,
		}
		if instance.Spec.DatabaseUrl.Value != "" {
			dbUrlEnv.Value = instance.Spec.DatabaseUrl.Value
		} else if instance.Spec.DatabaseUrl.ValueFrom != nil {
			dbUrlEnv.ValueFrom = instance.Spec.DatabaseUrl.ValueFrom
		}
		env = append(env, dbUrlEnv)
	}

	if instance.Spec.AppURL != "" {
		env = append(env, corev1.EnvVar{
			Name:  envAppURL,
			Value: instance.Spec.AppURL,
		})
	}

	if instance.Spec.DisableGlobalRateLimiting {
		env = append(env, corev1.EnvVar{
			Name:  "DISABLE_RATE_LIMITING",
			Value: "true",
		})
	}

	// Always add STATIC_API_KEY for operator authentication
	staticAPIKeySecret := staticAPIKeySecretName(instance.Name)
	env = append(env, corev1.EnvVar{
		Name: envStaticAPIKey,
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: staticAPIKeySecret,
				},
				Key: "token",
			},
		},
	})

	// Add on any extra ENVs from CR
	env = append(env, instance.Spec.Env...)

	var volumes []corev1.Volume
	var volumeMounts []corev1.VolumeMount

	if !instance.Spec.Persistence.Enabled {
		// Use emptyDir if persistence is not enabled
		volumes = append(volumes, corev1.Volume{
			Name: "data",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		})

		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "data",
			MountPath: "/app/data",
		})
	}

	return corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			SecurityContext: buildPodSecurityContext(instance),
			HostUsers:       instance.Spec.HostUsers,
			Containers: []corev1.Container{
				{
					Name:            "pocket-id",
					Image:           instance.Spec.Image,
					Env:             env,
					VolumeMounts:    volumeMounts,
					SecurityContext: buildContainerSecurityContext(instance),
					Resources:       buildResources(instance),
					ReadinessProbe: func() *corev1.Probe {
						if instance.Spec.ReadinessProbe != nil {
							return instance.Spec.ReadinessProbe
						}
						return &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/readyz",
									Port: intstr.FromInt(1411),
								},
							},
							InitialDelaySeconds: 10,
							PeriodSeconds:       10,
							TimeoutSeconds:      5,
							SuccessThreshold:    1,
							FailureThreshold:    3,
						}
					}(),
					LivenessProbe: func() *corev1.Probe {
						if instance.Spec.LivenessProbe != nil {
							return instance.Spec.LivenessProbe
						}
						return &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/readyz",
									Port: intstr.FromInt(1411),
								},
							},
							InitialDelaySeconds: 30,
							PeriodSeconds:       30,
							TimeoutSeconds:      10,
							SuccessThreshold:    1,
							FailureThreshold:    5,
						}
					}(),
				},
			},
			Volumes: volumes,
		},
	}
}

func buildResources(instance *pocketidinternalv1alpha1.PocketIDInstance) corev1.ResourceRequirements {
	defaults := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("50m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}

	userSpec := instance.Spec.Resources

	mergedRequests := make(corev1.ResourceList)
	maps.Copy(mergedRequests, defaults.Requests)
	maps.Copy(mergedRequests, userSpec.Requests)

	mergedLimits := make(corev1.ResourceList)
	maps.Copy(mergedLimits, defaults.Limits)
	maps.Copy(mergedLimits, userSpec.Limits)

	return corev1.ResourceRequirements{
		Requests: mergedRequests,
		Limits:   mergedLimits,
	}
}

func buildPodSecurityContext(instance *pocketidinternalv1alpha1.PocketIDInstance) *corev1.PodSecurityContext {
	runAsNonRoot := true
	runAsUser := int64(65534)
	fsGroup := int64(65534)

	defaults := &corev1.PodSecurityContext{
		RunAsNonRoot: &runAsNonRoot,
		RunAsUser:    &runAsUser,
		FSGroup:      &fsGroup,
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}

	if instance.Spec.PodSecurityContext == nil {
		return defaults
	}

	merged := instance.Spec.PodSecurityContext.DeepCopy()
	if merged.RunAsNonRoot == nil {
		merged.RunAsNonRoot = defaults.RunAsNonRoot
	}
	if merged.RunAsUser == nil {
		merged.RunAsUser = defaults.RunAsUser
	}
	if merged.FSGroup == nil {
		merged.FSGroup = defaults.FSGroup
	}
	if merged.SeccompProfile == nil {
		merged.SeccompProfile = defaults.SeccompProfile
	}

	return merged
}

func buildContainerSecurityContext(instance *pocketidinternalv1alpha1.PocketIDInstance) *corev1.SecurityContext {
	allowPrivilegeEscalation := false
	runAsNonRoot := true
	readOnlyRootFS := true

	defaults := &corev1.SecurityContext{
		AllowPrivilegeEscalation: &allowPrivilegeEscalation,
		RunAsNonRoot:             &runAsNonRoot,
		ReadOnlyRootFilesystem:   &readOnlyRootFS,
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
	}

	if instance.Spec.ContainerSecurityContext == nil {
		return defaults
	}

	merged := instance.Spec.ContainerSecurityContext.DeepCopy()
	if merged.AllowPrivilegeEscalation == nil {
		merged.AllowPrivilegeEscalation = defaults.AllowPrivilegeEscalation
	}
	if merged.RunAsNonRoot == nil {
		merged.RunAsNonRoot = defaults.RunAsNonRoot
	}
	if merged.ReadOnlyRootFilesystem == nil {
		merged.ReadOnlyRootFilesystem = defaults.ReadOnlyRootFilesystem
	}
	if merged.Capabilities == nil {
		merged.Capabilities = defaults.Capabilities
	}

	return merged
}

func (r *PocketIDInstanceReconciler) reconcileDeployment(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance, podTemplate corev1.PodTemplateSpec) error {
	replicas := int32(1)

	if instance.Spec.Persistence.Enabled {
		claimName := instance.Spec.Persistence.ExistingClaim
		if claimName == "" {
			claimName = instance.Name + "-data"
		}

		podTemplate.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{
			{
				Name:      "data",
				MountPath: "/app/data",
			},
		}
		podTemplate.Spec.Volumes = []corev1.Volume{
			{
				Name: "data",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
						ClaimName: claimName,
					},
				},
			},
		}
	}

	selector := map[string]string{
		"app.kubernetes.io/name":     "pocket-id",
		"app.kubernetes.io/instance": instance.Name,
	}

	deployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        instance.Name,
			Namespace:   instance.Namespace,
			Labels:      managedByLabels(instance.Spec.Labels),
			Annotations: instance.Spec.Annotations,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: selector},
			// Pocket-ID uses locking so only 1 process can hold the DB
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: podTemplate,
		},
	}

	if err := controllerutil.SetControllerReference(instance, deployment, r.Scheme); err != nil {
		return err
	}

	return r.Patch(ctx, deployment, client.Apply, client.FieldOwner("pocket-id-operator"))
}

func (r *PocketIDInstanceReconciler) reconcileStatefulSet(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance, podTemplate corev1.PodTemplateSpec) error {
	replicas := int32(1)

	selector := map[string]string{
		"app.kubernetes.io/name":     "pocket-id",
		"app.kubernetes.io/instance": instance.Name,
	}

	stsSpec := &appsv1.StatefulSetSpec{
		Replicas:    &replicas,
		ServiceName: instance.Name,
		Selector:    &metav1.LabelSelector{MatchLabels: selector},
		Template:    podTemplate,
	}

	if instance.Spec.Persistence.Enabled {
		stsSpec.Template.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{
			{
				Name:      "data",
				MountPath: "/app/data",
			},
		}

		if instance.Spec.Persistence.ExistingClaim != "" {
			stsSpec.Template.Spec.Volumes = []corev1.Volume{
				{
					Name: "data",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
							ClaimName: instance.Spec.Persistence.ExistingClaim,
						},
					},
				},
			}
			stsSpec.VolumeClaimTemplates = nil
		} else {
			stsSpec.Template.Spec.Volumes = nil

			var scn *string
			if instance.Spec.Persistence.StorageClass != "" {
				sc := instance.Spec.Persistence.StorageClass
				scn = &sc
			}

			stsSpec.VolumeClaimTemplates = []corev1.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "data",
						Labels: managedByLabels(instance.Spec.Labels),
					},
					Spec: corev1.PersistentVolumeClaimSpec{
						AccessModes:      instance.Spec.Persistence.AccessModes,
						StorageClassName: scn,
						Resources: corev1.VolumeResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceStorage: instance.Spec.Persistence.Size,
							},
						},
					},
				},
			}
		}
	}

	sts := &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "StatefulSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        instance.Name,
			Namespace:   instance.Namespace,
			Labels:      managedByLabels(instance.Spec.Labels),
			Annotations: instance.Spec.Annotations,
		},
		Spec: *stsSpec,
	}

	if err := controllerutil.SetControllerReference(instance, sts, r.Scheme); err != nil {
		return err
	}
	return r.Patch(ctx, sts, client.Apply, client.FieldOwner("pocket-id-operator"))
}

func (r *PocketIDInstanceReconciler) reconcileService(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance) error {
	service := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        instance.Name,
			Namespace:   instance.Namespace,
			Labels:      managedByLabels(instance.Spec.Labels),
			Annotations: instance.Spec.Annotations,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name":     "pocket-id",
				"app.kubernetes.io/instance": instance.Name,
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       1411,
					TargetPort: intstr.FromInt(1411),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	if err := controllerutil.SetControllerReference(instance, service, r.Scheme); err != nil {
		return err
	}

	return r.Patch(ctx, service, client.Apply, client.FieldOwner("pocket-id-operator"))
}

func (r *PocketIDInstanceReconciler) reconcileVolume(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance) error {
	pvc := &corev1.PersistentVolumeClaim{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "PersistentVolumeClaim",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name + "-data",
			Namespace: instance.Namespace,
		},
	}

	// Delete PVC if persistence is disabled, using existing claim, or using StatefulSet
	if !instance.Spec.Persistence.Enabled || instance.Spec.Persistence.ExistingClaim != "" || instance.Spec.DeploymentType == deploymentTypeStatefulSet {
		err := r.Delete(ctx, pvc)
		return client.IgnoreNotFound(err)
	}

	// Ensure storageClass gets set to nil if empty
	var scn *string
	if instance.Spec.Persistence.StorageClass != "" {
		sc := instance.Spec.Persistence.StorageClass
		scn = &sc
	}

	pvc.Labels = managedByLabels(instance.Spec.Labels)

	if err := controllerutil.SetControllerReference(instance, pvc, r.Scheme); err != nil {
		return err
	}

	existing := &corev1.PersistentVolumeClaim{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(pvc), existing); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}

		// PVC doesn't exist
		accessModes := instance.Spec.Persistence.AccessModes
		if len(accessModes) == 0 {
			accessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}
		}

		pvc.Spec = corev1.PersistentVolumeClaimSpec{
			AccessModes:      accessModes,
			StorageClassName: scn,
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: instance.Spec.Persistence.Size,
				},
			},
		}

		return r.Patch(ctx, pvc, client.Apply, client.FieldOwner("pocket-id-operator"))
	}

	// PVC already exists: only update labels if needed
	if !reflect.DeepEqual(existing.Labels, pvc.Labels) {
		existing.Labels = pvc.Labels
		return r.Update(ctx, existing)
	}

	return nil
}

func (r *PocketIDInstanceReconciler) updateStatus(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance) error {
	base := instance.DeepCopy()
	ready := metav1.ConditionFalse
	reason := "Progressing"
	message := "Workload is starting up"

	if instance.Spec.DeploymentType == deploymentTypeStatefulSet {
		sts := &appsv1.StatefulSet{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(instance), sts); err == nil {
			if sts.Status.ReadyReplicas > 0 {
				ready = metav1.ConditionTrue
				reason = readyConditionType
				message = "StatefulSet has ready replicas"
			}
		}
	} else {
		deployment := &appsv1.Deployment{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(instance), deployment); err == nil {
			if deployment.Status.AvailableReplicas > 0 {
				ready = metav1.ConditionTrue
				reason = readyConditionType
				message = "Deployment has available replicas"
			}
		}
	}

	meta.SetStatusCondition(&instance.Status.Conditions, metav1.Condition{
		Type:               readyConditionType,
		Status:             ready,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: instance.Generation,
	})

	// Update static API key secret name in status if not set
	staticAPIKeySecret := staticAPIKeySecretName(instance.Name)
	if instance.Status.StaticAPIKeySecretName != staticAPIKeySecret {
		instance.Status.StaticAPIKeySecretName = staticAPIKeySecret
	}

	return r.Status().Patch(ctx, instance, client.MergeFrom(base))
}

const (
	readyConditionType = "Ready"
)

// staticAPIKeySecretName returns the secret name for the instance's static API key
func staticAPIKeySecretName(instanceName string) string {
	return fmt.Sprintf("%s-static-api-key", instanceName)
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// ensureStaticAPIKeySecret creates or retrieves the static API key secret for bootstrap
// Returns (wasCreated bool, error) where wasCreated is true if the secret was just created
func (r *PocketIDInstanceReconciler) ensureStaticAPIKeySecret(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance) (bool, error) {
	secretName := staticAPIKeySecretName(instance.Name)
	secret := &corev1.Secret{}

	// Check if secret already exists using APIReader to bypass cache
	err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: instance.Namespace, Name: secretName}, secret)
	if err == nil {
		// Secret exists, return that it wasn't just created
		if _, ok := secret.Data["token"]; ok {
			return false, nil
		}
		return false, fmt.Errorf("static API key secret exists but has no token field")
	}

	if !errors.IsNotFound(err) {
		return false, fmt.Errorf("failed to get static API key secret: %w", err)
	}

	// Generate new token
	token, err := generateSecureToken(32)
	if err != nil {
		return false, fmt.Errorf("failed to generate secure token: %w", err)
	}

	// Create new secret
	secret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: instance.Namespace,
		},
		Data: map[string][]byte{
			"token": []byte(token),
		},
	}

	if err := controllerutil.SetControllerReference(instance, secret, r.Scheme); err != nil {
		return false, fmt.Errorf("failed to set controller reference: %w", err)
	}

	if err := r.Create(ctx, secret); err != nil {
		if errors.IsAlreadyExists(err) {
			// Another reconciliation created it, retrieve and return using APIReader to bypass cache
			if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: instance.Namespace, Name: secretName}, secret); err != nil {
				return false, fmt.Errorf("failed to get existing secret after conflict: %w", err)
			}
			if _, ok := secret.Data["token"]; ok {
				return false, nil
			}
			return false, fmt.Errorf("existing secret has no token field")
		}
		return false, fmt.Errorf("failed to create static API key secret: %w", err)
	}

	// Verify the secret was created successfully by reading it back with APIReader
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: instance.Namespace, Name: secretName}, secret); err != nil {
		return false, fmt.Errorf("failed to verify created secret: %w", err)
	}

	// Return true to indicate the secret was just created
	return true, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PocketIDInstanceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&pocketidinternalv1alpha1.PocketIDInstance{}).
		Owns(&appsv1.Deployment{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.PersistentVolumeClaim{}).
		Owns(&corev1.Secret{}).
		Named("pocketidinstance").
		Complete(r)
}
