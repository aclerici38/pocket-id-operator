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
	stderrors "errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

const (
	// Environment variable mapping
	envEncryptionKey      = "ENCRYPTION_KEY"
	envDBConnectionString = "DB_CONNECTION_STRING"
	envAppURL             = "APP_URL"

	deploymentTypeDeployment  = "Deployment"
	deploymentTypeStatefulSet = "StatefulSet"
)

// PocketIDInstanceReconciler reconciles a PocketIDInstance object
type PocketIDInstanceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
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

	// Attempt auth reconciliation when instance is available
	// If auth is not configured, use defaults (pocket-id-operator user and API key)
	if r.isInstanceAvailable(instance) {
		result, err := r.reconcileAuth(ctx, instance)
		if err != nil {
			log.Error(err, "Failed to reconcile auth")
			return result, err
		}
		if result.RequeueAfter > 0 {
			return result, nil
		}
	}

	return applyResync(ctrl.Result{}), nil
}

// isInstanceAvailable checks if the instance has Available=True
func (r *PocketIDInstanceReconciler) isInstanceAvailable(instance *pocketidinternalv1alpha1.PocketIDInstance) bool {
	for _, cond := range instance.Status.Conditions {
		if cond.Type == "Available" && cond.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
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
	}

	return r.Patch(ctx, pvc, client.Apply, client.FieldOwner("pocket-id-operator"))
}

func (r *PocketIDInstanceReconciler) updateStatus(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance) error {
	base := instance.DeepCopy()
	available := metav1.ConditionFalse
	reason := "Progressing"
	message := "Workload is starting up"

	if instance.Spec.DeploymentType == deploymentTypeStatefulSet {
		sts := &appsv1.StatefulSet{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(instance), sts); err == nil {
			if sts.Status.ReadyReplicas > 0 {
				available = metav1.ConditionTrue
				reason = readyConditionType
				message = "StatefulSet has ready replicas"
			}
		}
	} else {
		deployment := &appsv1.Deployment{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(instance), deployment); err == nil {
			if deployment.Status.AvailableReplicas > 0 {
				available = metav1.ConditionTrue
				reason = readyConditionType
				message = "Deployment has available replicas"
			}
		}
	}

	meta.SetStatusCondition(&instance.Status.Conditions, metav1.Condition{
		Type:               "Available",
		Status:             available,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: instance.Generation,
	})

	return r.Status().Patch(ctx, instance, client.MergeFrom(base))
}

const (
	defaultAuthUserRef    = "pocket-id-operator"
	defaultAuthAPIKeyName = "pocket-id-operator"
	readyConditionType    = "Ready"
)

// apiKeySecretName returns the secret name for a user's API key: {userRef}-{apiKeyName}-key
func apiKeySecretName(userRef, apiKeyName string) string {
	return fmt.Sprintf("%s-%s-key", userRef, apiKeyName)
}

func isUserReadyStatus(user *pocketidinternalv1alpha1.PocketIDUser) bool {
	for _, condition := range user.Status.Conditions {
		if condition.Type == readyConditionType && condition.Status == metav1.ConditionTrue {
			return true
		}
	}

	return false
}

// reconcileAuth handles bootstrap and auth configuration
func (r *PocketIDInstanceReconciler) reconcileAuth(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Get auth config - use defaults if not configured (matching kubebuilder defaults)
	authUser := resolveAuthUserRef(instance)
	apiKeyName := defaultAuthAPIKeyName
	if instance.Spec.Auth != nil {
		if instance.Spec.Auth.APIKeyName != "" {
			apiKeyName = instance.Spec.Auth.APIKeyName
		}
	}

	user := &pocketidinternalv1alpha1.PocketIDUser{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: authUser.Namespace, Name: authUser.Name}, user); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Waiting for auth user CR to be created", "user", authUser.Name, "namespace", authUser.Namespace)
			return ctrl.Result{RequeueAfter: Requeue}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get auth user CR: %w", err)
	}

	if user.Status.UserID != "" && !user.Status.IsAdmin {
		log.Info("Auth user is not admin; blocking reconcile", "user", authUser.Name)
		return ctrl.Result{RequeueAfter: Requeue}, nil
	}

	if instance.Spec.Auth != nil && instance.Status.AuthUserRef != "" {
		if instance.Status.AuthUserRef != authUser.Name || instance.Status.AuthUserNamespace != authUser.Namespace {
			if !isUserReadyStatus(user) {
				log.Info("Auth user not ready; delaying auth switch", "user", authUser.Name)
				return ctrl.Result{RequeueAfter: Requeue}, nil
			}
		}
	}

	// Check if the API key secret exists
	secretName := apiKeySecretName(authUser.Name, apiKeyName)
	secret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Namespace: authUser.Namespace, Name: secretName}, secret)

	if err == nil {
		// Secret exists - auth is ready, update status
		return r.updateAuthStatus(ctx, instance, authUser, apiKeyName)
	}

	if !errors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("get API key secret: %w", err)
	}

	// Secret doesn't exist - check if already bootstrapped
	if instance.Status.Bootstrapped {
		log.Error(nil, "API key secret missing after bootstrap", "secret", secretName)
		return ctrl.Result{RequeueAfter: Requeue}, fmt.Errorf("API key secret %s not found but instance was bootstrapped", secretName)
	}

	// User CR exists but secret doesn't - need to bootstrap
	return r.bootstrap(ctx, instance, user, apiKeyName)
}

// internalServiceURL returns the internal Kubernetes service URL for the instance
func internalServiceURL(instanceName, namespace string) string {
	return fmt.Sprintf("http://%s.%s.svc.cluster.local:1411", instanceName, namespace)
}

// bootstrap performs the initial setup of Pocket-ID using the provided User CR's spec
func (r *PocketIDInstanceReconciler) bootstrap(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance, user *pocketidinternalv1alpha1.PocketIDUser, apiKeyName string) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Resolve user spec values
	userInfoInputSecret := userInfoInputSecretName(user)
	username, err := r.resolveStringValue(ctx, user.Namespace, user.Spec.Username, userInfoInputSecret, userInfoSecretKeyUsername)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("resolve username: %w", err)
	}
	if username == "" {
		username = user.Name // Default to CR name
	}

	firstName, err := r.resolveStringValue(ctx, user.Namespace, user.Spec.FirstName, userInfoInputSecret, userInfoSecretKeyFirstName)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("resolve firstName: %w", err)
	}
	if firstName == "" {
		firstName = username // Default to username
	}

	lastName, err := r.resolveStringValue(ctx, user.Namespace, user.Spec.LastName, userInfoInputSecret, userInfoSecretKeyLastName)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("resolve lastName: %w", err)
	}

	email, err := r.resolveStringValue(ctx, user.Namespace, user.Spec.Email, userInfoInputSecret, userInfoSecretKeyEmail)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("resolve email: %w", err)
	}
	if email == "" {
		// Generate a default email if not provided
		email = fmt.Sprintf("%s@operator.local", username)
	}

	// Use internal service URL for operator-to-instance communication
	serviceURL := internalServiceURL(instance.Name, instance.Namespace)
	log.Info("Starting bootstrap", "user", user.Name, "username", username, "apiKey", apiKeyName, "serviceURL", serviceURL)

	// Create bootstrap client using internal service URL
	bootstrapClient := pocketid.NewBootstrapClient(serviceURL)

	// Perform bootstrap using the User CR's spec values
	setupReq := pocketid.SetupRequest{
		Username:  username,
		FirstName: firstName,
		LastName:  lastName,
		Email:     email,
	}

	// Find the API key description from the user spec
	apiKeyDescription := ""
	for _, k := range user.Spec.APIKeys {
		if k.Name == apiKeyName {
			apiKeyDescription = k.Description
			break
		}
	}

	setupResp, apiKeyResp, err := bootstrapClient.Bootstrap(
		ctx,
		setupReq,
		apiKeyName,
		apiKeyDescription,
		pocketid.DefaultAPIKeyExpiry(),
	)
	if err != nil {
		if bootstrapNotReady(err) {
			log.Info("Pocket-ID not ready for bootstrap, requeuing", "error", err)
			return ctrl.Result{RequeueAfter: Requeue}, nil
		}
		log.Error(err, "Bootstrap failed")
		return ctrl.Result{}, err
	}

	// Create the API key secret
	apiKeySecret := apiKeySecretName(user.Name, apiKeyName)
	if err := ensureAPIKeySecret(ctx, r.Client, r.Scheme, user, apiKeySecret, apiKeyResp.Token); err != nil {
		return ctrl.Result{}, fmt.Errorf("create API key secret: %w", err)
	}

	pUser := &pocketid.User{
		ID:          setupResp.ID,
		Username:    setupResp.Username,
		FirstName:   setupResp.FirstName,
		LastName:    setupResp.LastName,
		Email:       setupResp.Email,
		DisplayName: setupResp.DisplayName,
		IsAdmin:     setupResp.IsAdmin,
	}

	// Update user status with user info and API key
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := r.Get(ctx, client.ObjectKeyFromObject(user), user); err != nil {
			return err
		}
		userInfoSecret := userInfoOutputSecretName(user.Name)
		if err := ensureUserInfoSecret(ctx, r.Client, r.Scheme, user, userInfoSecret, pUser); err != nil {
			return fmt.Errorf("ensure user info secret: %w", err)
		}
		user.Status.UserID = setupResp.ID
		user.Status.UserInfoSecretName = userInfoSecret
		user.Status.IsAdmin = setupResp.IsAdmin
		mergeAPIKeyStatus(user, pocketidinternalv1alpha1.APIKeyStatus{
			Name:       apiKeyName,
			ID:         apiKeyResp.APIKey.ID,
			CreatedAt:  apiKeyResp.APIKey.CreatedAt,
			ExpiresAt:  apiKeyResp.APIKey.ExpiresAt,
			SecretName: apiKeySecret,
			SecretKey:  apiKeySecretKey,
		})
		return r.Status().Update(ctx, user)
	})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("update user status: %w", err)
	}

	// Update instance status
	base := instance.DeepCopy()
	instance.Status.Bootstrapped = true
	instance.Status.BootstrappedAt = time.Now().Format(time.RFC3339)
	instance.Status.AuthUserRef = user.Name
	instance.Status.AuthUserNamespace = user.Namespace
	instance.Status.AuthAPIKeyName = apiKeyName

	if err := r.Status().Patch(ctx, instance, client.MergeFrom(base)); err != nil {
		return ctrl.Result{}, fmt.Errorf("update instance status: %w", err)
	}

	log.Info("Bootstrap successful")
	return ctrl.Result{}, nil
}

func bootstrapNotReady(err error) bool {
	if err == nil {
		return false
	}
	if stderrors.Is(err, context.DeadlineExceeded) || stderrors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	if stderrors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var urlErr *url.Error
	if stderrors.As(err, &urlErr) && urlErr.Timeout() {
		return true
	}
	msg := err.Error()
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "Client.Timeout exceeded") {
		return true
	}
	return false
}

// updateAuthStatus updates the instance status with auth info
func (r *PocketIDInstanceReconciler) updateAuthStatus(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance, userRef authUserRef, apiKeyName string) (ctrl.Result, error) {
	if instance.Status.AuthUserRef == userRef.Name && instance.Status.AuthUserNamespace == userRef.Namespace && instance.Status.AuthAPIKeyName == apiKeyName {
		return ctrl.Result{}, nil
	}

	base := instance.DeepCopy()
	instance.Status.AuthUserRef = userRef.Name
	instance.Status.AuthUserNamespace = userRef.Namespace
	instance.Status.AuthAPIKeyName = apiKeyName

	if err := r.Status().Patch(ctx, instance, client.MergeFrom(base)); err != nil {
		return ctrl.Result{}, fmt.Errorf("update auth status: %w", err)
	}

	return ctrl.Result{}, nil
}

// resolveStringValue is a convenience wrapper around the shared helper
// The instance controller uses cached client (no APIReader) since it only reads controller-owned secrets
func (r *PocketIDInstanceReconciler) resolveStringValue(ctx context.Context, namespace string, sv pocketidinternalv1alpha1.StringValue, fallbackSecretName, fallbackKey string) (string, error) {
	return ResolveStringValue(ctx, r.Client, nil, namespace, sv, fallbackSecretName, fallbackKey)
}

// SetupWithManager sets up the controller with the Manager.
func (r *PocketIDInstanceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&pocketidinternalv1alpha1.PocketIDInstance{}).
		Owns(&appsv1.Deployment{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.PersistentVolumeClaim{}).
		Owns(&pocketidinternalv1alpha1.PocketIDUser{}).
		Named("pocketidinstance").
		Complete(r)
}
