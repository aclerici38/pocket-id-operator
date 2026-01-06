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
	"maps"
	"net/url"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

const (
	// Environment variable mapping
	envEncryptionKey      = "ENCRYPTION_KEY"
	envDBConnectionString = "DB_CONNECTION_STRING"
	envAppURL             = "APP_URL"

	deploymentTypeDeployment  = "Deployment"
	deploymentTypeStatefulSet = "StatefulSet"
)

// InstanceReconciler reconciles a Instance object
type InstanceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=pocketid.internal,resources=instances,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pocketid.internal,resources=instances/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=pocketid.internal,resources=instances/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Instance object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.22.4/pkg/reconcile
func (r *InstanceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	instance := &pocketidinternalv1alpha1.Instance{}
	if err := r.Get(ctx, req.NamespacedName, instance); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("Reconciling Instance", "name", instance.Name)

	if err := r.reconcileWorkload(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.reconcileService(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.reconcileRoute(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.reconcileVolume(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.updateStatus(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// Helpers
func (r *InstanceReconciler) reconcileWorkload(ctx context.Context, instance *pocketidinternalv1alpha1.Instance) error {
	podTemplate := r.buildPodTemplate(instance)

	if instance.Spec.DeploymentType == deploymentTypeStatefulSet {
		return r.reconcileStatefulSet(ctx, instance, podTemplate)
	}
	return r.reconcileDeployment(ctx, instance, podTemplate)
}

func (r *InstanceReconciler) buildPodTemplate(instance *pocketidinternalv1alpha1.Instance) corev1.PodTemplateSpec {
	labels := make(map[string]string)
	maps.Copy(labels, instance.Spec.Labels)
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

func buildPodSecurityContext(instance *pocketidinternalv1alpha1.Instance) *corev1.PodSecurityContext {
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

	// Allow overriding the defaults
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

func buildContainerSecurityContext(instance *pocketidinternalv1alpha1.Instance) *corev1.SecurityContext {
	allowPrivilegeEscalation := false
	runAsNonRoot := true
	runAsUser := int64(65534)

	defaults := &corev1.SecurityContext{
		AllowPrivilegeEscalation: &allowPrivilegeEscalation,
		RunAsNonRoot:             &runAsNonRoot,
		RunAsUser:                &runAsUser,
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
	}

	if instance.Spec.ContainerSecurityContext == nil {
		return defaults
	}

	// Allow overriding the defaults
	merged := instance.Spec.ContainerSecurityContext.DeepCopy()
	if merged.AllowPrivilegeEscalation == nil {
		merged.AllowPrivilegeEscalation = defaults.AllowPrivilegeEscalation
	}
	if merged.RunAsNonRoot == nil {
		merged.RunAsNonRoot = defaults.RunAsNonRoot
	}
	if merged.RunAsUser == nil {
		merged.RunAsUser = defaults.RunAsUser
	}
	if merged.Capabilities == nil {
		merged.Capabilities = defaults.Capabilities
	}

	return merged
}

func (r *InstanceReconciler) reconcileDeployment(ctx context.Context, instance *pocketidinternalv1alpha1.Instance, podTemplate corev1.PodTemplateSpec) error {
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
		// Add type meta for SSA patching
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        instance.Name,
			Namespace:   instance.Namespace,
			Labels:      instance.Spec.Labels,
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

func (r *InstanceReconciler) reconcileStatefulSet(ctx context.Context, instance *pocketidinternalv1alpha1.Instance, podTemplate corev1.PodTemplateSpec) error {
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
		stsSpec.Template.Spec.Volumes = nil
		stsSpec.Template.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{
			{
				Name:      "data",
				MountPath: "/app/data",
			},
		}

		var scn *string
		if instance.Spec.Persistence.StorageClass != "" {
			sc := instance.Spec.Persistence.StorageClass
			scn = &sc
		}

		stsSpec.VolumeClaimTemplates = []corev1.PersistentVolumeClaim{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "data",
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

	sts := &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "StatefulSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        instance.Name,
			Namespace:   instance.Namespace,
			Labels:      instance.Spec.Labels,
			Annotations: instance.Spec.Annotations,
		},
		Spec: *stsSpec,
	}

	if err := controllerutil.SetControllerReference(instance, sts, r.Scheme); err != nil {
		return err
	}
	return r.Patch(ctx, sts, client.Apply, client.FieldOwner("pocket-id-operator"))
}

func (r *InstanceReconciler) reconcileService(ctx context.Context, instance *pocketidinternalv1alpha1.Instance) error {
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, service, func() error {
		if err := controllerutil.SetControllerReference(instance, service, r.Scheme); err != nil {
			return err
		}

		service.Spec.Selector = map[string]string{
			"app.kubernetes.io/name":     "pocket-id",
			"app.kubernetes.io/instance": instance.Name,
		}

		service.Spec.Ports = []corev1.ServicePort{
			{
				Name:       "http",
				Port:       1411,
				TargetPort: intstr.FromInt(1411),
				Protocol:   corev1.ProtocolTCP,
			},
		}
		return nil
	})
	return err
}

func (r *InstanceReconciler) reconcileRoute(ctx context.Context, instance *pocketidinternalv1alpha1.Instance) error {
	route := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		},
	}

	// If route is disabled, delete it
	if !instance.Spec.Route.Enabled {
		err := r.Delete(ctx, route)
		return client.IgnoreNotFound(err)
	}

	port := gwapiv1.PortNumber(1411)

	var hostnames []gwapiv1.Hostname
	if instance.Spec.AppURL != "" {
		parsedURL, err := url.Parse(instance.Spec.AppURL)
		if err != nil {
			return err
		}
		hostnames = []gwapiv1.Hostname{gwapiv1.Hostname(parsedURL.Hostname())}
	}

	route.TypeMeta = metav1.TypeMeta{
		APIVersion: "gateway.networking.k8s.io/v1",
		Kind:       "HTTPRoute",
	}
	route.Spec = gwapiv1.HTTPRouteSpec{
		CommonRouteSpec: gwapiv1.CommonRouteSpec{
			ParentRefs: instance.Spec.Route.ParentRefs,
		},
		Hostnames: hostnames,
		Rules: []gwapiv1.HTTPRouteRule{
			{
				BackendRefs: []gwapiv1.HTTPBackendRef{
					{
						BackendRef: gwapiv1.BackendRef{
							BackendObjectReference: gwapiv1.BackendObjectReference{
								Name: gwapiv1.ObjectName(instance.Name),
								Port: &port,
							},
						},
					},
				},
			},
		},
	}

	if err := controllerutil.SetControllerReference(instance, route, r.Scheme); err != nil {
		return err
	}

	return r.Patch(ctx, route, client.Apply,
		client.FieldOwner("pocket-id-operator"),
	)
}

func (r *InstanceReconciler) reconcileVolume(ctx context.Context, instance *pocketidinternalv1alpha1.Instance) error {
	pvc := &corev1.PersistentVolumeClaim{
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

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, pvc, func() error {
		if err := controllerutil.SetControllerReference(instance, pvc, r.Scheme); err != nil {
			return err
		}

		// Don't update immutable fields
		if pvc.CreationTimestamp.IsZero() {
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
		return nil
	})
	return err
}

func (r *InstanceReconciler) updateStatus(ctx context.Context, instance *pocketidinternalv1alpha1.Instance) error {
	base := instance.DeepCopy()
	available := metav1.ConditionFalse
	reason := "Progressing"
	message := "Workload is starting up"

	if instance.Spec.DeploymentType == deploymentTypeStatefulSet {
		sts := &appsv1.StatefulSet{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(instance), sts); err == nil {
			if sts.Status.ReadyReplicas > 0 {
				available = metav1.ConditionTrue
				reason = "Ready"
				message = "StatefulSet has ready replicas"
			}
		}
	} else {
		deployment := &appsv1.Deployment{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(instance), deployment); err == nil {
			if deployment.Status.AvailableReplicas > 0 {
				available = metav1.ConditionTrue
				reason = "Ready"
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

// SetupWithManager sets up the controller with the Manager.
func (r *InstanceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&pocketidinternalv1alpha1.Instance{}).
		Owns(&appsv1.Deployment{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.PersistentVolumeClaim{}).
		Owns(&gwapiv1.HTTPRoute{}).
		Named("instance").
		Complete(r)
}
