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

	if instance.Spec.Route.Enabled {
		if err := r.reconcileRoute(ctx, instance); err != nil {
			return ctrl.Result{}, err
		}
	}

	if instance.Spec.Persistence.Enabled {
		if err := r.reconcileVolume(ctx, instance); err != nil {
			return ctrl.Result{}, err
		}
	}

	if err := r.updateStatus(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// Helpers
func (r *InstanceReconciler) reconcileWorkload(ctx context.Context, instance *pocketidinternalv1alpha1.Instance) error {
	podTemplate := r.buildPodTemplate(instance)

	if instance.Spec.DeploymentType == "StatefulSet" {
		return r.reconcileStatefulSet(ctx, instance, podTemplate)
	}
	return r.reconcileDeployment(ctx, instance, podTemplate)
}

func (r *InstanceReconciler) buildPodTemplate(instance *pocketidinternalv1alpha1.Instance) corev1.PodTemplateSpec {
	labels := map[string]string{
		"app.kubernetes.io/name":       "pocket-id",
		"app.kubernetes.io/instance":   instance.Name,
		"app.kubernetes.io/managed-by": "pocket-id-operator",
	}

	encryptionKeyEnv := instance.Spec.EncryptionKey
	encryptionKeyEnv.Name = envEncryptionKey

	env := []corev1.EnvVar{encryptionKeyEnv}

	if instance.Spec.DatabaseUrl != nil {
		dbUrlEnv := *instance.Spec.DatabaseUrl
		dbUrlEnv.Name = envDBConnectionString
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

	if instance.Spec.Persistence.Enabled {
		claimName := instance.Spec.Persistence.ExistingClaim
		if claimName == "" {
			claimName = instance.Name + "-data"
		}

		volumes = append(volumes, corev1.Volume{
			Name: "data",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: claimName,
				},
			},
		})

		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "data",
			MountPath: "/app/data",
		})
	} else {
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
			Labels: labels,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:         "pocket-id",
					Image:        instance.Spec.Image,
					Env:          env,
					VolumeMounts: volumeMounts,
				},
			},
			Volumes: volumes,
		},
	}
}

func (r *InstanceReconciler) reconcileDeployment(ctx context.Context, instance *pocketidinternalv1alpha1.Instance, podTemplate corev1.PodTemplateSpec) error {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, deployment, func() error {
		if err := controllerutil.SetControllerReference(instance, deployment, r.Scheme); err != nil {
			return err
		}

		replicas := int32(1)
		deployment.Spec = appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: podTemplate.Labels,
			},
			Template: podTemplate,
		}
		return nil
	})
	return err
}

func (r *InstanceReconciler) reconcileStatefulSet(ctx context.Context, instance *pocketidinternalv1alpha1.Instance, podTemplate corev1.PodTemplateSpec) error {
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, sts, func() error {
		if err := controllerutil.SetControllerReference(instance, sts, r.Scheme); err != nil {
			return err
		}

		replicas := int32(1)
		sts.Spec = appsv1.StatefulSetSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: podTemplate.Labels,
			},
			Template: podTemplate,
		}
		return nil
	})
	return err
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

		service.Spec = corev1.ServiceSpec{
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
		}
		return nil
	})
	return err
}

func (r *InstanceReconciler) reconcileRoute(ctx context.Context, instance *pocketidinternalv1alpha1.Instance) error {
	port := gwapiv1.PortNumber(1411)
	route := &gwapiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		},
	}

	var hostnames []gwapiv1.Hostname
	if instance.Spec.AppURL != "" {
		parsedUrl, err := url.Parse(instance.Spec.AppURL)
		if err != nil {
			return err
		}
		hostnames = []gwapiv1.Hostname{gwapiv1.Hostname(parsedUrl.Host)}
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, route, func() error {
		if err := controllerutil.SetControllerReference(instance, route, r.Scheme); err != nil {
			return err
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
		return nil
	})
	return err
}

func (r *InstanceReconciler) reconcileVolume(ctx context.Context, instance *pocketidinternalv1alpha1.Instance) error {
	// If using an existing claim, no need to create a PVC
	if instance.Spec.Persistence.ExistingClaim != "" {
		return nil
	}

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name + "-data",
			Namespace: instance.Namespace,
		},
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
				StorageClassName: &instance.Spec.Persistence.StorageClass,
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
	available := metav1.ConditionFalse
	reason := "Progressing"
	message := "Workload is starting up"

	if instance.Spec.DeploymentType == "StatefulSet" {
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

	return r.Status().Update(ctx, instance)
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
