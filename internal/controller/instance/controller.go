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

package instance

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
	"net/url"
	"reflect"
	"strings"

	"golang.org/x/mod/semver"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	appsv1apply "k8s.io/client-go/applyconfigurations/apps/v1"
	corev1apply "k8s.io/client-go/applyconfigurations/core/v1"
	metav1apply "k8s.io/client-go/applyconfigurations/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1apply "sigs.k8s.io/gateway-api/applyconfiguration/apis/v1"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
	"github.com/aclerici38/pocket-id-operator/internal/controller/common"
)

const (
	// latestTestedPocketIDVersion is the most recent pocket-id upstream version tested.
	// renovate: datasource=docker depName=ghcr.io/pocket-id/pocket-id
	latestTestedPocketIDVersion = "v2.3.0"

	// Environment variable mapping
	envEncryptionKey      = "ENCRYPTION_KEY"
	envDBConnectionString = "DB_CONNECTION_STRING"
	envAppURL             = "APP_URL"
	envStaticAPIKey       = "STATIC_API_KEY"
	envTrustProxy         = "TRUST_PROXY"

	deploymentTypeDeployment  = "Deployment"
	deploymentTypeStatefulSet = "StatefulSet"

	readyConditionType = "Ready"
)

// Reconciler reconciles a PocketIDInstance object
type Reconciler struct {
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
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	instance := &pocketidinternalv1alpha1.PocketIDInstance{}
	if err := r.Get(ctx, req.NamespacedName, instance); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("Reconciling PocketIDInstance", "name", instance.Name)

	// Ensure static API key secret exists
	if err := r.ensureStaticAPIKeySecret(ctx, instance); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensure static API key secret: %w", err)
	}

	if err := r.reconcileWorkload(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.reconcileService(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.reconcileHTTPRoute(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.reconcileVolume(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.updateStatus(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}

	// Fetch and store the deployed PocketID version
	if err := r.reconcileVersion(ctx, instance); err != nil {
		log.Info("WARNING: could not fetch PocketID version from API. Endpoint added in v2.3.0", "error", err)
	}

	return common.ApplyResync(ctrl.Result{}), nil
}

// Helpers
func (r *Reconciler) reconcileWorkload(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance) error {
	// Compute hash of static API key secret to trigger rollout when it changes
	secretHash, err := r.computeStaticAPIKeyHash(ctx, instance)
	if err != nil {
		return fmt.Errorf("compute static API key hash: %w", err)
	}

	podTemplate := r.buildPodTemplate(instance, secretHash)

	if instance.Spec.DeploymentType == deploymentTypeStatefulSet {
		return r.reconcileStatefulSet(ctx, instance, podTemplate)
	}
	return r.reconcileDeployment(ctx, instance, podTemplate)
}

func (r *Reconciler) buildPodTemplate(instance *pocketidinternalv1alpha1.PocketIDInstance, staticAPIKeyHash string) *corev1apply.PodTemplateSpecApplyConfiguration {
	labels := common.ManagedByLabels(instance.Spec.Labels)
	labels["app.kubernetes.io/name"] = "pocket-id"
	labels["app.kubernetes.io/instance"] = instance.Name
	labels["app.kubernetes.io/managed-by"] = "pocket-id-operator"

	annotations := make(map[string]string)
	maps.Copy(annotations, instance.Spec.Annotations)

	if staticAPIKeyHash != "" {
		annotations["pocketid.internal/static-api-key-hash"] = staticAPIKeyHash
	}

	encryptionKeyEnv := corev1.EnvVar{
		Name: envEncryptionKey,
	}
	if instance.Spec.EncryptionKey.Value != "" {
		encryptionKeyEnv.Value = instance.Spec.EncryptionKey.Value
	} else if instance.Spec.EncryptionKey.ValueFrom != nil {
		encryptionKeyEnv.ValueFrom = instance.Spec.EncryptionKey.ValueFrom
	}

	env := []corev1.EnvVar{
		encryptionKeyEnv,
		{
			Name:  envTrustProxy,
			Value: "true",
		},
	}

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

	env = append(env, corev1.EnvVar{
		Name:  "DISABLE_RATE_LIMITING",
		Value: "true",
	})

	// Always add STATIC_API_KEY for operator authentication
	staticAPIKeySecret := common.StaticAPIKeySecretName(instance.Name)
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

	// Inject metrics env vars when enabled
	if instance.Spec.Metrics != nil && instance.Spec.Metrics.Enabled {
		metricsPort := int32(9464)
		if instance.Spec.Metrics.Port != 0 {
			metricsPort = instance.Spec.Metrics.Port
		}
		env = append(env,
			corev1.EnvVar{Name: "METRICS_ENABLED", Value: "true"},
			corev1.EnvVar{Name: "OTEL_METRICS_EXPORTER", Value: "prometheus"},
			corev1.EnvVar{Name: "OTEL_EXPORTER_PROMETHEUS_HOST", Value: "0.0.0.0"},
			corev1.EnvVar{Name: "OTEL_EXPORTER_PROMETHEUS_PORT", Value: fmt.Sprintf("%d", metricsPort)},
		)
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

	container := corev1apply.Container().
		WithName("pocket-id").
		WithImage(instance.Spec.Image).
		WithSecurityContext(securityContextApplyConfiguration(buildContainerSecurityContext(instance))).
		WithResources(resourceRequirementsApplyConfiguration(buildResources(instance)))

	readinessProbe := instance.Spec.ReadinessProbe
	if readinessProbe == nil {
		readinessProbe = &corev1.Probe{
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
	}
	container.WithReadinessProbe(probeApplyConfiguration(readinessProbe))

	livenessProbe := instance.Spec.LivenessProbe
	if livenessProbe == nil {
		livenessProbe = &corev1.Probe{
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
	}
	container.WithLivenessProbe(probeApplyConfiguration(livenessProbe))

	envApply := envVarApplyConfigurationValues(env)
	if len(envApply) > 0 {
		container.Env = envApply
	}

	mountsApply := volumeMountApplyConfigurationValues(volumeMounts)
	if len(mountsApply) > 0 {
		container.VolumeMounts = mountsApply
	}

	podSpec := corev1apply.PodSpec().
		WithSecurityContext(podSecurityContextApplyConfiguration(buildPodSecurityContext(instance)))
	if instance.Spec.HostUsers != nil {
		podSpec.WithHostUsers(*instance.Spec.HostUsers)
	}
	podSpec.Containers = []corev1apply.ContainerApplyConfiguration{*container}

	if len(volumes) > 0 {
		podSpec.Volumes = volumeApplyConfigurationValues(volumes)
	}

	return corev1apply.PodTemplateSpec().
		WithLabels(labels).
		WithAnnotations(annotations).
		WithSpec(podSpec)
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

func (r *Reconciler) reconcileDeployment(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance, podTemplate *corev1apply.PodTemplateSpecApplyConfiguration) error {
	replicas := int32(1)

	if instance.Spec.Persistence.Enabled {
		claimName := instance.Spec.Persistence.ExistingClaim
		if claimName == "" {
			claimName = instance.Name + "-data"
		}

		podTemplate.Spec.Containers[0].VolumeMounts = volumeMountApplyConfigurationValues([]corev1.VolumeMount{
			{
				Name:      "data",
				MountPath: "/app/data",
			},
		})
		podTemplate.Spec.Volumes = volumeApplyConfigurationValues([]corev1.Volume{
			{
				Name: "data",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
						ClaimName: claimName,
					},
				},
			},
		})
	}

	selector := map[string]string{
		"app.kubernetes.io/name":     "pocket-id",
		"app.kubernetes.io/instance": instance.Name,
	}

	ownerRef, err := common.ControllerOwnerReference(instance, r.Scheme)
	if err != nil {
		return err
	}

	deployment := appsv1apply.Deployment(instance.Name, instance.Namespace).
		WithLabels(common.ManagedByLabels(instance.Spec.Labels)).
		WithAnnotations(instance.Spec.Annotations).
		WithOwnerReferences(ownerRef).
		WithSpec(appsv1apply.DeploymentSpec().
			WithReplicas(replicas).
			WithSelector(metav1apply.LabelSelector().WithMatchLabels(selector)).
			WithStrategy(appsv1apply.DeploymentStrategy().WithType(appsv1.RecreateDeploymentStrategyType)).
			WithTemplate(podTemplate),
		)

	return r.Apply(ctx, deployment, client.FieldOwner("pocket-id-operator"))
}

func (r *Reconciler) reconcileStatefulSet(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance, podTemplate *corev1apply.PodTemplateSpecApplyConfiguration) error {
	replicas := int32(1)

	selector := map[string]string{
		"app.kubernetes.io/name":     "pocket-id",
		"app.kubernetes.io/instance": instance.Name,
	}

	stsSpec := appsv1apply.StatefulSetSpec().
		WithReplicas(replicas).
		WithServiceName(instance.Name).
		WithSelector(metav1apply.LabelSelector().WithMatchLabels(selector)).
		WithTemplate(podTemplate)

	if instance.Spec.Persistence.Enabled {
		stsSpec.Template.Spec.Containers[0].VolumeMounts = volumeMountApplyConfigurationValues([]corev1.VolumeMount{
			{
				Name:      "data",
				MountPath: "/app/data",
			},
		})

		if instance.Spec.Persistence.ExistingClaim != "" {
			stsSpec.Template.Spec.Volumes = volumeApplyConfigurationValues([]corev1.Volume{
				{
					Name: "data",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
							ClaimName: instance.Spec.Persistence.ExistingClaim,
						},
					},
				},
			})
		} else {
			stsSpec.Template.Spec.Volumes = nil

			var scn *string
			if instance.Spec.Persistence.StorageClass != "" {
				sc := instance.Spec.Persistence.StorageClass
				scn = &sc
			}

			pvcSpec := corev1apply.PersistentVolumeClaimSpec().
				WithAccessModes(instance.Spec.Persistence.AccessModes...).
				WithResources(corev1apply.VolumeResourceRequirements().WithRequests(corev1.ResourceList{
					corev1.ResourceStorage: instance.Spec.Persistence.Size,
				}))
			if scn != nil {
				pvcSpec.WithStorageClassName(*scn)
			}

			stsSpec.WithVolumeClaimTemplates(corev1apply.PersistentVolumeClaim("data", instance.Namespace).
				WithLabels(common.ManagedByLabels(instance.Spec.Labels)).
				WithSpec(pvcSpec))
		}
	}

	ownerRef, err := common.ControllerOwnerReference(instance, r.Scheme)
	if err != nil {
		return err
	}

	sts := appsv1apply.StatefulSet(instance.Name, instance.Namespace).
		WithLabels(common.ManagedByLabels(instance.Spec.Labels)).
		WithAnnotations(instance.Spec.Annotations).
		WithOwnerReferences(ownerRef).
		WithSpec(stsSpec)

	return r.Apply(ctx, sts, client.FieldOwner("pocket-id-operator"))
}

func (r *Reconciler) reconcileService(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance) error {
	ownerRef, err := common.ControllerOwnerReference(instance, r.Scheme)
	if err != nil {
		return err
	}

	ports := []*corev1apply.ServicePortApplyConfiguration{
		corev1apply.ServicePort().
			WithName("http").
			WithPort(1411).
			WithTargetPort(intstr.FromInt(1411)).
			WithProtocol(corev1.ProtocolTCP),
	}

	if instance.Spec.Metrics != nil && instance.Spec.Metrics.Enabled {
		metricsPort := int32(9464)
		if instance.Spec.Metrics.Port != 0 {
			metricsPort = instance.Spec.Metrics.Port
		}
		ports = append(ports, corev1apply.ServicePort().
			WithName("metrics").
			WithPort(metricsPort).
			WithTargetPort(intstr.FromInt32(metricsPort)).
			WithProtocol(corev1.ProtocolTCP))
	}

	service := corev1apply.Service(instance.Name, instance.Namespace).
		WithLabels(common.ManagedByLabels(instance.Spec.Labels)).
		WithAnnotations(instance.Spec.Annotations).
		WithOwnerReferences(ownerRef).
		WithSpec(corev1apply.ServiceSpec().
			WithSelector(map[string]string{
				"app.kubernetes.io/name":     "pocket-id",
				"app.kubernetes.io/instance": instance.Name,
			}).
			WithPorts(ports...),
		)

	return r.Apply(ctx, service, client.FieldOwner("pocket-id-operator"))
}

func (r *Reconciler) reconcileHTTPRoute(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance) error {
	routeName := instance.Name
	if instance.Spec.Route != nil && instance.Spec.Route.Name != "" {
		routeName = instance.Spec.Route.Name
	}

	if instance.Spec.Route == nil || !instance.Spec.Route.Enabled {
		existing := &gatewayv1.HTTPRoute{}
		existing.Name = routeName
		existing.Namespace = instance.Namespace
		err := r.Delete(ctx, existing)
		if isHTTPRouteCRDUnavailableError(err) {
			return nil
		}
		return client.IgnoreNotFound(err)
	}

	// Check CRD availability at reconcile-time so the controller can start even when
	// Gateway API is absent and pick it up later if installed.
	if err := r.ensureHTTPRouteCRDAvailable(ctx, instance.Namespace); err != nil {
		return err
	}

	ownerRef, err := common.ControllerOwnerReference(instance, r.Scheme)
	if err != nil {
		return err
	}

	labels := common.ManagedByLabels(instance.Spec.Route.Labels)
	labels["app.kubernetes.io/name"] = "pocket-id"
	labels["app.kubernetes.io/instance"] = instance.Name

	parentRefs := make([]*gatewayv1apply.ParentReferenceApplyConfiguration, 0, len(instance.Spec.Route.ParentRefs))
	for _, ref := range instance.Spec.Route.ParentRefs {
		pr := gatewayv1apply.ParentReference().
			WithName(ref.Name)
		if ref.Group != nil {
			pr.WithGroup(*ref.Group)
		}
		if ref.Kind != nil {
			pr.WithKind(*ref.Kind)
		}
		if ref.Namespace != nil {
			pr.WithNamespace(*ref.Namespace)
		}
		if ref.SectionName != nil {
			pr.WithSectionName(*ref.SectionName)
		}
		if ref.Port != nil {
			pr.WithPort(*ref.Port)
		}
		parentRefs = append(parentRefs, pr)
	}

	spec := gatewayv1apply.HTTPRouteSpec().
		WithParentRefs(parentRefs...).
		WithRules(gatewayv1apply.HTTPRouteRule().
			WithBackendRefs(gatewayv1apply.HTTPBackendRef().
				WithName(gatewayv1.ObjectName(instance.Name)).
				WithPort(1411)))

	// Set hostnames from route config, or derive from appUrl
	if len(instance.Spec.Route.Hostnames) > 0 {
		spec.WithHostnames(instance.Spec.Route.Hostnames...)
	} else if instance.Spec.AppURL != "" {
		if u, err := url.Parse(instance.Spec.AppURL); err == nil && u.Host != "" {
			spec.WithHostnames(gatewayv1.Hostname(u.Hostname()))
		}
	}

	httpRoute := gatewayv1apply.HTTPRoute(routeName, instance.Namespace).
		WithLabels(labels).
		WithOwnerReferences(ownerRef).
		WithSpec(spec)

	if len(instance.Spec.Route.Annotations) > 0 {
		httpRoute.WithAnnotations(instance.Spec.Route.Annotations)
	}

	if err := r.Apply(ctx, httpRoute, client.FieldOwner("pocket-id-operator")); err != nil {
		if isHTTPRouteCRDUnavailableError(err) {
			return fmt.Errorf("httproute is enabled but Gateway API CRDs are not installed")
		}
		return err
	}

	return nil
}

func (r *Reconciler) ensureHTTPRouteCRDAvailable(ctx context.Context, namespace string) error {
	list := &gatewayv1.HTTPRouteList{}
	err := r.APIReader.List(ctx, list, client.InNamespace(namespace), client.Limit(1))
	if err == nil {
		return nil
	}
	if isHTTPRouteCRDUnavailableError(err) {
		return fmt.Errorf("httproute is enabled but Gateway API CRDs are not installed")
	}
	return err
}

func isHTTPRouteCRDUnavailableError(err error) bool {
	if err == nil {
		return false
	}
	if errors.IsNotFound(err) {
		return true
	}
	if meta.IsNoMatchError(err) {
		return true
	}
	if strings.Contains(err.Error(), `no matches for kind "HTTPRoute"`) {
		return true
	}
	return strings.Contains(err.Error(), "the server could not find the requested resource")
}

func (r *Reconciler) reconcileVolume(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance) error {
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

	pvc.Labels = common.ManagedByLabels(instance.Spec.Labels)

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

		pvcSpec := corev1apply.PersistentVolumeClaimSpec().
			WithAccessModes(accessModes...).
			WithResources(corev1apply.VolumeResourceRequirements().WithRequests(corev1.ResourceList{
				corev1.ResourceStorage: instance.Spec.Persistence.Size,
			}))
		if scn != nil {
			pvcSpec.WithStorageClassName(*scn)
		}

		ownerRef, err := common.ControllerOwnerReference(instance, r.Scheme)
		if err != nil {
			return err
		}

		pvcApply := corev1apply.PersistentVolumeClaim(pvc.Name, pvc.Namespace).
			WithLabels(pvc.Labels).
			WithOwnerReferences(ownerRef).
			WithSpec(pvcSpec)

		return r.Apply(ctx, pvcApply, client.FieldOwner("pocket-id-operator"))
	}

	// PVC already exists: only update labels if needed
	if !reflect.DeepEqual(existing.Labels, pvc.Labels) {
		existing.Labels = pvc.Labels
		return r.Update(ctx, existing)
	}

	return nil
}

func (r *Reconciler) reconcileVersion(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance) error {
	apiClient, err := common.GetAPIClient(ctx, r.Client, r.APIReader, instance)
	if err != nil {
		return err
	}

	log := logf.FromContext(ctx)

	version, err := apiClient.GetCurrentVersion(ctx)
	if err != nil {
		return err
	}

	if semver.IsValid(version) && semver.Compare(version, latestTestedPocketIDVersion) > 0 {
		log.Info("WARNING: pocket-id version is newer than the latest tested version, the operator may not work correctly",
			"detectedVersion", version,
			"latestTestedVersion", latestTestedPocketIDVersion,
		)
	}

	if instance.Status.Version != version {
		base := instance.DeepCopy()
		instance.Status.Version = version
		return r.Status().Patch(ctx, instance, client.MergeFrom(base))
	}
	return nil
}

func (r *Reconciler) updateStatus(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance) error {
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

	staticAPIKeySecret := common.StaticAPIKeySecretName(instance.Name)
	if instance.Status.StaticAPIKeySecretName != staticAPIKeySecret {
		instance.Status.StaticAPIKeySecretName = staticAPIKeySecret
	}

	return r.Status().Patch(ctx, instance, client.MergeFrom(base))
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// ensureStaticAPIKeySecret creates the static API key secret if it doesn't exist.
func (r *Reconciler) ensureStaticAPIKeySecret(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance) error {
	secretName := common.StaticAPIKeySecretName(instance.Name)
	secret := &corev1.Secret{}

	// Check if secret already exists using APIReader to bypass cache
	err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: instance.Namespace, Name: secretName}, secret)
	if err == nil {
		if token, ok := secret.Data["token"]; ok && len(token) > 0 {
			return nil
		}
		token, err := generateSecureToken(32)
		if err != nil {
			return fmt.Errorf("failed to generate secure token: %w", err)
		}
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		secret.Data["token"] = []byte(token)
		if err := controllerutil.SetControllerReference(instance, secret, r.Scheme); err != nil {
			return fmt.Errorf("failed to set controller reference: %w", err)
		}
		if err := r.Update(ctx, secret); err != nil {
			return fmt.Errorf("failed to update static API key secret: %w", err)
		}
		return nil
	}

	if !errors.IsNotFound(err) {
		return fmt.Errorf("failed to get static API key secret: %w", err)
	}

	token, err := generateSecureToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate secure token: %w", err)
	}

	secret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: instance.Namespace,
			Labels:    common.ManagedByLabels(nil),
		},
		Data: map[string][]byte{
			"token": []byte(token),
		},
	}

	if err := controllerutil.SetControllerReference(instance, secret, r.Scheme); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	if err := r.Create(ctx, secret); err != nil {
		if errors.IsAlreadyExists(err) {
			// Another reconciliation created it, that's fine
			return nil
		}
		return fmt.Errorf("failed to create static API key secret: %w", err)
	}

	return nil
}

// computeStaticAPIKeyHash computes a SHA256 hash of the static API key secret's token.
// This hash is used as a pod annotation to trigger rollouts when the secret changes.
func (r *Reconciler) computeStaticAPIKeyHash(ctx context.Context, instance *pocketidinternalv1alpha1.PocketIDInstance) (string, error) {
	secretName := common.StaticAPIKeySecretName(instance.Name)
	secret := &corev1.Secret{}

	err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: instance.Namespace, Name: secretName}, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("get static API key secret: %w", err)
	}

	token, ok := secret.Data["token"]
	if !ok || len(token) == 0 {
		return "", nil
	}

	hash := sha256.Sum256(token)
	return hex.EncodeToString(hash[:]), nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
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
