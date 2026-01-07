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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// HTTPRoute config
type HttpRouteConfig struct {
	// Creates the route
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// ParentRefs to attach the route to a Gateway
	// +optional
	ParentRefs []gwapiv1.ParentReference `json:"parentRefs,omitempty"`
}

// Environment variable value that can be either a plain value or from a Kubernetes resource
type EnvValue struct {
	// Plain text value 16 byte minimum
	// +optional
	// +kubebuilder:validation:MinLength=16
	Value string `json:"value,omitempty"`

	// Source for the environment variable's value
	// +optional
	ValueFrom *corev1.EnvVarSource `json:"valueFrom,omitempty"`
}

// Persistence config. Mounts a volume at /app/Data
type PersistenceConfig struct {
	// Enables mounting a persistent volume
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Name of an existing, externally-managed PVC to mount
	// +optional
	ExistingClaim string `json:"existingClaim,omitempty"`

	// Name of storageClass to provision a volume from
	// +optional
	StorageClass string `json:"storageClass,omitempty"`

	// Size of the claim to dynamically provision
	// +kubebuilder:default="1Gi"
	// +optional
	Size resource.Quantity `json:"size,omitempty"`

	// AccessModes for the PVC
	// +kubebuilder:default={"ReadWriteOnce"}
	// +optional
	AccessModes []corev1.PersistentVolumeAccessMode `json:"accessModes,omitempty"`
}

// AuthConfig specifies how the operator authenticates with the instance
type AuthConfig struct {
	// UserRef is the name of the PocketIDUser CR to use for authentication
	// Defaults to "pocket-id-operator" which will be created if it does not exist
	// +kubebuilder:default="pocket-id-operator"
	UserRef string `json:"userRef"`

	// APIKeyName is the name of the API key to use from the referenced user
	// If the key exists in PocketIDUser.status.apiKeys, that key will be used
	// Otherwise the operator will attempt to bootstrap the instance and create a new key
	// +kubebuilder:default="pocket-id-operator"
	APIKeyName string `json:"apiKeyName"`
}

// PocketIDInstanceSpec defines the desired state of PocketIDInstance
// +kubebuilder:validation:XValidation:rule="self.deploymentType == oldSelf.deploymentType",message="deploymentType is immutable"
type PocketIDInstanceSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// The following markers will use OpenAPI v3 schema to validate the value
	// More info: https://book.kubebuilder.io/reference/markers/crd-validation.html

	// Kind of workload to create, Deployment or StatefulSet
	// Defaults to Deployment (immutable after creation)
	// +kubebuilder:validation:Enum=Deployment;StatefulSet
	// +kubebuilder:default=Deployment
	DeploymentType string `json:"deploymentType,omitempty"`

	// Container image to run. It is highly recommended to specify a tag
	// Defaults to ghcr.io/pocket-id/pocket-id:latest
	// +kubebuilder:default="ghcr.io/pocket-id/pocket-id:latest"
	Image string `json:"image,omitempty"`

	// Encryption Key
	// Required since Pocket-ID v2
	// See the official documentation for ENCRYPTION_KEY
	// +kubebuilder:validation:Required
	EncryptionKey EnvValue `json:"encryptionKey"`

	// URL to access database at
	// See the official documentation for DB_CONNECTION_STRING
	// For sqlite only add the filepath e.g. "data/pocket-id.db"
	// Uses application default if empty
	// +optional
	DatabaseUrl *EnvValue `json:"databaseUrl,omitempty"`

	// External URL Pocket-id can be reached at
	// See the official documentation for APP_URL
	// +optional
	AppURL string `json:"appUrl,omitempty"`

	// Additional environment variables to set
	// Uses k8s env var syntax (includes secretKeyRef, configMapKeyRef, etc.)
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`

	// Configures a httpRoute to expose pocket-id
	// +optional
	Route HttpRouteConfig `json:"route,omitempty"`

	// Configures persistence for Pocket-ID
	// Pocket-ID can be run statelessly if using Postgres as a file and db backend
	// If not enabled mounts an emptydir instead
	Persistence PersistenceConfig `json:"persistence,omitempty"`

	// Pod security context
	// +optional
	PodSecurityContext *corev1.PodSecurityContext `json:"podSecurityContext,omitempty"`

	// Container security context
	// +optional
	ContainerSecurityContext *corev1.SecurityContext `json:"containerSecurityContext,omitempty"`

	// HostUsers controls whether the container's user namespace is separate from the host
	// Defaults to true
	// +kubebuilder:default=true
	HostUsers *bool `json:"hostUsers,omitempty"`

	// Additional labels to add to the workload and pod
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Additional annotations to add to the workload and pod
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Readiness probe configuration
	// +optional
	ReadinessProbe *corev1.Probe `json:"readinessProbe,omitempty"`

	// Liveness probe configuration
	// +optional
	LivenessProbe *corev1.Probe `json:"livenessProbe,omitempty"`

	// Resource requests and limits for the container
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// How the operator authenticates with the instance
	// +optional
	Auth *AuthConfig `json:"auth,omitempty"`
}

// PocketIDInstanceStatus defines the observed state of PocketIDInstance.
type PocketIDInstanceStatus struct {
	// Bootstrapped indicates whether the instance has been bootstrapped
	// (initial admin user and API key created)
	// +optional
	Bootstrapped bool `json:"bootstrapped,omitempty"`

	// BootstrappedAt is the timestamp when bootstrap completed
	// +optional
	BootstrappedAt string `json:"bootstrappedAt,omitempty"`

	// AuthUserRef is the name of the PocketIDUser CR being used for authentication
	// +optional
	AuthUserRef string `json:"authUserRef,omitempty"`

	// AuthAPIKeyName is the name of the API key being used for authentication
	// +optional
	AuthAPIKeyName string `json:"authApiKeyName,omitempty"`

	// Conditions represent the current state of the Instance resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// PocketIDInstance is the Schema for the pocketidinstances API
type PocketIDInstance struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of PocketIDInstance
	// +required
	Spec PocketIDInstanceSpec `json:"spec"`

	// status defines the observed state of PocketIDInstance
	// +optional
	Status PocketIDInstanceStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PocketIDInstanceList contains a list of PocketIDInstance
type PocketIDInstanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PocketIDInstance `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PocketIDInstance{}, &PocketIDInstanceList{})
}
