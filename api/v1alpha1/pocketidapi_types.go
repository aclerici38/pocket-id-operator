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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// APIPermission defines a single scoped permission offered by an API.
type APIPermission struct {
	// Key is the permission identifier requested as a token scope, e.g. "read:orders".
	// It must be a valid RFC 6749 scope token: printable ASCII with no space, double
	// quote, or backslash. Reserved OIDC scope/claim names are rejected at the spec level.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:Pattern=`^[\x21\x23-\x5B\x5D-\x7E]+$`
	Key string `json:"key"`

	// Name is a human-friendly label for the permission.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`

	// Description optionally explains what the permission grants.
	// +kubebuilder:validation:MaxLength=500
	// +optional
	Description string `json:"description,omitempty"`
}

// PocketIDAPISpec defines the desired state of PocketIDAPI
// +kubebuilder:validation:XValidation:rule="self.resource == oldSelf.resource",message="resource is immutable"
// +kubebuilder:validation:XValidation:rule="!has(self.permissions) || self.permissions.all(p, !(p.key.lowerAscii() in ['openid','profile','email','email_verified','groups','offline_access']))",message="permission key is reserved by Pocket ID"
type PocketIDAPISpec struct {
	// InstanceSelector selects the PocketIDInstance to reconcile against.
	// If omitted, the controller expects exactly one instance in the cluster.
	// +optional
	InstanceSelector *metav1.LabelSelector `json:"instanceSelector,omitempty"`

	// Name of the API to create in Pocket ID.
	// If omitted, defaults to metadata.name of the API resource.
	// +kubebuilder:validation:MinLength=2
	// +kubebuilder:validation:MaxLength=255
	// +optional
	Name string `json:"name,omitempty"`

	// Resource is the audience identifier for tokens issued against this API
	// (typically a URI). It is the permanent identifier used to adopt an existing
	// API and is immutable once set.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	Resource string `json:"resource"`

	// Permissions are the scoped permissions offered by this API. The operator is
	// the sole owner of the API: the permission set in Pocket-ID is reconciled to
	// exactly this list, so permissions added out-of-band are removed.
	// +listType=map
	// +listMapKey=key
	// +kubebuilder:validation:MaxItems=100
	// +optional
	Permissions []APIPermission `json:"permissions,omitempty"`
}

// ObservedAPIPermission is a permission resolved from Pocket-ID, including its ID.
type ObservedAPIPermission struct {
	// ID is the Pocket-ID identifier for the permission.
	ID string `json:"id"`

	// Key is the permission identifier requested as a token scope.
	Key string `json:"key"`

	// Name is the human-friendly label from Pocket-ID.
	// +optional
	Name string `json:"name,omitempty"`
}

// PocketIDAPIStatus defines the observed state of PocketIDAPI.
type PocketIDAPIStatus struct {
	// APIID is the ID assigned by Pocket-ID.
	// +optional
	APIID string `json:"apiID,omitempty"`

	// Name is the resolved name from Pocket-ID.
	// +optional
	Name string `json:"name,omitempty"`

	// Resource is the resolved audience identifier from Pocket-ID.
	// +optional
	Resource string `json:"resource,omitempty"`

	// CreatedAt is the creation timestamp from Pocket-ID.
	// +optional
	CreatedAt string `json:"createdAt,omitempty"`

	// Permissions are the permissions resolved from Pocket-ID, including their IDs.
	// This is the lookup table PocketIDOIDCClients use to resolve permission keys.
	// +listType=map
	// +listMapKey=key
	// +optional
	Permissions []ObservedAPIPermission `json:"permissions,omitempty"`

	// Conditions represent the current state of the PocketIDAPI resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pidapi;

// PocketIDAPI is the Schema for the pocketidapis API
type PocketIDAPI struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of PocketIDAPI
	// +optional
	Spec PocketIDAPISpec `json:"spec,omitempty"`

	// status defines the observed state of PocketIDAPI
	// +optional
	Status PocketIDAPIStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PocketIDAPIList contains a list of PocketIDAPI
type PocketIDAPIList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PocketIDAPI `json:"items"`
}
