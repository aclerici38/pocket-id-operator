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

// CustomClaim defines a custom claim key/value pair for a user group.
type CustomClaim struct {
	// Key is the claim key
	// +kubebuilder:validation:Required
	Key string `json:"key"`

	// Value is the claim value
	// +kubebuilder:validation:Required
	Value string `json:"value"`
}

// PocketIDUserGroupSpec defines the desired state of PocketIDUserGroup
type PocketIDUserGroupSpec struct {
	// InstanceSelector selects the PocketIDInstance to reconcile against.
	// If omitted, the controller expects exactly one instance in the cluster.
	// +optional
	InstanceSelector *metav1.LabelSelector `json:"instanceSelector,omitempty"`

	// Name of the user group. Defaults to the metadata.name
	// +kubebuilder:validation:MinLength=2
	// +kubebuilder:validation:MaxLength=255
	// +optional
	Name string `json:"name,omitempty"`

	// FriendlyName is the display name for the user group
	// +kubebuilder:validation:MinLength=2
	// +kubebuilder:validation:MaxLength=50
	// +optional
	FriendlyName string `json:"friendlyName,omitempty"`

	// CustomClaims are additional claims to attach to users in this group
	// +optional
	CustomClaims []CustomClaim `json:"customClaims,omitempty"`

	// UserRefs are PocketIDUser resources to add to this group
	// +optional
	UserRefs []NamespacedUserReference `json:"userRefs,omitempty"`
}

// PocketIDUserGroupStatus defines the observed state of PocketIDUserGroup.
type PocketIDUserGroupStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// GroupID is the ID assigned by Pocket-ID
	// +optional
	GroupID string `json:"groupId,omitempty"`

	// Name is the resolved group name from Pocket-ID
	// +optional
	Name string `json:"name,omitempty"`

	// FriendlyName is the resolved display name from Pocket-ID
	// +optional
	FriendlyName string `json:"friendlyName,omitempty"`

	// CreatedAt is the creation timestamp from Pocket-ID
	// +optional
	CreatedAt string `json:"createdAt,omitempty"`

	// LdapID is the LDAP identifier if the group is managed via LDAP
	// +optional
	LdapID string `json:"ldapId,omitempty"`

	// UserCount is the number of users in the group
	// +optional
	UserCount int `json:"userCount,omitempty"`

	// CustomClaims are the resolved custom claims on the group
	// +optional
	CustomClaims []CustomClaim `json:"customClaims,omitempty"`

	// Conditions represent the current state of the PocketIDUserGroup resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// PocketIDUserGroup is the Schema for the pocketidusergroups API
type PocketIDUserGroup struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of PocketIDUserGroup
	// +required
	Spec PocketIDUserGroupSpec `json:"spec"`

	// status defines the observed state of PocketIDUserGroup
	// +optional
	Status PocketIDUserGroupStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PocketIDUserGroupList contains a list of PocketIDUserGroup
type PocketIDUserGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PocketIDUserGroup `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PocketIDUserGroup{}, &PocketIDUserGroupList{})
}
