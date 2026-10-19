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

// CustomClaim defines a custom claim key/value pair for a user or user group.
type CustomClaim struct {
	// Key is the claim key.
	// +kubebuilder:validation:Required
	Key string `json:"key"`

	// Value is the claim value.
	// +kubebuilder:validation:Required
	Value string `json:"value"`
}

// NamespacedUserReference references a PocketIDUser by name and namespace.
type NamespacedUserReference struct {
	// Name is the name of the PocketIDUser CR.
	// +optional
	Name string `json:"name,omitempty"`

	// Namespace is the namespace of the PocketIDUser CR. Defaults to the referencing resource's namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// UserGroupUsers defines the members the operator manages in a user group.
type UserGroupUsers struct {
	// UserRefs are PocketIDUser custom resources to add to this group. Each must be Ready.
	// +optional
	UserRefs []NamespacedUserReference `json:"userRefs,omitempty"`

	// Usernames are existing Pocket-ID users to add to this group, for users not managed by a PocketIDUser. Each must exist in Pocket-ID.
	// +optional
	Usernames []string `json:"usernames,omitempty"`

	// UserIDs are Pocket-ID user IDs to add to this group, for users not managed by a PocketIDUser.
	// +optional
	UserIDs []string `json:"userIDs,omitempty"`
}

// PocketIDUserGroupSpec defines the desired state of PocketIDUserGroup.
type PocketIDUserGroupSpec struct {
	// InstanceSelector selects the PocketIDInstance to reconcile against.
	// If omitted, the controller expects exactly one instance in the cluster.
	// +optional
	InstanceSelector *metav1.LabelSelector `json:"instanceSelector,omitempty"`

	// Name of the user group in Pocket-ID. Defaults to metadata.name.
	// +kubebuilder:validation:MinLength=2
	// +kubebuilder:validation:MaxLength=255
	// +optional
	Name string `json:"name,omitempty"`

	// FriendlyName is the display name of the user group. Defaults to the name.
	// +kubebuilder:validation:MinLength=2
	// +kubebuilder:validation:MaxLength=50
	// +optional
	FriendlyName string `json:"friendlyName,omitempty"`

	// CustomClaims are additional claims to attach to every user in this group. A user's own claim with the same key takes precedence.
	// +optional
	CustomClaims []CustomClaim `json:"customClaims,omitempty"`

	// Users defines the members the operator manages in this group. Members added outside the operator are left in place.
	// +optional
	Users *UserGroupUsers `json:"users,omitempty"`

	// AllowedOIDCClients lists PocketIDOIDCClient CRs that this group grants access to. Each must be Ready. The final set of allowed clients is the union of this field and any PocketIDOIDCClients that reference this group in their allowedUserGroups.
	// +optional
	AllowedOIDCClients []NamespacedOIDCClientReference `json:"allowedOIDCClients,omitempty"`
}

// PocketIDUserGroupStatus defines the observed state of PocketIDUserGroup.
type PocketIDUserGroupStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "mise run generate" to regenerate code after modifying this file

	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// GroupID is the ID assigned by Pocket-ID.
	// +optional
	GroupID string `json:"groupID,omitempty"`

	// Name is the group name from Pocket-ID.
	// +optional
	Name string `json:"name,omitempty"`

	// FriendlyName is the display name from Pocket-ID.
	// +optional
	FriendlyName string `json:"friendlyName,omitempty"`

	// CreatedAt is the creation timestamp from Pocket-ID.
	// +optional
	CreatedAt string `json:"createdAt,omitempty"`

	// LdapID is the LDAP identifier if the group is synced from LDAP.
	// +optional
	LdapID string `json:"ldapID,omitempty"`

	// TotalUserCount is the number of members in the group, including those not managed by the operator.
	// +optional
	TotalUserCount int `json:"totalUserCount,omitempty"`

	// ManagedUserIDs are the Pocket-ID user IDs the operator manages in this group. Members not in this list were added outside the operator and are never removed.
	// +optional
	ManagedUserIDs []string `json:"managedUserIDs,omitempty"`

	// CustomClaims are the group's custom claims in Pocket-ID.
	// +optional
	CustomClaims []CustomClaim `json:"customClaims,omitempty"`

	// AllowedOIDCClientIDs are the IDs of the OIDC clients this group is allowed to access in Pocket-ID.
	// +optional
	AllowedOIDCClientIDs []string `json:"allowedOIDCClientIDs,omitempty"`

	// Conditions represent the current state of the PocketIDUserGroup resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=usergroup;

// PocketIDUserGroup is the Schema for the pocketidusergroups API.
type PocketIDUserGroup struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of PocketIDUserGroup
	// +optional
	Spec PocketIDUserGroupSpec `json:"spec,omitempty"`

	// status defines the observed state of PocketIDUserGroup
	// +optional
	Status PocketIDUserGroupStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PocketIDUserGroupList contains a list of PocketIDUserGroup.
type PocketIDUserGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PocketIDUserGroup `json:"items"`
}
