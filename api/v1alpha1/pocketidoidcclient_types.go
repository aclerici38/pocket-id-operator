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

// NamespacedUserGroupReference references a PocketIDUserGroup by name and namespace.
type NamespacedUserGroupReference struct {
	// Name is the name of the PocketIDUserGroup CR
	// +optional
	Name string `json:"name,omitempty"`

	// Namespace is the namespace of the PocketIDUserGroup CR
	// Defaults to the PocketIDOIDCClient namespace
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// OIDCClientFederatedIdentity defines a federated identity for OIDC client credentials.
type OIDCClientFederatedIdentity struct {
	// Issuer is the OIDC issuer for the identity
	// +optional
	Issuer string `json:"issuer,omitempty"`

	// Subject is the subject for the identity
	// +optional
	Subject string `json:"subject,omitempty"`

	// Audience is the audience for the identity
	// +optional
	Audience string `json:"audience,omitempty"`

	// JWKS is the URL or JSON for the identity's JWKS
	// +optional
	JWKS string `json:"jwks,omitempty"`
}

// PocketIDOIDCClientSpec defines the desired state of PocketIDOIDCClient
type PocketIDOIDCClientSpec struct {
	// InstanceSelector selects the PocketIDInstance to reconcile against.
	// If omitted, the controller expects exactly one instance in the cluster.
	// +optional
	InstanceSelector *metav1.LabelSelector `json:"instanceSelector,omitempty"`

	// ID is the optional client ID to use instead of a generated one
	// +kubebuilder:validation:MinLength=2
	// +kubebuilder:validation:MaxLength=128
	// +optional
	ID string `json:"id,omitempty"`

	// Callback URLs for the client
	// +optional
	CallbackURLs []string `json:"callbackUrls,omitempty"`

	// Logout callback URLs for the client
	// +optional
	LogoutCallbackURLs []string `json:"logoutCallbackUrls,omitempty"`

	// Launch URL for the client
	// +optional
	LaunchURL string `json:"launchUrl,omitempty"`

	// Logo URL for the client
	// +optional
	LogoURL string `json:"logoUrl,omitempty"`

	// Dark logo URL for the client
	// +optional
	DarkLogoURL string `json:"darkLogoUrl,omitempty"`

	// Indicates if the client is public (no client secret)
	// +kubebuilder:default=false
	// +optional
	IsPublic bool `json:"isPublic,omitempty"`

	// Enables PKCE for the client
	// +kubebuilder:default=false
	// +optional
	PKCEEnabled bool `json:"pkceEnabled,omitempty"`

	// Requires reauthentication on login
	// +kubebuilder:default=false
	// +optional
	RequiresReauthentication bool `json:"requiresReauthentication,omitempty"`

	// FederatedIdentities configures JWT assertion identities
	// +optional
	FederatedIdentities []OIDCClientFederatedIdentity `json:"federatedIdentities,omitempty"`

	// AllowedUserGroups restricts access to the listed PocketIDUserGroups
	// +optional
	AllowedUserGroups []NamespacedUserGroupReference `json:"allowedUserGroups,omitempty"`
}

// PocketIDOIDCClientStatus defines the observed state of PocketIDOIDCClient.
type PocketIDOIDCClientStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// ClientID is the ID assigned by Pocket-ID
	// +optional
	ClientID string `json:"clientId,omitempty"`

	// Name is the resolved name from Pocket-ID
	// +optional
	Name string `json:"name,omitempty"`

	// CreatedAt is the creation timestamp from Pocket-ID
	// +optional
	CreatedAt string `json:"createdAt,omitempty"`

	// AllowedUserGroupIDs are the resolved group IDs assigned to the client
	// +optional
	AllowedUserGroupIDs []string `json:"allowedUserGroupIds,omitempty"`

	// Conditions represent the current state of the PocketIDOIDCClient resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// PocketIDOIDCClient is the Schema for the pocketidoidcclients API
type PocketIDOIDCClient struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of PocketIDOIDCClient
	// +required
	Spec PocketIDOIDCClientSpec `json:"spec"`

	// status defines the observed state of PocketIDOIDCClient
	// +optional
	Status PocketIDOIDCClientStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PocketIDOIDCClientList contains a list of PocketIDOIDCClient
type PocketIDOIDCClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PocketIDOIDCClient `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PocketIDOIDCClient{}, &PocketIDOIDCClientList{})
}
