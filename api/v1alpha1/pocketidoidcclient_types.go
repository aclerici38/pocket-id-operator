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

// OIDCClientSecretSpec defines how credentials should be stored in a Secret.
type OIDCClientSecretSpec struct {
	// Enabled controls whether to create a secret with OIDC client credentials.
	// If false, no secret will be created.
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// Name is the name of the secret to create.
	// Defaults to metadata.name + "-oidc-credentials"
	// +optional
	Name string `json:"name,omitempty"`

	// Keys allows customization of the secret keys for each credential field.
	// +optional
	Keys *OIDCClientSecretKeys `json:"keys,omitempty"`
}

// OIDCClientSecretKeys defines customizable keys for secret data fields.
type OIDCClientSecretKeys struct {
	// ClientID is the key name for the OIDC client ID.
	// +kubebuilder:default="client_id"
	// +optional
	ClientID string `json:"clientId,omitempty"`

	// ClientSecret is the key name for the OIDC client secret.
	// +kubebuilder:default="client_secret"
	// +optional
	ClientSecret string `json:"clientSecret,omitempty"`

	// IssuerURL is the key name for the OIDC issuer URL.
	// +kubebuilder:default="issuer_url"
	// +optional
	IssuerURL string `json:"issuerUrl,omitempty"`

	// CallbackURLs is the key name for the callback URLs.
	// +kubebuilder:default="callback_urls"
	// +optional
	CallbackURLs string `json:"callbackUrls,omitempty"`

	// LogoutCallbackURLs is the key name for the logout callback URLs.
	// +kubebuilder:default="logout_callback_urls"
	// +optional
	LogoutCallbackURLs string `json:"logoutCallbackUrls,omitempty"`

	// DiscoveryURL is the key name for the OIDC discovery URL.
	// +kubebuilder:default="discovery_url"
	// +optional
	DiscoveryURL string `json:"discoveryUrl,omitempty"`

	// AuthorizationURL is the key name for the OIDC authorization endpoint URL.
	// +kubebuilder:default="authorization_url"
	// +optional
	AuthorizationURL string `json:"authorizationUrl,omitempty"`

	// TokenURL is the key name for the OIDC token endpoint URL.
	// +kubebuilder:default="token_url"
	// +optional
	TokenURL string `json:"tokenUrl,omitempty"`

	// UserinfoURL is the key name for the OIDC userinfo endpoint URL.
	// +kubebuilder:default="userinfo_url"
	// +optional
	UserinfoURL string `json:"userinfoUrl,omitempty"`

	// JwksURL is the key name for the OIDC JWKS (JSON Web Key Set) endpoint URL.
	// +kubebuilder:default="jwks_url"
	// +optional
	JwksURL string `json:"jwksUrl,omitempty"`

	// EndSessionURL is the key name for the OIDC end session (logout) endpoint URL.
	// +kubebuilder:default="end_session_url"
	// +optional
	EndSessionURL string `json:"endSessionUrl,omitempty"`
}

// PocketIDOIDCClientSpec defines the desired state of PocketIDOIDCClient
type PocketIDOIDCClientSpec struct {
	// InstanceSelector selects the PocketIDInstance to reconcile against.
	// If omitted, the controller expects exactly one instance in the cluster.
	// +optional
	InstanceSelector *metav1.LabelSelector `json:"instanceSelector,omitempty"`

	// ClientID is the optional OIDC client ID to use instead of a generated one
	// +kubebuilder:validation:MinLength=2
	// +kubebuilder:validation:MaxLength=128
	// +optional
	ClientID string `json:"clientId,omitempty"`

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

	// Secret defines how OIDC client credentials should be stored in a Kubernetes Secret.
	// +optional
	Secret *OIDCClientSecretSpec `json:"secret,omitempty"`
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
// +kubebuilder:resource:shortName=oidcclient;

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
