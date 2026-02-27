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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// StringValue represents a value that can be either a plain string or from a secret
type StringValue struct {
	// Plain text value
	// +optional
	Value string `json:"value,omitempty"`

	// Source for the value from a secret
	// +optional
	ValueFrom *corev1.SecretKeySelector `json:"valueFrom,omitempty"`
}

// APIKeySpec defines the desired state of an API key
type APIKeySpec struct {
	// Name of the API key (3-50 characters)
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=3
	// +kubebuilder:validation:MaxLength=50
	Name string `json:"name"`

	// ExpiresAt is the expiration time in RFC3339 format (e.g., "2030-01-01T00:00:00Z")
	// Defaults to 1 year in the future
	// +optional
	ExpiresAt string `json:"expiresAt,omitempty"`

	// Description of the API key
	// +kubebuilder:default="Created by pocket-id-operator"
	// +optional
	Description string `json:"description,omitempty"`

	// SecretRef references an existing Secret containing the API key token
	// If set, the operator will use this secret instead of creating a new one
	// +optional
	SecretRef *corev1.SecretKeySelector `json:"secretRef,omitempty"`
}

// APIKeyStatus reflects the observed state of an API key from Pocket-ID
type APIKeyStatus struct {
	// Name of the API key (matches spec)
	Name string `json:"name"`

	// ID assigned by Pocket-ID
	ID string `json:"id,omitempty"`

	// CreatedAt timestamp from Pocket-ID
	CreatedAt string `json:"createdAt,omitempty"`

	// ExpiresAt timestamp from Pocket-ID
	ExpiresAt string `json:"expiresAt,omitempty"`

	// LastUsedAt timestamp from Pocket-ID
	LastUsedAt string `json:"lastUsedAt,omitempty"`

	// SecretName where the API key token is stored
	SecretName string `json:"secretName,omitempty"`

	// SecretKey within the secret containing the token
	SecretKey string `json:"secretKey,omitempty"`
}

// PocketIDUserSpec defines the desired state of PocketIDUser
type PocketIDUserSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// The following markers will use OpenAPI v3 schema to validate the value
	// More info: https://book.kubebuilder.io/reference/markers/crd-validation.html

	// Username of the user. Defaults to the metadata.name
	// Can be a plain value or reference a secret
	// +optional
	Username StringValue `json:"username,omitempty"`

	// First name of the user
	// Can be a plain value or reference a secret
	// Defaults to metadata.name of the Resource
	// +optional
	FirstName StringValue `json:"firstName,omitempty"`

	// Last name of the user
	// Can be a plain value or reference a secret
	// +optional
	LastName StringValue `json:"lastName,omitempty"`

	// Email of the user
	// Can be a plain value or reference a secret
	// Required unless email is disabled in pocket-id
	// +optional
	Email StringValue `json:"email,omitempty"`

	// DisplayName of the user
	// Defaults to "spec.FirstName spec.LastName"
	// +optional
	DisplayName StringValue `json:"displayName,omitempty"`

	// InstanceSelector selects the PocketIDInstance to reconcile against.
	// If omitted, the controller expects exactly one instance in the cluster.
	// +optional
	InstanceSelector *metav1.LabelSelector `json:"instanceSelector,omitempty"`

	// UserInfoSecretRef references a single Secret containing sensitive user profile fields.
	// Values from the secret are evaluated last, so spec.username will override the username key in this secret
	// Keys: username, firstName, lastName, email, displayName
	// +optional
	UserInfoSecretRef *corev1.LocalObjectReference `json:"userInfoSecretRef,omitempty"`

	// Flag whether a user is an admin or not
	// +kubebuilder:default=false
	// +optional
	Admin bool `json:"admin"`

	// Disabled indicates whether the user account is disabled
	// +kubebuilder:default=false
	// +optional
	Disabled bool `json:"disabled,omitempty"`

	// Locale is the user's preferred locale (e.g., "en", "de", "fr")
	// +optional
	Locale string `json:"locale,omitempty"`

	// APIKeys is a list of API keys to create for this user
	// +optional
	APIKeys []APIKeySpec `json:"apiKeys,omitempty"`
}

// PocketIDUserStatus defines the observed state of PocketIDUser.
type PocketIDUserStatus struct {
	// UserID is the ID assigned by Pocket-ID
	// +optional
	UserID string `json:"userID,omitempty"`

	// UserInfoSecretName is the name of the Secret storing user profile fields.
	// The operator writes to "<name>-user-data".
	// +optional
	UserInfoSecretName string `json:"userInfoSecretName,omitempty"`

	// EmailVerified reflects whether the user's email is verified in Pocket-ID
	// +optional
	EmailVerified bool `json:"emailVerified,omitempty"`

	// IsAdmin reflects whether the user is an admin in Pocket-ID
	// +optional
	IsAdmin bool `json:"isAdmin,omitempty"`

	// Disabled reflects whether the user is disabled in Pocket-ID
	// +optional
	Disabled bool `json:"disabled,omitempty"`

	// Locale of the user from Pocket-ID
	// +optional
	Locale string `json:"locale,omitempty"`

	// OneTimeLoginToken is the one-time login token for a newly created user
	// +optional
	OneTimeLoginToken string `json:"oneTimeLoginToken,omitempty"`

	// OneTimeLoginURL is the login URL built from the one-time login token
	// +optional
	OneTimeLoginURL string `json:"oneTimeLoginURL,omitempty"`

	// OneTimeLoginExpiresAt is the RFC3339 timestamp when the login token expires
	// +optional
	OneTimeLoginExpiresAt string `json:"oneTimeLoginExpiresAt,omitempty"`

	// APIKeys reflects the observed state of each API key
	// +optional
	APIKeys []APIKeyStatus `json:"apiKeys,omitempty"`

	// Conditions represent the current state of the PocketIDUser resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=piduser;

// PocketIDUser is the Schema for the pocketidusers API
type PocketIDUser struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of PocketIDUser
	// +optional
	Spec PocketIDUserSpec `json:"spec,omitempty"`

	// status defines the observed state of PocketIDUser
	// +optional
	Status PocketIDUserStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PocketIDUserList contains a list of PocketIDUser
type PocketIDUserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PocketIDUser `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PocketIDUser{}, &PocketIDUserList{})
}
