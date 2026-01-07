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
	// +optional
	Description string `json:"description,omitempty"`
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
	// +optional
	// +kubebuilder:validation:MinLength=2
	// +kubebuilder:validation:MaxLength=50
	Username string `json:"username,omitempty"`

	// First name of the user
	// +kubebuilder:validation:Required
    // +kubebuilder:validation:MinLength=1
    // +kubebuilder:validation:MaxLength=50
    FirstName string `json:"firstName"`

    // Last name of the user
    // +optional
    // +kubebuilder:validation:MaxLength=50
    LastName string `json:"lastName,omitempty"`

    // Email of the user
    // +optional
    Email string `json:"email,omitempty"`

	// Flag whether a user is an admin or not
	// +kubebuilder:default=false
	Admin bool `json:"admin"`

	// APIKeys is a list of API keys to create for this user
	// +optional
	APIKeys []APIKeySpec `json:"apiKeys,omitempty"`
}

// PocketIDUserStatus defines the observed state of PocketIDUser.
type PocketIDUserStatus struct {
	// UserID is the ID assigned by Pocket-ID
	// +optional
	UserID string `json:"userID,omitempty"`

	// Username as stored in Pocket-ID
	// +optional
	Username string `json:"username,omitempty"`

	// DisplayName from Pocket-ID
	// +optional
	DisplayName string `json:"displayName,omitempty"`

	// Email as stored in Pocket-ID
	// +optional
	Email string `json:"email,omitempty"`

	// IsAdmin reflects whether the user is an admin in Pocket-ID
	// +optional
	IsAdmin bool `json:"isAdmin,omitempty"`

	// Disabled reflects whether the user is disabled in Pocket-ID
	// +optional
	Disabled bool `json:"disabled,omitempty"`

	// Locale of the user from Pocket-ID
	// +optional
	Locale string `json:"locale,omitempty"`

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

// PocketIDUser is the Schema for the pocketidusers API
type PocketIDUser struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of PocketIDUser
	// +required
	Spec PocketIDUserSpec `json:"spec"`

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
