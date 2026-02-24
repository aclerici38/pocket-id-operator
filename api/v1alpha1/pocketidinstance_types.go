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
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

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

// SensitiveValue holds a value that can be provided as plain text or from a Kubernetes secret/configmap.
// Unlike EnvValue, this has no minimum length constraint.
type SensitiveValue struct {
	// Plain text value
	// +optional
	Value string `json:"value,omitempty"`

	// Source for the value (e.g. secretKeyRef, configMapKeyRef)
	// +optional
	ValueFrom *corev1.EnvVarSource `json:"valueFrom,omitempty"`
}

// S3Config configures S3 as the file backend.
// When present, FILE_BACKEND is automatically set to "s3".
type S3Config struct {
	// S3 bucket name
	// +kubebuilder:validation:Required
	Bucket string `json:"bucket"`

	// S3 region
	// +kubebuilder:validation:Required
	Region string `json:"region"`

	// S3 endpoint URL (for MinIO, Ceph, or other S3-compatible stores)
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// S3 access key ID
	// +kubebuilder:validation:Required
	AccessKeyID SensitiveValue `json:"accessKeyId"`

	// S3 secret access key
	// +kubebuilder:validation:Required
	SecretAccessKey SensitiveValue `json:"secretAccessKey"`

	// Force path-style URLs instead of virtual-hosted-style
	// +kubebuilder:default=false
	// +optional
	ForcePathStyle bool `json:"forcePathStyle,omitempty"`
}

// SMTPConfig configures SMTP email transport.
// When present, SMTP is automatically enabled.
type SMTPConfig struct {
	// SMTP server hostname
	// +kubebuilder:validation:Required
	Host string `json:"host"`

	// SMTP server port
	// +kubebuilder:validation:Required
	Port int32 `json:"port"`

	// Sender email address
	// +kubebuilder:validation:Required
	From string `json:"from"`

	// SMTP authentication username
	// +optional
	User string `json:"user,omitempty"`

	// SMTP authentication password
	// +optional
	Password *SensitiveValue `json:"password,omitempty"`

	// TLS mode for the SMTP connection
	// +kubebuilder:validation:Enum=none;starttls;tls
	// +kubebuilder:default="none"
	// +optional
	TLS string `json:"tls,omitempty"`

	// Skip certificate verification (for self-signed certs)
	// +kubebuilder:default=false
	// +optional
	SkipCertVerify bool `json:"skipCertVerify,omitempty"`
}

// EmailNotificationsConfig controls which email notifications Pocket-ID sends.
// Only relevant when SMTP is configured.
type EmailNotificationsConfig struct {
	// Notify users of logins from new devices
	// +kubebuilder:default=false
	// +optional
	LoginNotification bool `json:"loginNotification,omitempty"`

	// Allow admins to send one-time login access codes
	// +kubebuilder:default=false
	// +optional
	OneTimeAccessAsAdmin bool `json:"oneTimeAccessAsAdmin,omitempty"`

	// Notify users of expiring API keys
	// +kubebuilder:default=false
	// +optional
	APIKeyExpiration bool `json:"apiKeyExpiration,omitempty"`

	// Allow email-based login bypass for unauthenticated users (reduced security)
	// +kubebuilder:default=false
	// +optional
	OneTimeAccessAsUnauthenticated bool `json:"oneTimeAccessAsUnauthenticated,omitempty"`

	// Send verification emails on signup or email change
	// +kubebuilder:default=false
	// +optional
	Verification bool `json:"verification,omitempty"`
}

// LDAPAttributeMappingConfig maps LDAP attributes to Pocket-ID user/group fields.
type LDAPAttributeMappingConfig struct {
	// LDAP attribute for immutable user identifier
	// +optional
	UserUniqueIdentifier string `json:"userUniqueIdentifier,omitempty"`

	// LDAP attribute for username
	// +optional
	UserUsername string `json:"userUsername,omitempty"`

	// LDAP attribute for email
	// +optional
	UserEmail string `json:"userEmail,omitempty"`

	// LDAP attribute for first name
	// +optional
	UserFirstName string `json:"userFirstName,omitempty"`

	// LDAP attribute for last name
	// +optional
	UserLastName string `json:"userLastName,omitempty"`

	// LDAP attribute for profile picture
	// +optional
	UserProfilePicture string `json:"userProfilePicture,omitempty"`

	// LDAP attribute for group membership
	// +optional
	GroupMember string `json:"groupMember,omitempty"`

	// LDAP attribute for immutable group identifier
	// +optional
	GroupUniqueIdentifier string `json:"groupUniqueIdentifier,omitempty"`

	// LDAP attribute for group name
	// +optional
	GroupName string `json:"groupName,omitempty"`
}

// LDAPConfig configures LDAP authentication.
// When present, LDAP is automatically enabled.
type LDAPConfig struct {
	// LDAP server connection URL (e.g. ldaps://ldap.example.com)
	// +kubebuilder:validation:Required
	URL string `json:"url"`

	// LDAP bind distinguished name
	// +kubebuilder:validation:Required
	BindDN string `json:"bindDN"`

	// LDAP bind password
	// +kubebuilder:validation:Required
	BindPassword SensitiveValue `json:"bindPassword"`

	// LDAP search base DN
	// +kubebuilder:validation:Required
	Base string `json:"base"`

	// Skip LDAP certificate verification
	// +kubebuilder:default=false
	// +optional
	SkipCertVerify bool `json:"skipCertVerify,omitempty"`

	// Disable removed LDAP users instead of deleting them
	// +kubebuilder:default=false
	// +optional
	SoftDeleteUsers bool `json:"softDeleteUsers,omitempty"`

	// LDAP group name that grants admin privileges
	// +optional
	AdminGroupName string `json:"adminGroupName,omitempty"`

	// LDAP user search filter
	// +optional
	UserSearchFilter string `json:"userSearchFilter,omitempty"`

	// LDAP group search filter
	// +optional
	UserGroupSearchFilter string `json:"userGroupSearchFilter,omitempty"`

	// LDAP attribute mappings
	// +optional
	AttributeMapping *LDAPAttributeMappingConfig `json:"attributeMapping,omitempty"`
}

// LoggingConfig configures logging behavior.
type LoggingConfig struct {
	// Log level
	// +kubebuilder:validation:Enum=debug;info;warn;error
	// +optional
	Level string `json:"level,omitempty"`

	// Output logs as JSON
	// +kubebuilder:default=false
	// +optional
	JSON bool `json:"json,omitempty"`
}

// TracingConfig enables OpenTelemetry tracing.
// When present, tracing is automatically enabled.
// Configure exporter-specific OTEL_* variables via the env escape hatch.
type TracingConfig struct {
}

// UIConfig configures Pocket-ID UI settings.
// The operator always sets UI_CONFIG_DISABLED=true to ensure env var overrides take effect.
type UIConfig struct {
	// Application display name
	// +optional
	AppName string `json:"appName,omitempty"`

	// User session timeout in minutes
	// +optional
	SessionDuration *int32 `json:"sessionDuration,omitempty"`

	// Post-login redirect page
	// +optional
	HomePageURL string `json:"homePageUrl,omitempty"`

	// Turn off UI animations
	// +kubebuilder:default=false
	// +optional
	DisableAnimations bool `json:"disableAnimations,omitempty"`

	// Custom CSS color value for UI accent theme
	// +optional
	AccentColor string `json:"accentColor,omitempty"`
}

// UserManagementConfig configures user registration and account settings.
type UserManagementConfig struct {
	// Auto-verify emails on signup or change
	// +kubebuilder:default=false
	// +optional
	EmailsVerified bool `json:"emailsVerified,omitempty"`

	// Allow users to edit their own account details
	// +optional
	AllowOwnAccountEdit *bool `json:"allowOwnAccountEdit,omitempty"`

	// User signup mode
	// +kubebuilder:validation:Enum=disabled;withToken;open
	// +optional
	AllowUserSignups string `json:"allowUserSignups,omitempty"`

	// Default custom claims to assign to new users (JSON array)
	// +optional
	SignupDefaultCustomClaims string `json:"signupDefaultCustomClaims,omitempty"`

	// Default user group IDs to assign to new users
	// +optional
	SignupDefaultUserGroupIDs []string `json:"signupDefaultUserGroupIds,omitempty"`
}

// GeoIPConfig configures GeoIP/MaxMind integration for audit log geolocation.
type GeoIPConfig struct {
	// MaxMind license key for downloading GeoLite2 database
	// +optional
	MaxmindLicenseKey *SensitiveValue `json:"maxmindLicenseKey,omitempty"`

	// Custom path to the GeoLite2 database file
	// +optional
	DBPath string `json:"dbPath,omitempty"`

	// Custom URL to download the GeoLite2 database from
	// +optional
	DBURL string `json:"dbUrl,omitempty"`
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

// HTTPRouteConfig configures an HTTPRoute (Gateway API) for the instance
type HTTPRouteConfig struct {
	// Enables creation of an HTTPRoute
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Name override for the HTTPRoute (defaults to instance name)
	// +optional
	Name string `json:"name,omitempty"`

	// Additional labels for the HTTPRoute
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Additional annotations for the HTTPRoute
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Gateway parent references
	// +kubebuilder:validation:MinItems=1
	ParentRefs []gatewayv1.ParentReference `json:"parentRefs"`

	// Hostnames for the route
	// Will be automatically set to the hostname from spec.appUrl if not specified
	// +optional
	Hostnames []gatewayv1.Hostname `json:"hostnames,omitempty"`
}

// MetricsConfig configures the Prometheus metrics endpoint for Pocket-ID
type MetricsConfig struct {
	// Enables the Prometheus metrics endpoint
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Port for the Prometheus metrics endpoint
	// +kubebuilder:default=9464
	// +optional
	Port int32 `json:"port,omitempty"`
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

	// Container image to run. Defaults to the latest distroless version at time of operator release
	// +kubebuilder:default="ghcr.io/pocket-id/pocket-id:v2.3.0-distroless@sha256:85a7485108325e34679b0fbca0baeb8418401f6d6cf59944d50f3ec013aafd09"
	Image string `json:"image,omitempty"`

	// Encryption Key
	// Required since Pocket-ID v2
	// See the official documentation for ENCRYPTION_KEY environment variable
	// +kubebuilder:validation:Required
	EncryptionKey EnvValue `json:"encryptionKey"`

	// URL to access database at
	// See the official documentation for DB_CONNECTION_STRING
	// For sqlite only add the filepath e.g. "/app/data/pocket-id.db"
	// Uses application default (/app/data/pocket-id.db) if empty
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

	// Configures persistence for Pocket-ID
	// Note: Pocket-ID can be run statelessly if using Postgres as a file and db backend
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

	// Prometheus metrics configuration
	// When enabled the operator injects the required OTEL environment variables
	// and exposes a metrics port on the Service
	// +optional
	Metrics *MetricsConfig `json:"metrics,omitempty"`

	// HTTPRoute configuration
	// Creates an HTTPRoute when enabled. Requires Gateway API CRDs to be installed.
	// +optional
	Route *HTTPRouteConfig `json:"route,omitempty"`

	// S3 file backend configuration
	// When present, FILE_BACKEND is automatically set to "s3"
	// +optional
	S3 *S3Config `json:"s3,omitempty"`

	// SMTP email transport configuration
	// When present, SMTP is automatically enabled
	// +optional
	SMTP *SMTPConfig `json:"smtp,omitempty"`

	// Email notification settings
	// Only relevant when SMTP is configured
	// +optional
	EmailNotifications *EmailNotificationsConfig `json:"emailNotifications,omitempty"`

	// LDAP authentication configuration
	// When present, LDAP is automatically enabled
	// +optional
	LDAP *LDAPConfig `json:"ldap,omitempty"`

	// Logging configuration
	// +optional
	Logging *LoggingConfig `json:"logging,omitempty"`

	// OpenTelemetry tracing configuration
	// When present, tracing is automatically enabled
	// Configure exporter-specific OTEL_* variables via the env escape hatch
	// +optional
	Tracing *TracingConfig `json:"tracing,omitempty"`

	// UI configuration
	// The operator always sets UI_CONFIG_DISABLED=true to ensure env var overrides take effect
	// +optional
	UI *UIConfig `json:"ui,omitempty"`

	// User registration and account management settings
	// +optional
	UserManagement *UserManagementConfig `json:"userManagement,omitempty"`

	// GeoIP/MaxMind integration for audit log geolocation
	// +optional
	GeoIP *GeoIPConfig `json:"geoip,omitempty"`

	// Audit log retention in days
	// +optional
	AuditLogRetentionDays *int32 `json:"auditLogRetentionDays,omitempty"`

	// Disable anonymous 24-hour usage analytics heartbeat
	// +kubebuilder:default=false
	// +optional
	AnalyticsDisabled bool `json:"analyticsDisabled,omitempty"`

	// Disable GitHub version checks
	// +kubebuilder:default=false
	// +optional
	VersionCheckDisabled bool `json:"versionCheckDisabled,omitempty"`

	// Internal base URL for OIDC .well-known endpoints (for split-horizon DNS)
	// +optional
	InternalAppURL string `json:"internalAppUrl,omitempty"`
}

// PocketIDInstanceStatus defines the observed state of PocketIDInstance.
type PocketIDInstanceStatus struct {
	// Version is the current deployed version of the PocketID instance,
	// retrieved from the /api/version/current endpoint.
	// +optional
	Version string `json:"version,omitempty"`

	// StaticAPIKeySecretName is the name of the secret containing the STATIC_API_KEY
	// +optional
	StaticAPIKeySecretName string `json:"staticApiKeySecretName,omitempty"`

	// Conditions represent the current state of the Instance resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pidinstance;

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
