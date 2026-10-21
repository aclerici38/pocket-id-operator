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
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// SensitiveValue holds a value that can be provided as plain text or from a Kubernetes secret/configmap.
type SensitiveValue struct {
	// Plain text value.
	// +optional
	Value string `json:"value,omitempty"`

	// Source for the value (e.g. secretKeyRef, configMapKeyRef).
	// +optional
	ValueFrom *corev1.EnvVarSource `json:"valueFrom,omitempty"`
}

// ExternalInstanceConfig points the operator at an existing, externally-managed Pocket-ID instead of deploying one. When set, the operator creates no workload and manages OIDC clients, users, and groups on that instance via its API.
type ExternalInstanceConfig struct {
	// URL is the base URL of the existing Pocket-ID instance (e.g. https://auth.example.com).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^https?://`
	URL string `json:"url"`

	// APIKeySecretRef references a Secret key holding a Pocket-ID API key with permission to manage clients, users, and groups on the instance.
	// +kubebuilder:validation:Required
	APIKeySecretRef corev1.SecretKeySelector `json:"apiKeySecretRef"`
}

// EffectiveAppURL returns the externally-reachable URL of the Pocket-ID instance. This can be the external URL for adopted instances, otherwise the deployed instance's appUrl.
func (i *PocketIDInstance) EffectiveAppURL() string {
	if i.Spec.External != nil && i.Spec.External.URL != "" {
		return strings.TrimRight(i.Spec.External.URL, "/")
	}
	return strings.TrimRight(i.Spec.AppURL, "/")
}

// S3Config configures S3 as the file backend. When present, the operator sets FILE_BACKEND=s3.
type S3Config struct {
	// S3 bucket name.
	// Sets S3_BUCKET. See https://pocket-id.org/docs/configuration/environment-variables.
	// +kubebuilder:validation:Required
	Bucket string `json:"bucket"`

	// S3 region.
	// Sets S3_REGION. See https://pocket-id.org/docs/configuration/environment-variables.
	// +kubebuilder:validation:Required
	Region string `json:"region"`

	// S3 endpoint URL.
	// Sets S3_ENDPOINT. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// S3 access key ID.
	// Sets S3_ACCESS_KEY_ID. See https://pocket-id.org/docs/configuration/environment-variables.
	// +kubebuilder:validation:Required
	AccessKeyID SensitiveValue `json:"accessKeyId"`

	// S3 secret access key.
	// Sets S3_SECRET_ACCESS_KEY. See https://pocket-id.org/docs/configuration/environment-variables.
	// +kubebuilder:validation:Required
	SecretAccessKey SensitiveValue `json:"secretAccessKey"`

	// Use path-style S3 URLs.
	// Sets S3_FORCE_PATH_STYLE. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	ForcePathStyle *bool `json:"forcePathStyle,omitempty"`

	// Disable default S3 integrity checks.
	// Sets S3_DISABLE_DEFAULT_INTEGRITY_CHECKS. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	DisableDefaultIntegrityChecks *bool `json:"disableDefaultIntegrityChecks,omitempty"`
}

// SMTPConfig configures SMTP email transport. When present, the operator sets SMTP_ENABLED=true and UI_CONFIG_DISABLED=true.
type SMTPConfig struct {
	// SMTP server hostname.
	// Sets SMTP_HOST. See https://pocket-id.org/docs/configuration/environment-variables.
	// +kubebuilder:validation:Required
	Host string `json:"host"`

	// SMTP server port.
	// Sets SMTP_PORT. See https://pocket-id.org/docs/configuration/environment-variables.
	// +kubebuilder:validation:Required
	Port int32 `json:"port"`

	// Sender email address.
	// Sets SMTP_FROM. See https://pocket-id.org/docs/configuration/environment-variables.
	// +kubebuilder:validation:Required
	From string `json:"from"`

	// SMTP username.
	// Sets SMTP_USER. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	User string `json:"user,omitempty"`

	// SMTP password.
	// Sets SMTP_PASSWORD. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	Password *SensitiveValue `json:"password,omitempty"`

	// SMTP TLS mode.
	// Sets SMTP_TLS. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	TLS string `json:"tls,omitempty"`

	// Skip SMTP certificate verification.
	// Sets SMTP_SKIP_CERT_VERIFY. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	SkipCertVerify *bool `json:"skipCertVerify,omitempty"`
}

// EmailNotificationsConfig controls which email notifications Pocket-ID sends. Requires smtp. The operator sets UI_CONFIG_DISABLED=true when this section is configured.
type EmailNotificationsConfig struct {
	// Deprecated: use loginNotificationMode instead.
	// +optional
	LoginNotification *bool `json:"loginNotification,omitempty"`

	// When users receive a sign-in notification email. Requires Pocket-ID v2.19.0 or newer; takes precedence over loginNotification.
	// Sets EMAIL_LOGIN_NOTIFICATION_MODE. See https://pocket-id.org/docs/configuration/environment-variables.
	// +kubebuilder:validation:Enum=disabled;always;ipAndUserAgent;browserRecognition
	// +optional
	LoginNotificationMode string `json:"loginNotificationMode,omitempty"`

	// Admin-sent login codes.
	// Sets EMAIL_ONE_TIME_ACCESS_AS_ADMIN_ENABLED. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	OneTimeAccessAsAdmin *bool `json:"oneTimeAccessAsAdmin,omitempty"`

	// API key expiration notifications.
	// Sets EMAIL_API_KEY_EXPIRATION_ENABLED. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	APIKeyExpiration *bool `json:"apiKeyExpiration,omitempty"`

	// Email login codes for unauthenticated users.
	// Sets EMAIL_ONE_TIME_ACCESS_AS_UNAUTHENTICATED_ENABLED. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	OneTimeAccessAsUnauthenticated *bool `json:"oneTimeAccessAsUnauthenticated,omitempty"`

	// Email verification.
	// Sets EMAIL_VERIFICATION_ENABLED. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	Verification *bool `json:"verification,omitempty"`
}

// LDAPAttributeMappingConfig maps LDAP attributes to Pocket-ID user/group fields.
type LDAPAttributeMappingConfig struct {
	// User unique identifier attribute.
	// Sets LDAP_ATTRIBUTE_USER_UNIQUE_IDENTIFIER. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	UserUniqueIdentifier string `json:"userUniqueIdentifier,omitempty"`

	// Username attribute.
	// Sets LDAP_ATTRIBUTE_USER_USERNAME. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	UserUsername string `json:"userUsername,omitempty"`

	// Email attribute.
	// Sets LDAP_ATTRIBUTE_USER_EMAIL. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	UserEmail string `json:"userEmail,omitempty"`

	// First name attribute.
	// Sets LDAP_ATTRIBUTE_USER_FIRST_NAME. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	UserFirstName string `json:"userFirstName,omitempty"`

	// Last name attribute.
	// Sets LDAP_ATTRIBUTE_USER_LAST_NAME. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	UserLastName string `json:"userLastName,omitempty"`

	// Display name attribute.
	// Sets LDAP_ATTRIBUTE_USER_DISPLAY_NAME. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	UserDisplayName string `json:"userDisplayName,omitempty"`

	// Profile picture attribute.
	// Sets LDAP_ATTRIBUTE_USER_PROFILE_PICTURE. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	UserProfilePicture string `json:"userProfilePicture,omitempty"`

	// Group membership attribute.
	// Sets LDAP_ATTRIBUTE_GROUP_MEMBER. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	GroupMember string `json:"groupMember,omitempty"`

	// Group unique identifier attribute.
	// Sets LDAP_ATTRIBUTE_GROUP_UNIQUE_IDENTIFIER. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	GroupUniqueIdentifier string `json:"groupUniqueIdentifier,omitempty"`

	// Group name attribute.
	// Sets LDAP_ATTRIBUTE_GROUP_NAME. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	GroupName string `json:"groupName,omitempty"`
}

// LDAPConfig configures LDAP authentication. When present, the operator sets LDAP_ENABLED=true and UI_CONFIG_DISABLED=true.
type LDAPConfig struct {
	// LDAP server URL.
	// Sets LDAP_URL. See https://pocket-id.org/docs/configuration/environment-variables.
	// +kubebuilder:validation:Required
	URL string `json:"url"`

	// Bind DN.
	// Sets LDAP_BIND_DN. See https://pocket-id.org/docs/configuration/environment-variables.
	// +kubebuilder:validation:Required
	BindDN string `json:"bindDN"`

	// Bind password.
	// Sets LDAP_BIND_PASSWORD. See https://pocket-id.org/docs/configuration/environment-variables.
	// +kubebuilder:validation:Required
	BindPassword SensitiveValue `json:"bindPassword"`

	// Search base DN.
	// Sets LDAP_BASE. See https://pocket-id.org/docs/configuration/environment-variables.
	// +kubebuilder:validation:Required
	Base string `json:"base"`

	// Skip LDAP certificate verification.
	// Sets LDAP_SKIP_CERT_VERIFY. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	SkipCertVerify *bool `json:"skipCertVerify,omitempty"`

	// Disable removed users instead of deleting them.
	// Sets LDAP_SOFT_DELETE_USERS. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	SoftDeleteUsers *bool `json:"softDeleteUsers,omitempty"`

	// Group that grants admin privileges.
	// Sets LDAP_ADMIN_GROUP_NAME. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	AdminGroupName string `json:"adminGroupName,omitempty"`

	// User search filter.
	// Sets LDAP_USER_SEARCH_FILTER. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	UserSearchFilter string `json:"userSearchFilter,omitempty"`

	// Group search filter.
	// Sets LDAP_USER_GROUP_SEARCH_FILTER. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	UserGroupSearchFilter string `json:"userGroupSearchFilter,omitempty"`

	// LDAP attribute mappings.
	// +optional
	AttributeMapping *LDAPAttributeMappingConfig `json:"attributeMapping,omitempty"`
}

// LoggingConfig configures logging behavior.
type LoggingConfig struct {
	// Log level.
	// Sets LOG_LEVEL. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	Level string `json:"level,omitempty"`

	// JSON log output.
	// Sets LOG_JSON. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	JSON *bool `json:"json,omitempty"`

	// Include SQL query arguments in debug logs and traces.
	// Sets LOG_QUERY_ARGS. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	QueryArgs *bool `json:"queryArgs,omitempty"`
}

// TracingConfig enables OpenTelemetry tracing. When present, the operator sets OTEL_TRACES_EXPORTER=otlp.
// Configure other OTEL_* variables via spec.env.
type TracingConfig struct {
	// OTLP traces endpoint, including the path.
	// Sets OTEL_EXPORTER_OTLP_TRACES_ENDPOINT. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	Endpoint string `json:"endpoint,omitempty"`
}

// UIConfig configures Pocket-ID UI settings. The operator sets UI_CONFIG_DISABLED=true when this section is configured.
type UIConfig struct {
	// Application name.
	// Sets APP_NAME. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	AppName string `json:"appName,omitempty"`

	// Session duration in minutes.
	// Sets SESSION_DURATION. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	SessionDuration *int32 `json:"sessionDuration,omitempty"`

	// Post-login redirect page.
	// Sets HOME_PAGE_URL. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	HomePageURL string `json:"homePageUrl,omitempty"`

	// Disable UI animations.
	// Sets DISABLE_ANIMATIONS. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	DisableAnimations *bool `json:"disableAnimations,omitempty"`

	// UI accent color.
	// Sets ACCENT_COLOR. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	AccentColor string `json:"accentColor,omitempty"`
}

// UserManagementConfig configures user registration and account settings. The operator sets UI_CONFIG_DISABLED=true when this section is configured.
type UserManagementConfig struct {
	// Mark emails as verified.
	// Sets EMAILS_VERIFIED. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	EmailsVerified *bool `json:"emailsVerified,omitempty"`

	// Allow users to edit their own account.
	// Sets ALLOW_OWN_ACCOUNT_EDIT. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	AllowOwnAccountEdit *bool `json:"allowOwnAccountEdit,omitempty"`

	// Require an email address.
	// Sets REQUIRE_USER_EMAIL. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	RequireUserEmail *bool `json:"requireUserEmail,omitempty"`

	// User signup mode.
	// Sets ALLOW_USER_SIGNUPS. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	AllowUserSignups string `json:"allowUserSignups,omitempty"`

	// Default custom claims for new users.
	// Sets SIGNUP_DEFAULT_CUSTOM_CLAIMS. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	SignupDefaultCustomClaims string `json:"signupDefaultCustomClaims,omitempty"`

	// Default user group IDs for new users.
	// JSON-encoded into SIGNUP_DEFAULT_USER_GROUP_IDS. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	SignupDefaultUserGroupIDs []string `json:"signupDefaultUserGroupIds,omitempty"`
}

// WebAuthnConfig restricts which passkeys Pocket-ID accepts. The operator sets UI_CONFIG_DISABLED=true when this section is configured.
type WebAuthnConfig struct {
	// Passkey user verification requirement.
	// Sets WEBAUTHN_USER_VERIFICATION. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	UserVerification string `json:"userVerification,omitempty"`

	// Allow synced passkeys.
	// Sets WEBAUTHN_ALLOW_SYNCED_PASSKEYS. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	AllowSyncedPasskeys *bool `json:"allowSyncedPasskeys,omitempty"`

	// Accepted authenticator type.
	// Sets WEBAUTHN_AUTHENTICATOR_ATTACHMENT. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
}

// GeoIPConfig configures GeoIP/MaxMind integration for audit log geolocation.
type GeoIPConfig struct {
	// MaxMind license key.
	// Sets MAXMIND_LICENSE_KEY. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	MaxmindLicenseKey *SensitiveValue `json:"maxmindLicenseKey,omitempty"`

	// GeoLite2 database path.
	// Sets GEOLITE_DB_PATH. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	DBPath string `json:"dbPath,omitempty"`

	// GeoLite2 database download URL.
	// Sets GEOLITE_DB_URL. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	DBURL *SensitiveValue `json:"dbUrl,omitempty"`
}

// PersistenceConfig configures persistence for the pocket-id container.
type PersistenceConfig struct {
	// Enables mounting a persistent volume.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Name of an existing, externally-managed PVC to mount.
	// +optional
	ExistingClaim string `json:"existingClaim,omitempty"`

	// Name of the StorageClass to provision a volume from.
	// +optional
	StorageClass string `json:"storageClass,omitempty"`

	// Size of the claim to dynamically provision.
	// +kubebuilder:default="1Gi"
	// +optional
	Size resource.Quantity `json:"size,omitempty"`

	// AccessModes for the PVC.
	// +kubebuilder:default={"ReadWriteOnce"}
	// +optional
	AccessModes []corev1.PersistentVolumeAccessMode `json:"accessModes,omitempty"`

	// Path where the data volume is mounted in the container.
	// +kubebuilder:default="/app/data"
	// +optional
	Path string `json:"path,omitempty"`

	// SubPath within the volume to mount (volumeMount.subPath).
	// +optional
	SubPath string `json:"subPath,omitempty"`

	// Extra volume mounts to add to the pocket-id container. This is useful for mounting volumes defined in spec.podTemplate.
	// +optional
	ExtraVolumeMounts []corev1.VolumeMount `json:"extraVolumeMounts,omitempty"`
}

// HTTPRouteConfig configures an HTTPRoute (Gateway API) for the instance. Gateway API CRDs must already be present in the cluster.
type HTTPRouteConfig struct {
	// Enables creation of an HTTPRoute.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Name override for the HTTPRoute (defaults to the instance name).
	// +optional
	Name string `json:"name,omitempty"`

	// Additional labels for the HTTPRoute.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Additional annotations for the HTTPRoute.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Gateway parent references.
	// +kubebuilder:validation:MinItems=1
	ParentRefs []gatewayv1.ParentReference `json:"parentRefs"`

	// Hostnames for the route.
	// Automatically set to the hostname from spec.appUrl if not specified.
	// +optional
	Hostnames []gatewayv1.Hostname `json:"hostnames,omitempty"`

	// Template is merged with the operator-built HTTPRoute spec.
	// Operator-managed fields (parentRefs, hostnames, and the default backend rule to the Service) always take precedence.
	// +optional
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	Template *gatewayv1.HTTPRouteSpec `json:"template,omitempty"`
}

// TrustedProxiesConfig configures which upstream proxies Pocket-ID trusts for X-Forwarded-* headers (the TRUST_PROXY environment variable).
// This determines the client IP Pocket-ID sees, which feeds rate limiting, audit-log IPs, and GeoIP.
// When this section is omitted, the operator sets TRUST_PROXY=false unless it manages the instance's route (spec.route.enabled), in which case it trusts the private/loopback ranges where a Gateway's IP would be.
type TrustedProxiesConfig struct {
	// Enabled turns on trust of X-Forwarded-* headers. When false, TRUST_PROXY is set to "false".
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// CIDRs is the list of trusted proxy IPs/CIDRs. Only used when enabled is true. When empty, TRUST_PROXY is set to "true", trusting all upstream sources.
	// To restrict trust, list explicit ranges, e.g. the cluster pod network or a CDN's published ranges when it connects directly to the pod.
	// +optional
	CIDRs []string `json:"cidrs,omitempty"`
}

// MetricsConfig configures the Prometheus metrics endpoint for Pocket-ID.
type MetricsConfig struct {
	// Enables the Prometheus metrics endpoint.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`

	// Port for the Prometheus metrics endpoint.
	// +kubebuilder:default=9464
	// +optional
	Port int32 `json:"port,omitempty"`
}

// TLSConfig terminates TLS inside the Pocket-ID pod instead of at a proxy in front of it. Pocket-ID watches the mount, so certificate renewals can be picked up without restarting the pod.
// +kubebuilder:validation:XValidation:rule="size(self.secretRef.name) > 0",message="tls.secretRef.name is required"
type TLSConfig struct {
	// SecretRef names a kubernetes.io/tls Secret in the instance's namespace holding tls.crt and tls.key.
	// +kubebuilder:validation:Required
	SecretRef corev1.LocalObjectReference `json:"secretRef"`
}

// PocketIDInstanceSpec defines the desired state of PocketIDInstance.
// +kubebuilder:validation:XValidation:rule="self.deploymentType == oldSelf.deploymentType",message="deploymentType is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.external) == has(oldSelf.external)",message="external is immutable; create a new PocketIDInstance to switch modes"
// +kubebuilder:validation:XValidation:rule="!has(self.s3) || !has(self.fileBackend) || self.fileBackend == 's3'",message="fileBackend must be 's3' (or unset) when s3 config is present"
// +kubebuilder:validation:XValidation:rule="!has(self.encryptionKey) || !has(self.encryptionKey.value) || size(self.encryptionKey.value) == 0 || size(self.encryptionKey.value) >= 16",message="encryptionKey value must be at least 16 characters"
// +kubebuilder:validation:XValidation:rule="has(self.external) != has(self.encryptionKey)",message="set exactly one of external (adopt an existing Pocket-ID) or encryptionKey (deploy a new one)"
type PocketIDInstanceSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "mise run generate" to regenerate code after modifying this file
	// The following markers will use OpenAPI v3 schema to validate the value
	// More info: https://book.kubebuilder.io/reference/markers/crd-validation.html

	// Kind of workload to create: Deployment or StatefulSet. Defaults to Deployment and is immutable after creation.
	// +kubebuilder:validation:Enum=Deployment;StatefulSet
	// +kubebuilder:default=Deployment
	// +optional
	DeploymentType string `json:"deploymentType,omitempty"`

	// Container image to run. When unset, the operator uses the latest version tested against this release.
	// +optional
	Image string `json:"image,omitempty"`

	// Encryption key. Required when deploying an instance; omit for external instances.
	// Sets ENCRYPTION_KEY. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	EncryptionKey *SensitiveValue `json:"encryptionKey,omitempty"`

	// External adopts an existing Pocket-ID instead of deploying one. When set, no workload/service/PVC is created and the operator manages OIDC clients, users, and groups on that instance via its API.
	// Mutually exclusive with encryptionKey and the other deployment fields.
	// +optional
	External *ExternalInstanceConfig `json:"external,omitempty"`

	// Database connection string.
	// Sets DB_CONNECTION_STRING. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	DatabaseUrl *SensitiveValue `json:"databaseUrl,omitempty"`

	// Public URL of Pocket-ID.
	// Sets APP_URL. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	AppURL string `json:"appUrl,omitempty"`

	// Additional environment variables to set. Uses Kubernetes env var syntax (secretKeyRef, configMapKeyRef, etc.).
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`

	// Configures persistence for Pocket-ID. Pocket-ID can be run statelessly; see https://pocket-id-operator.pages.dev/examples/pocketidinstance/#stateless-deployment.
	// If not enabled, an emptyDir is mounted instead.
	// +optional
	Persistence PersistenceConfig `json:"persistence,omitempty"`

	// Pod security context.
	// +optional
	PodSecurityContext *corev1.PodSecurityContext `json:"podSecurityContext,omitempty"`

	// Container security context.
	// +optional
	ContainerSecurityContext *corev1.SecurityContext `json:"containerSecurityContext,omitempty"`

	// Deprecated: use spec.podTemplate.hostUsers instead.
	// +kubebuilder:default=true
	// +optional
	HostUsers *bool `json:"hostUsers,omitempty"`

	// Additional labels to add to the workload and pod.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Additional annotations to add to the workload and pod.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Pod template to merge with the operator-built pod spec. Operator-managed fields including the pocket-id container always take precedence.
	// +optional
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	PodTemplate *corev1.PodTemplateSpec `json:"podTemplate,omitempty"`

	// Readiness probe configuration.
	// +optional
	ReadinessProbe *corev1.Probe `json:"readinessProbe,omitempty"`

	// Liveness probe configuration.
	// +optional
	LivenessProbe *corev1.Probe `json:"livenessProbe,omitempty"`

	// Resource requests and limits for the container.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// Prometheus metrics configuration. When enabled, the operator injects the required OTEL environment variables and exposes a metrics port on the Service.
	// +optional
	Metrics *MetricsConfig `json:"metrics,omitempty"`

	// Configures an HTTPRoute when enabled. Requires Gateway API CRDs to be installed.
	// +optional
	Route *HTTPRouteConfig `json:"route,omitempty"`

	// TLS terminates HTTPS in the Pocket-ID pod from a mounted certificate Secret.
	// +optional
	TLS *TLSConfig `json:"tls,omitempty"`

	// ServiceTemplate is merged with the operator-built Service spec.
	// Operator-managed fields (the selector and the number, protocol, and appProtocol of the http/metrics ports) always take precedence.
	// +optional
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:pruning:PreserveUnknownFields
	ServiceTemplate *corev1.ServiceSpec `json:"serviceTemplate,omitempty"`

	// File storage backend. Automatically set to "s3" when s3 config is present.
	// Sets FILE_BACKEND. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	FileBackend string `json:"fileBackend,omitempty"`

	// S3 file backend. When present, the operator sets FILE_BACKEND=s3.
	// +optional
	S3 *S3Config `json:"s3,omitempty"`

	// SMTP email transport. When present, the operator sets SMTP_ENABLED=true and UI_CONFIG_DISABLED=true.
	// +optional
	SMTP *SMTPConfig `json:"smtp,omitempty"`

	// Email notification settings. Requires smtp. The operator sets UI_CONFIG_DISABLED=true when this section is configured.
	// +optional
	EmailNotifications *EmailNotificationsConfig `json:"emailNotifications,omitempty"`

	// LDAP authentication. When present, the operator sets LDAP_ENABLED=true and UI_CONFIG_DISABLED=true.
	// +optional
	LDAP *LDAPConfig `json:"ldap,omitempty"`

	// Logging configuration.
	// +optional
	Logging *LoggingConfig `json:"logging,omitempty"`

	// OpenTelemetry tracing. When present, the operator sets OTEL_TRACES_EXPORTER=otlp.
	// Configure other OTEL_* variables via spec.env.
	// +optional
	Tracing *TracingConfig `json:"tracing,omitempty"`

	// UI settings. The operator sets UI_CONFIG_DISABLED=true when this section is configured.
	// +optional
	UI *UIConfig `json:"ui,omitempty"`

	// User registration and account settings. The operator sets UI_CONFIG_DISABLED=true when this section is configured.
	// +optional
	UserManagement *UserManagementConfig `json:"userManagement,omitempty"`

	// Passkey restrictions. The operator sets UI_CONFIG_DISABLED=true when this section is configured.
	// +optional
	WebAuthn *WebAuthnConfig `json:"webauthn,omitempty"`

	// GeoIP/MaxMind integration for audit log geolocation.
	// +optional
	GeoIP *GeoIPConfig `json:"geoip,omitempty"`

	// Audit log retention in days.
	// Sets AUDIT_LOG_RETENTION_DAYS. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	AuditLogRetentionDays *int32 `json:"auditLogRetentionDays,omitempty"`

	// Disable anonymous usage analytics.
	// Sets ANALYTICS_DISABLED. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	AnalyticsDisabled *bool `json:"analyticsDisabled,omitempty"`

	// Disable version checks.
	// Sets VERSION_CHECK_DISABLED. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	VersionCheckDisabled *bool `json:"versionCheckDisabled,omitempty"`

	// Disable rate limiting. Pocket-ID's rate limits are permissive enough for the operator, so keeping them is recommended.
	// Sets DISABLE_RATE_LIMITING. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	RateLimitingDisabled *bool `json:"rateLimitingDisabled,omitempty"`

	// Internal base URL for split-horizon DNS.
	// Sets INTERNAL_APP_URL. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	InternalAppURL string `json:"internalAppUrl,omitempty"`

	// Local IPv6 ranges (comma-separated CIDRs).
	// Sets LOCAL_IPV6_RANGES. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	LocalIPv6Ranges string `json:"localIPv6Ranges,omitempty"`

	// TrustedProxies configures which proxies Pocket-ID trusts for X-Forwarded-* headers. When unset, the operator trusts the private/loopback ranges if spec.route.enabled is set.
	// Sets TRUST_PROXY. See https://pocket-id.org/docs/configuration/environment-variables#trust_proxy.
	// +optional
	TrustedProxies *TrustedProxiesConfig `json:"trustedProxies,omitempty"`

	// Timezone (e.g. "America/New_York").
	// Sets TZ.
	// +optional
	Timezone string `json:"timezone,omitempty"`

	// Allowed OAuth Client ID Metadata Document URLs. The operator sets UI_CONFIG_DISABLED=true when this field is set.
	// JSON-encoded into CIMD_URL_ALLOWLIST. See https://pocket-id.org/docs/configuration/environment-variables.
	// +optional
	CIMDURLAllowlist []string `json:"cimdUrlAllowlist,omitempty"`

	// OIDCClientRotation configures instance-wide throttling of OIDC client secret rotations.
	// +optional
	OIDCClientRotation *OIDCClientRotationConfig `json:"OIDCClientRotation,omitempty"`
}

// OIDCClientRotationConfig controls instance-wide throttling of OIDC client secret rotations.
type OIDCClientRotationConfig struct {
	// MinSpacing is the minimum time between any two client secret rotations on this instance.
	// Prevents a thundering herd when many clients become due simultaneously.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="duration(self) > duration('0s')",message="minSpacing must be a positive duration"
	MinSpacing metav1.Duration `json:"minSpacing"`
}

// PocketIDInstanceStatus defines the observed state of PocketIDInstance.
type PocketIDInstanceStatus struct {
	// Version is the current deployed version of the Pocket-ID instance, retrieved from the /api/version/current endpoint.
	// +optional
	Version string `json:"version,omitempty"`

	// StaticAPIKeySecretName is the name of the Secret containing the STATIC_API_KEY.
	// +optional
	StaticAPIKeySecretName string `json:"staticApiKeySecretName,omitempty"`

	// Conditions represent the current state of the Instance resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastRotatedClientSecret is the timestamp of the most recent OIDC client secret rotation on this instance.
	// Used to enforce spec.OIDCClientRotation.minSpacing.
	// +optional
	LastRotatedClientSecret *metav1.Time `json:"lastRotatedClientSecret,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pidinstance;

// PocketIDInstance is the Schema for the pocketidinstances API.
type PocketIDInstance struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of PocketIDInstance.
	// +required
	Spec PocketIDInstanceSpec `json:"spec"`

	// status defines the observed state of PocketIDInstance.
	// +optional
	Status PocketIDInstanceStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PocketIDInstanceList contains a list of PocketIDInstance.
type PocketIDInstanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PocketIDInstance `json:"items"`
}
