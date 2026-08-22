//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Test constants
const (
	instanceName = "e2e-instance"
	instanceNS   = "pocket-id-e2e-test"
	userNS       = "pocket-id-e2e-users"
)

// --- YAML Builders ---

// InstanceOptions configures a PocketIDInstance YAML.
type InstanceOptions struct {
	Name               string
	Namespace          string
	Labels             map[string]string
	Image              string
	PersistenceEnabled *bool
	PersistenceSize    string
	ExistingClaim      string
	CIMDURLAllowlist   []string
	// TLSSecretName makes the instance terminate TLS from that kubernetes.io/tls
	// Secret, which also forces appUrl to https.
	TLSSecretName string
	// NodePort publishes the instance's http port on that node port, which Kind maps to
	// the same port on the host (see setup-test-e2e). Set on the shared instance so the
	// suite can call Pocket-ID's API directly instead of through a pod in the cluster.
	NodePort int
}

const defaultPocketIDImage = "ghcr.io/pocket-id/pocket-id:v2.14.0-distroless@sha256:e0f83a42a78d0759b6d2d8c7380ef0fa8a4c95dfa01ad88740a073ae9cc4ba94"

func pocketIDImage() string {
	if img := os.Getenv("POCKET_ID_IMAGE"); img != "" {
		return img
	}
	return defaultPocketIDImage
}

func (o InstanceOptions) withDefaults() InstanceOptions {
	if o.Name == "" {
		o.Name = instanceName
	}
	if o.Namespace == "" {
		o.Namespace = instanceNS
	}
	if o.Image == "" {
		o.Image = pocketIDImage()
	}
	return o
}

func buildInstanceYAML(opts InstanceOptions) string {
	opts = opts.withDefaults()

	var labels string
	if len(opts.Labels) > 0 {
		labelLines := make([]string, 0, len(opts.Labels))
		for k, v := range opts.Labels {
			labelLines = append(labelLines, fmt.Sprintf("    %s: %s", k, v))
		}
		labels = "  labels:\n" + strings.Join(labelLines, "\n") + "\n"
	}

	var persistence string
	if opts.PersistenceEnabled != nil && *opts.PersistenceEnabled {
		persistence = "  persistence:\n    enabled: true\n"
		if opts.ExistingClaim != "" {
			persistence += fmt.Sprintf("    existingClaim: %s\n", opts.ExistingClaim)
		} else if opts.PersistenceSize != "" {
			persistence += fmt.Sprintf("    size: %s\n", opts.PersistenceSize)
		}
	}

	var cimd string
	if len(opts.CIMDURLAllowlist) > 0 {
		cimd = "  cimdUrlAllowlist:\n"
		for _, pattern := range opts.CIMDURLAllowlist {
			cimd += fmt.Sprintf("  - %q\n", pattern)
		}
	}
	persistence += cimd

	if opts.NodePort != 0 {
		persistence += fmt.Sprintf(`  serviceTemplate:
    type: NodePort
    ports:
    - name: http
      nodePort: %d
`, opts.NodePort)
	}

	scheme := "http"
	if opts.TLSSecretName != "" {
		scheme = "https"
		persistence += fmt.Sprintf("  tls:\n    secretRef:\n      name: %s\n", opts.TLSSecretName)
	}

	return fmt.Sprintf(`apiVersion: pocketid.internal/v1alpha1
kind: PocketIDInstance
metadata:
  name: %s
  namespace: %s
%sspec:
  image: %s
  encryptionKey:
    valueFrom:
      secretKeyRef:
        name: pocket-id-encryption
        key: key
  appUrl: "%s://%s.%s.svc:1411"
%s`, opts.Name, opts.Namespace, labels, opts.Image, scheme, opts.Name, opts.Namespace, persistence)
}

// UserOptions configures a PocketIDUser YAML.
type UserOptions struct {
	Name             string
	Namespace        string
	UserID           string
	Username         string
	FirstName        string
	LastName         string
	Email            string
	DisplayName      string
	Admin            *bool
	CustomClaims     []CustomClaim
	APIKeys          []APIKeySpec
	UserInfoSecret   string
	InstanceSelector map[string]string
	Annotations      map[string]string
}

type APIKeySpec struct {
	Name        string
	Description string
	ExpiresAt   string
}

func (o UserOptions) withDefaults() UserOptions {
	if o.Name == "" {
		o.Name = "test-user"
	}
	if o.Namespace == "" {
		o.Namespace = userNS
	}
	return o
}

func buildUserYAML(opts UserOptions) string {
	opts = opts.withDefaults()

	var annotations string
	if len(opts.Annotations) > 0 {
		annotationLines := make([]string, 0, len(opts.Annotations))
		for k, v := range opts.Annotations {
			annotationLines = append(annotationLines, fmt.Sprintf("    %s: \"%s\"", k, v))
		}
		annotations = "  annotations:\n" + strings.Join(annotationLines, "\n") + "\n"
	}

	var spec strings.Builder

	if opts.UserID != "" {
		spec.WriteString(fmt.Sprintf("  userID: %s\n", opts.UserID))
	}
	if opts.Username != "" {
		spec.WriteString(fmt.Sprintf("  username:\n    value: %s\n", opts.Username))
	}
	if opts.FirstName != "" {
		spec.WriteString(fmt.Sprintf("  firstName:\n    value: %s\n", opts.FirstName))
	}
	if opts.LastName != "" {
		spec.WriteString(fmt.Sprintf("  lastName:\n    value: %s\n", opts.LastName))
	}
	if opts.Email != "" {
		spec.WriteString(fmt.Sprintf("  email:\n    value: %s\n", opts.Email))
	}
	if opts.DisplayName != "" {
		spec.WriteString(fmt.Sprintf("  displayName:\n    value: %s\n", opts.DisplayName))
	}
	if opts.Admin != nil {
		spec.WriteString(fmt.Sprintf("  admin: %t\n", *opts.Admin))
	}
	if opts.UserInfoSecret != "" {
		spec.WriteString(fmt.Sprintf("  userInfoSecretRef:\n    name: %s\n", opts.UserInfoSecret))
	}
	if len(opts.CustomClaims) > 0 {
		spec.WriteString("  customClaims:\n")
		for _, claim := range opts.CustomClaims {
			spec.WriteString(fmt.Sprintf("  - key: %s\n    value: %s\n", claim.Key, claim.Value))
		}
	}
	if len(opts.InstanceSelector) > 0 {
		spec.WriteString("  instanceSelector:\n    matchLabels:\n")
		for k, v := range opts.InstanceSelector {
			spec.WriteString(fmt.Sprintf("      %s: %s\n", k, v))
		}
	}
	if len(opts.APIKeys) > 0 {
		spec.WriteString("  apiKeys:\n")
		for _, key := range opts.APIKeys {
			spec.WriteString(fmt.Sprintf("  - name: %s\n", key.Name))
			if key.Description != "" {
				spec.WriteString(fmt.Sprintf("    description: %s\n", key.Description))
			}
			if key.ExpiresAt != "" {
				spec.WriteString(fmt.Sprintf("    expiresAt: %s\n", key.ExpiresAt))
			}
		}
	}

	specStr := spec.String()
	if specStr == "" {
		return fmt.Sprintf(`apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
%s`, opts.Name, opts.Namespace, annotations)
	}

	return fmt.Sprintf(`apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
%sspec:
%s`, opts.Name, opts.Namespace, annotations, specStr)
}

// UserGroupOptions configures a PocketIDUserGroup YAML.
type UserGroupOptions struct {
	Name               string
	Namespace          string
	GroupName          string
	FriendlyName       string
	CustomClaims       []CustomClaim
	UserRefs           []ResourceRef
	Usernames          []string
	UserIds            []string
	AllowedOIDCClients []ResourceRef
}

type CustomClaim struct {
	Key   string
	Value string
}

type ResourceRef struct {
	Name      string
	Namespace string
}

func (o UserGroupOptions) withDefaults() UserGroupOptions {
	if o.Name == "" {
		o.Name = "test-user-group"
	}
	if o.Namespace == "" {
		o.Namespace = userNS
	}
	if o.GroupName == "" {
		o.GroupName = o.Name
	}
	if o.FriendlyName == "" {
		o.FriendlyName = o.GroupName
	}
	return o
}

func buildUserGroupYAML(opts UserGroupOptions) string {
	opts = opts.withDefaults()

	var spec strings.Builder
	spec.WriteString(fmt.Sprintf("  name: %s\n", opts.GroupName))
	spec.WriteString(fmt.Sprintf("  friendlyName: %s\n", opts.FriendlyName))

	if len(opts.CustomClaims) > 0 {
		spec.WriteString("  customClaims:\n")
		for _, claim := range opts.CustomClaims {
			spec.WriteString(fmt.Sprintf("  - key: %s\n    value: %s\n", claim.Key, claim.Value))
		}
	}

	// Build users section if any user specification is provided
	hasUsers := len(opts.UserRefs) > 0 || len(opts.Usernames) > 0 || len(opts.UserIds) > 0
	if hasUsers {
		spec.WriteString("  users:\n")

		if len(opts.UserRefs) > 0 {
			spec.WriteString("    userRefs:\n")
			for _, ref := range opts.UserRefs {
				spec.WriteString(fmt.Sprintf("    - name: %s\n", ref.Name))
				if ref.Namespace != "" {
					spec.WriteString(fmt.Sprintf("      namespace: %s\n", ref.Namespace))
				}
			}
		}

		if len(opts.Usernames) > 0 {
			spec.WriteString("    usernames:\n")
			for _, username := range opts.Usernames {
				spec.WriteString(fmt.Sprintf("    - %s\n", username))
			}
		}

		if len(opts.UserIds) > 0 {
			spec.WriteString("    userIDs:\n")
			for _, userID := range opts.UserIds {
				spec.WriteString(fmt.Sprintf("    - %s\n", userID))
			}
		}
	}

	if len(opts.AllowedOIDCClients) > 0 {
		spec.WriteString("  allowedOIDCClients:\n")
		for _, ref := range opts.AllowedOIDCClients {
			spec.WriteString(fmt.Sprintf("  - name: %s\n", ref.Name))
			if ref.Namespace != "" {
				spec.WriteString(fmt.Sprintf("    namespace: %s\n", ref.Namespace))
			}
		}
	}

	return fmt.Sprintf(`apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUserGroup
metadata:
  name: %s
  namespace: %s
spec:
%s`, opts.Name, opts.Namespace, spec.String())
}

// OIDCClientOptions configures a PocketIDOIDCClient YAML.
type OIDCClientOptions struct {
	Name               string
	Namespace          string
	SpecName           string // spec.name: Pocket-ID display name (defaults to metadata.name when empty)
	Description        string
	ClientID           string // Custom client ID (defaults to Name if empty)
	CallbackURLs       []string
	LogoutCallbackURLs []string
	IsPublic           bool
	SkipConsent        bool
	RequiresPAR        bool // spec.requiresPushedAuthorizationRequests

	AccessTokenDurationMinutes  int64
	RefreshTokenDurationMinutes int64

	FederatedIdentities []FederatedIdentity
	AllowedUserGroups   []string // spec.allowedUserGroups[].name: PocketIDUserGroup CRs
	AllowedGroupNames   []string // spec.allowedUserGroups[].groupName: Pocket-ID groups with no CR
	AllowedGroupIDs     []string // spec.allowedUserGroups[].groupID: Pocket-ID groups with no CR
	APIAccess           []APIAccessGrant
	Logo                *OIDCLogoConfig
	Secret              *OIDCSecretConfig
	SCIM                *SCIMConfig
}

// FederatedIdentity configures a spec.federatedIdentities entry.
type FederatedIdentity struct {
	Issuer           string
	Subject          string
	Audience         string
	JWKS             string
	ReplayProtection bool
}

// APIAccessGrant configures a spec.apiAccess entry granting permissions on a PocketIDAPI.
type APIAccessGrant struct {
	APIRefName           string
	APIRefNamespace      string
	DelegatedPermissions []string
	ClientPermissions    []string
	DelegatedAccess      *bool
	ClientAccess         *bool
}

// OIDCLogoConfig configures the logo spec for an OIDCClient.
type OIDCLogoConfig struct {
	AutoGenerate *bool
	NameOverride string
	LogoURL      string
	DarkLogoURL  string
}

// SCIMConfig configures the SCIM spec for an OIDCClient.
type SCIMConfig struct {
	Endpoint       string
	TokenSecretRef *SecretKeyRef
}

// SecretKeyRef references a key in a Kubernetes Secret.
type SecretKeyRef struct {
	Name string
	Key  string
}

type OIDCSecretConfig struct {
	Enabled *bool
	Name    string
	Keys    *OIDCSecretKeys
}

type OIDCSecretKeys struct {
	ClientID           string
	ClientSecret       string
	IssuerURL          string
	CallbackURLs       string
	LogoutCallbackURLs string
}

func (o OIDCClientOptions) withDefaults() OIDCClientOptions {
	if o.Name == "" {
		o.Name = "test-oidc-client"
	}
	if o.Namespace == "" {
		o.Namespace = userNS
	}
	// A CIMD client's callback URLs come from its metadata document and are rejected in
	// the spec, so the default must not be injected for one. The https prefix is what both
	// the CRD's CEL rules and pocketid.LooksLikeCIMDID key on.
	if len(o.CallbackURLs) == 0 && !strings.HasPrefix(o.ClientID, "https://") {
		o.CallbackURLs = []string{"https://example.com/callback"}
	}
	return o
}

func buildOIDCClientYAML(opts OIDCClientOptions) string {
	opts = opts.withDefaults()

	var spec strings.Builder

	if opts.SpecName != "" {
		spec.WriteString(fmt.Sprintf("  name: %s\n", opts.SpecName))
	}

	if opts.ClientID != "" {
		// Quoted because a CIMD client ID is a URL.
		spec.WriteString(fmt.Sprintf("  clientID: %q\n", opts.ClientID))
	}

	if opts.Description != "" {
		spec.WriteString(fmt.Sprintf("  description: %s\n", opts.Description))
	}

	if opts.IsPublic {
		spec.WriteString("  isPublic: true\n")
	}

	if opts.SkipConsent {
		spec.WriteString("  skipConsent: true\n")
	}

	if opts.RequiresPAR {
		spec.WriteString("  requiresPushedAuthorizationRequests: true\n")
	}

	if opts.AccessTokenDurationMinutes != 0 {
		spec.WriteString(fmt.Sprintf("  accessTokenDurationMinutes: %d\n", opts.AccessTokenDurationMinutes))
	}
	if opts.RefreshTokenDurationMinutes != 0 {
		spec.WriteString(fmt.Sprintf("  refreshTokenDurationMinutes: %d\n", opts.RefreshTokenDurationMinutes))
	}

	if len(opts.FederatedIdentities) > 0 {
		spec.WriteString("  federatedIdentities:\n")
		for _, identity := range opts.FederatedIdentities {
			spec.WriteString(fmt.Sprintf("  - issuer: %s\n", identity.Issuer))
			if identity.Subject != "" {
				spec.WriteString(fmt.Sprintf("    subject: %s\n", identity.Subject))
			}
			if identity.Audience != "" {
				spec.WriteString(fmt.Sprintf("    audience: %s\n", identity.Audience))
			}
			if identity.JWKS != "" {
				spec.WriteString(fmt.Sprintf("    jwks: %s\n", identity.JWKS))
			}
			if identity.ReplayProtection {
				spec.WriteString("    replayProtection: true\n")
			}
		}
	}

	if len(opts.CallbackURLs) > 0 {
		spec.WriteString("  callbackUrls:\n")
		for _, url := range opts.CallbackURLs {
			spec.WriteString(fmt.Sprintf("  - %s\n", url))
		}
	}

	if len(opts.LogoutCallbackURLs) > 0 {
		spec.WriteString("  logoutCallbackUrls:\n")
		for _, url := range opts.LogoutCallbackURLs {
			spec.WriteString(fmt.Sprintf("  - %s\n", url))
		}
	}

	if len(opts.AllowedUserGroups) > 0 || len(opts.AllowedGroupNames) > 0 || len(opts.AllowedGroupIDs) > 0 {
		spec.WriteString("  allowedUserGroups:\n")
		for _, group := range opts.AllowedUserGroups {
			spec.WriteString(fmt.Sprintf("  - name: %s\n", group))
		}
		for _, group := range opts.AllowedGroupNames {
			spec.WriteString(fmt.Sprintf("  - groupName: %s\n", group))
		}
		for _, group := range opts.AllowedGroupIDs {
			spec.WriteString(fmt.Sprintf("  - groupID: %s\n", group))
		}
	}

	if len(opts.APIAccess) > 0 {
		spec.WriteString("  apiAccess:\n")
		for _, grant := range opts.APIAccess {
			spec.WriteString(fmt.Sprintf("  - apiRef:\n      name: %s\n", grant.APIRefName))
			if grant.APIRefNamespace != "" {
				spec.WriteString(fmt.Sprintf("      namespace: %s\n", grant.APIRefNamespace))
			}
			if len(grant.DelegatedPermissions) > 0 {
				spec.WriteString("    delegatedPermissions:\n")
				for _, key := range grant.DelegatedPermissions {
					spec.WriteString(fmt.Sprintf("    - %s\n", key))
				}
			}
			if len(grant.ClientPermissions) > 0 {
				spec.WriteString("    clientPermissions:\n")
				for _, key := range grant.ClientPermissions {
					spec.WriteString(fmt.Sprintf("    - %s\n", key))
				}
			}
			if grant.DelegatedAccess != nil {
				spec.WriteString(fmt.Sprintf("    delegatedAccess: %t\n", *grant.DelegatedAccess))
			}
			if grant.ClientAccess != nil {
				spec.WriteString(fmt.Sprintf("    clientAccess: %t\n", *grant.ClientAccess))
			}
		}
	}

	if opts.Logo != nil {
		spec.WriteString("  logo:\n")
		if opts.Logo.AutoGenerate != nil {
			spec.WriteString(fmt.Sprintf("    autoGenerate: %t\n", *opts.Logo.AutoGenerate))
		}
		if opts.Logo.NameOverride != "" {
			spec.WriteString(fmt.Sprintf("    nameOverride: %s\n", opts.Logo.NameOverride))
		}
		if opts.Logo.LogoURL != "" {
			spec.WriteString(fmt.Sprintf("    logoUrl: %s\n", opts.Logo.LogoURL))
		}
		if opts.Logo.DarkLogoURL != "" {
			spec.WriteString(fmt.Sprintf("    darkLogoUrl: %s\n", opts.Logo.DarkLogoURL))
		}
	}

	if opts.Secret != nil {
		spec.WriteString("  secret:\n")
		if opts.Secret.Enabled != nil {
			spec.WriteString(fmt.Sprintf("    enabled: %t\n", *opts.Secret.Enabled))
		}
		if opts.Secret.Name != "" {
			spec.WriteString(fmt.Sprintf("    name: %s\n", opts.Secret.Name))
		}
		if opts.Secret.Keys != nil {
			spec.WriteString("    keys:\n")
			if opts.Secret.Keys.ClientID != "" {
				spec.WriteString(fmt.Sprintf("      clientID: %s\n", opts.Secret.Keys.ClientID))
			}
			if opts.Secret.Keys.ClientSecret != "" {
				spec.WriteString(fmt.Sprintf("      clientSecret: %s\n", opts.Secret.Keys.ClientSecret))
			}
			if opts.Secret.Keys.IssuerURL != "" {
				spec.WriteString(fmt.Sprintf("      issuerUrl: %s\n", opts.Secret.Keys.IssuerURL))
			}
			if opts.Secret.Keys.CallbackURLs != "" {
				spec.WriteString(fmt.Sprintf("      callbackUrls: %s\n", opts.Secret.Keys.CallbackURLs))
			}
			if opts.Secret.Keys.LogoutCallbackURLs != "" {
				spec.WriteString(fmt.Sprintf("      logoutCallbackUrls: %s\n", opts.Secret.Keys.LogoutCallbackURLs))
			}
		}
	}

	if opts.SCIM != nil {
		spec.WriteString("  scim:\n")
		spec.WriteString(fmt.Sprintf("    endpoint: %s\n", opts.SCIM.Endpoint))
		if opts.SCIM.TokenSecretRef != nil {
			spec.WriteString("    tokenSecretRef:\n")
			spec.WriteString(fmt.Sprintf("      name: %s\n", opts.SCIM.TokenSecretRef.Name))
			spec.WriteString(fmt.Sprintf("      key: %s\n", opts.SCIM.TokenSecretRef.Key))
		}
	}

	return fmt.Sprintf(`apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: %s
  namespace: %s
spec:
%s`, opts.Name, opts.Namespace, spec.String())
}

// APIOptions configures a PocketIDAPI YAML.
type APIOptions struct {
	Name             string // metadata.name
	Namespace        string
	SpecName         string // spec.name: Pocket-ID display name (defaults to metadata.name when empty)
	Resource         string // audience identifier (immutable); defaults from Name when empty
	Permissions      []APIPermissionOption
	InstanceSelector map[string]string
	CIMDAccess       *bool
}

// APIPermissionOption configures a spec.permissions entry.
type APIPermissionOption struct {
	Key         string
	Name        string
	Description string
	CIMDAccess  bool
}

func (o APIOptions) withDefaults() APIOptions {
	if o.Name == "" {
		o.Name = "test-api"
	}
	if o.Namespace == "" {
		o.Namespace = userNS
	}
	if o.Resource == "" {
		o.Resource = fmt.Sprintf("https://%s.example.com", o.Name)
	}
	return o
}

func buildAPIYAML(opts APIOptions) string {
	opts = opts.withDefaults()

	var spec strings.Builder
	if opts.SpecName != "" {
		spec.WriteString(fmt.Sprintf("  name: %s\n", opts.SpecName))
	}
	spec.WriteString(fmt.Sprintf("  resource: %s\n", opts.Resource))

	if len(opts.InstanceSelector) > 0 {
		spec.WriteString("  instanceSelector:\n    matchLabels:\n")
		for k, v := range opts.InstanceSelector {
			spec.WriteString(fmt.Sprintf("      %s: %s\n", k, v))
		}
	}

	if len(opts.Permissions) > 0 {
		spec.WriteString("  permissions:\n")
		for _, p := range opts.Permissions {
			spec.WriteString(fmt.Sprintf("  - key: %s\n    name: %s\n", p.Key, p.Name))
			if p.Description != "" {
				spec.WriteString(fmt.Sprintf("    description: %s\n", p.Description))
			}
			if p.CIMDAccess {
				spec.WriteString("    cimdAccess: true\n")
			}
		}
	}

	if opts.CIMDAccess != nil {
		spec.WriteString(fmt.Sprintf("  cimdAccess: %t\n", *opts.CIMDAccess))
	}

	return fmt.Sprintf(`apiVersion: pocketid.internal/v1alpha1
kind: PocketIDAPI
metadata:
  name: %s
  namespace: %s
spec:
%s`, opts.Name, opts.Namespace, spec.String())
}

// --- kubectl Helpers ---

// kubectlGetSecretData returns one decoded value from a Secret, or "" when the Secret or
// the key is absent.
func kubectlGetSecretData(secretName, namespace, key string) string {
	secret := &corev1.Secret{}
	if err := k8sClient.Get(context.Background(),
		client.ObjectKey{Name: secretName, Namespace: namespace}, secret); err != nil {
		return ""
	}
	return string(secret.Data[key])
}

func kubectlDelete(resource, name, namespace string) {
	deleteObject(resource, name, namespace)
}

func kubectlDeleteWait(resource, name, namespace string, timeout time.Duration) error {
	return deleteObjectAndWait(resource, name, namespace, timeout)
}

func kubectlAnnotate(resource, name, namespace, annotation string) error {
	return annotateObject(resource, name, namespace, annotation)
}

func kubectlPatch(resource, name, namespace, patch string) error {
	return patchObject(resource, name, namespace, patch)
}

// removeFinalizers clears finalizers from every operator-owned resource in the namespace,
// so teardown cannot hang on a controller that is already being torn down itself.
func removeFinalizers(namespace string) {
	for _, resource := range []string{
		"pocketiduser", "pocketidusergroup", "pocketidoidcclient", "pocketidapi", "pocketidinstance",
	} {
		list := &unstructured.UnstructuredList{}
		gvk := resourceGVK[resource]
		gvk.Kind += "List"
		list.SetGroupVersionKind(gvk)
		if err := k8sClient.List(context.Background(), list, client.InNamespace(namespace)); err != nil {
			continue
		}
		for i := range list.Items {
			_ = patchObject(resource, list.Items[i].GetName(), namespace,
				`{"metadata":{"finalizers":null}}`)
		}
	}
}

// --- Wait Helpers ---

func waitForReady(resource, name, namespace string) {
	waitForCondition(resource, name, namespace, "Ready", "True")
}

func waitForCondition(resource, name, namespace, conditionType, status string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		obj, err := getObject(resource, name, namespace)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(conditionField(obj, conditionType, "status")).To(Equal(status),
			"%s/%s should have condition %s=%s", resource, name, conditionType, status)
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
}

func waitForConditionReason(resource, name, namespace, conditionType, reason string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		obj, err := getObject(resource, name, namespace)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(conditionField(obj, conditionType, "reason")).To(Equal(reason))
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
}

func waitForStatusField(resource, name, namespace, path, expected string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		obj, err := getObject(resource, name, namespace)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(fieldString(obj, path)).To(Equal(expected),
			"%s/%s field %s", resource, name, path)
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
}

func waitForStatusFieldNotEmpty(resource, name, namespace, path string) string {
	GinkgoHelper()
	var result string
	Eventually(func(g Gomega) {
		obj, err := getObject(resource, name, namespace)
		g.Expect(err).NotTo(HaveOccurred())
		result = fieldString(obj, path)
		g.Expect(result).NotTo(BeEmpty(), "%s/%s field %s", resource, name, path)
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
	return result
}

func waitForSecretKey(secretName, namespace, key string) string {
	var result string
	Eventually(func(g Gomega) {
		result = kubectlGetSecretData(secretName, namespace, key)
		g.Expect(result).NotTo(BeEmpty())
	}, time.Minute, 2*time.Second).Should(Succeed())
	return result
}

// waitForReconciled waits until the resource's Ready condition is True and its
// observedGeneration has caught up to metadata.generation, i.e. the operator has fully
// reconciled the latest spec. Use this after updating a spec whose effect is not visible
// in a pollable status field, before asserting directly against Pocket-ID.
func waitForReconciled(resource, name, namespace string) {
	GinkgoHelper()
	current, err := getObject(resource, name, namespace)
	Expect(err).NotTo(HaveOccurred())
	gen := fieldString(current, ".metadata.generation")
	Expect(gen).NotTo(BeEmpty())

	Eventually(func(g Gomega) {
		obj, err := getObject(resource, name, namespace)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(conditionField(obj, "Ready", "observedGeneration")).To(Equal(gen),
			"observedGeneration should catch up to spec generation")
		g.Expect(conditionField(obj, "Ready", "status")).To(Equal("True"))
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
}

func waitForResourceDeleted(resource, name, namespace string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		_, err := getObject(resource, name, namespace)
		g.Expect(isGone(err)).To(BeTrue(), "%s/%s should be gone, got %v", resource, name, err)
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
}

// isGone reports whether a Get proves the object is absent. A missing object is the usual
// case; a missing *kind* also counts, because the httproute specs uninstall the Gateway API
// CRD at runtime and nothing of that kind can exist once its definition is gone.
func isGone(err error) bool {
	return apierrors.IsNotFound(err) || meta.IsNoMatchError(err) ||
		runtime.IsNotRegisteredError(err)
}

func waitForSecretExists(secretName, namespace string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		_, err := getObject("secret", secretName, namespace)
		g.Expect(err).NotTo(HaveOccurred(), "secret %s should exist", secretName)
	}, time.Minute, 2*time.Second).Should(Succeed())
}

func waitForSecretNotExists(secretName, namespace string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		_, err := getObject("secret", secretName, namespace)
		g.Expect(isGone(err)).To(BeTrue(), "secret %s should be gone, got %v", secretName, err)
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
}

// --- Create and Wait Helpers ---

func createInstance(opts InstanceOptions) {
	applyYAML(buildInstanceYAML(opts))
}

func createInstanceAndWaitReady(opts InstanceOptions) {
	opts = opts.withDefaults()
	createInstance(opts)
	Eventually(func(g Gomega) {
		output := getField("pocketidinstance", opts.Name, opts.Namespace, ".status.conditions[?(@.type=='Ready')].status")
		g.Expect(output).To(Equal("True"))
	}, 5*time.Minute, 5*time.Second).Should(Succeed())
}

func createUser(opts UserOptions) {
	applyYAML(buildUserYAML(opts))
}

func createUserAndWaitReady(opts UserOptions) {
	opts = opts.withDefaults()
	createUser(opts)
	waitForReady("pocketiduser", opts.Name, opts.Namespace)
}

func createUserGroup(opts UserGroupOptions) {
	applyYAML(buildUserGroupYAML(opts))
}

func createUserGroupAndWaitReady(opts UserGroupOptions) {
	opts = opts.withDefaults()
	createUserGroup(opts)
	waitForReady("pocketidusergroup", opts.Name, opts.Namespace)
}

func createAPI(opts APIOptions) {
	applyYAML(buildAPIYAML(opts))
}

func createAPIAndWaitReady(opts APIOptions) {
	opts = opts.withDefaults()
	createAPI(opts)
	waitForReady("pocketidapi", opts.Name, opts.Namespace)
}

func createOIDCClient(opts OIDCClientOptions) {
	applyYAML(buildOIDCClientYAML(opts))
}

func createOIDCClientAndWaitReady(opts OIDCClientOptions) {
	opts = opts.withDefaults()
	createOIDCClient(opts)
	waitForReady("pocketidoidcclient", opts.Name, opts.Namespace)
}

// --- Misc Helpers ---

func boolPtr(b bool) *bool {
	return &b
}

func createSecretYAML(name, namespace string, data map[string]string) string {
	var dataLines strings.Builder
	for k, v := range data {
		dataLines.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
	}

	return fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque
stringData:
%s`, name, namespace, dataLines.String())
}

// applyTLSSecret creates a kubernetes.io/tls Secret holding a self-signed certificate
// for dnsName, which is deliberately not the Service DNS name the operator dials: the
// operator must reach the instance without being able to verify the peer.
func applyTLSSecret(name, namespace, dnsName string) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: dnsName},
		DNSNames:              []string{dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	applyYAML(fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
type: kubernetes.io/tls
data:
  tls.crt: %s
  tls.key: %s
`, name, namespace,
		base64.StdEncoding.EncodeToString(certPEM),
		base64.StdEncoding.EncodeToString(keyPEM)))
}

// kubectlLogs returns a pod's logs. Logs are a subresource the typed client cannot read,
// so this is the one place the suite still needs a clientset.
func kubectlLogs(name, namespace string) string {
	stream, err := clientSet.CoreV1().Pods(namespace).GetLogs(name, &corev1.PodLogOptions{}).
		Stream(context.Background())
	if err != nil {
		return ""
	}
	defer func() { _ = stream.Close() }()

	out, err := io.ReadAll(stream)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// addUserToGroupInPocketID adds a user to a group directly via the Pocket-ID API,
// bypassing the operator. This simulates a user being added through the UI. The API
// replaces the whole membership list, so the current members are read first and the new
// user appended.
func addUserToGroupInPocketID(groupID, userID string) {
	GinkgoHelper()
	ctx, cancel := testCtx()
	defer cancel()

	group, err := pid.GetUserGroup(ctx, groupID)
	Expect(err).NotTo(HaveOccurred(), "reading group %s", groupID)

	Expect(pid.UpdateUserGroupUsers(ctx, groupID, append(group.UserIDs, userID))).
		To(Succeed(), "adding user %s to group %s", userID, groupID)
}

// createAPIInPocketID creates an API directly via the Pocket-ID API (bypassing the
// operator, simulating creation through the UI) and returns the new API's ID. Used to
// test adoption of a pre-existing API by resource.
func createAPIInPocketID(name, resource string) string {
	GinkgoHelper()
	ctx, cancel := testCtx()
	defer cancel()

	api, err := pid.CreateAPI(ctx, pocketid.APIInput{Name: name, Resource: resource})
	Expect(err).NotTo(HaveOccurred(), "creating API %q", name)
	Expect(api.ID).NotTo(BeEmpty())
	return api.ID
}

// deleteUserGroupInPocketID deletes a user group directly via the Pocket-ID API,
// simulating a group removed out-of-band (another cluster, or the UI).
func deleteUserGroupInPocketID(groupID string) {
	GinkgoHelper()
	ctx, cancel := testCtx()
	defer cancel()

	Expect(pid.DeleteUserGroup(ctx, groupID)).To(Succeed(), "deleting group %s", groupID)
}

func clientSecretsSectionFromPocketID(clientID string) string {
	body := getFromPocketID("/api/oidc/clients/" + clientID)
	section := regexp.MustCompile(`"secrets":\[[^\]]*\]`).FindString(body)
	Expect(section).NotTo(BeEmpty(),
		"a client read must carry credentials.secrets; the operator has no other source for them: %s", body)
	return section
}

// clientSecretIDsFromPocketID returns the IDs of the secrets Pocket-ID holds for a client, in the
// order the API reports them.
func clientSecretIDsFromPocketID(clientID string) []string {
	return matchAllInClientSecrets(clientSecretsSectionFromPocketID(clientID), "id")
}

// clientSecretPrefixesFromPocketID returns the clear-text prefixes Pocket-ID recorded for a
// client's secrets. The operator identifies its own credential by matching these, so how much of
// the value they carry is a contract with Pocket-ID rather than an implementation detail.
func clientSecretPrefixesFromPocketID(clientID string) []string {
	return matchAllInClientSecrets(clientSecretsSectionFromPocketID(clientID), "prefix")
}

func matchAllInClientSecrets(section, field string) []string {
	var values []string
	for _, match := range regexp.MustCompile(`"`+field+`":"([^"]*)"`).FindAllStringSubmatch(section, -1) {
		values = append(values, match[1])
	}
	return values
}

// deleteClientSecretInPocketID retires a client secret directly via the Pocket-ID API,
// simulating one revoked through the UI or by another cluster.
func deleteClientSecretInPocketID(clientID, secretID string) {
	GinkgoHelper()
	ctx, cancel := testCtx()
	defer cancel()

	Expect(pid.DeleteOIDCClientSecret(ctx, clientID, secretID)).
		To(Succeed(), "deleting secret %s of client %s", secretID, clientID)
}

func getGroupMembersFromPocketID(groupID string) string {
	GinkgoHelper()
	ctx, cancel := testCtx()
	defer cancel()

	group, err := pid.GetUserGroup(ctx, groupID)
	Expect(err).NotTo(HaveOccurred(), "reading group %s", groupID)
	return strings.Join(group.UserIDs, " ")
}
