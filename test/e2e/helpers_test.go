//go:build e2e
// +build e2e

package e2e

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/gomega"

	"github.com/aclerici38/pocket-id-operator/test/utils"
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
	Name                      string
	Namespace                 string
	Labels                    map[string]string
	Image                     string
	DisableGlobalRateLimiting *bool
	PersistenceEnabled        *bool
	PersistenceSize           string
	ExistingClaim             string
}

func (o InstanceOptions) withDefaults() InstanceOptions {
	if o.Name == "" {
		o.Name = instanceName
	}
	if o.Namespace == "" {
		o.Namespace = instanceNS
	}
	if o.Image == "" {
		o.Image = "ghcr.io/pocket-id/pocket-id:latest"
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

	var rateLimiting string
	if opts.DisableGlobalRateLimiting != nil {
		rateLimiting = fmt.Sprintf("  disableGlobalRateLimiting: %t\n", *opts.DisableGlobalRateLimiting)
	}

	return fmt.Sprintf(`apiVersion: pocketid.internal/v1alpha1
kind: PocketIDInstance
metadata:
  name: %s
  namespace: %s
%sspec:
  image: %s
%s  encryptionKey:
    valueFrom:
      secretKeyRef:
        name: pocket-id-encryption
        key: key
  appUrl: "http://%s.%s.svc.cluster.local:1411"
%s`, opts.Name, opts.Namespace, labels, opts.Image, rateLimiting, opts.Name, opts.Namespace, persistence)
}

// UserOptions configures a PocketIDUser YAML.
type UserOptions struct {
	Name             string
	Namespace        string
	Username         string
	FirstName        string
	LastName         string
	Email            string
	DisplayName      string
	Admin            *bool
	APIKeys          []APIKeySpec
	UserInfoSecret   string
	InstanceSelector map[string]string
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

	var spec strings.Builder

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
`, opts.Name, opts.Namespace)
	}

	return fmt.Sprintf(`apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
spec:
%s`, opts.Name, opts.Namespace, specStr)
}

// UserGroupOptions configures a PocketIDUserGroup YAML.
type UserGroupOptions struct {
	Name         string
	Namespace    string
	GroupName    string
	FriendlyName string
	CustomClaims []CustomClaim
	UserRefs     []ResourceRef
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

	if len(opts.UserRefs) > 0 {
		spec.WriteString("  users:\n")
		spec.WriteString("    userRefs:\n")
		for _, ref := range opts.UserRefs {
			spec.WriteString(fmt.Sprintf("    - name: %s\n", ref.Name))
			if ref.Namespace != "" {
				spec.WriteString(fmt.Sprintf("      namespace: %s\n", ref.Namespace))
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
	CallbackURLs       []string
	LogoutCallbackURLs []string
	IsPublic           bool
	AllowedUserGroups  []string
	Secret             *OIDCSecretConfig
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
	if len(o.CallbackURLs) == 0 {
		o.CallbackURLs = []string{"https://example.com/callback"}
	}
	return o
}

func buildOIDCClientYAML(opts OIDCClientOptions) string {
	opts = opts.withDefaults()

	var spec strings.Builder

	if opts.IsPublic {
		spec.WriteString("  isPublic: true\n")
	}

	spec.WriteString("  callbackUrls:\n")
	for _, url := range opts.CallbackURLs {
		spec.WriteString(fmt.Sprintf("  - %s\n", url))
	}

	if len(opts.LogoutCallbackURLs) > 0 {
		spec.WriteString("  logoutCallbackUrls:\n")
		for _, url := range opts.LogoutCallbackURLs {
			spec.WriteString(fmt.Sprintf("  - %s\n", url))
		}
	}

	if len(opts.AllowedUserGroups) > 0 {
		spec.WriteString("  allowedUserGroups:\n")
		for _, group := range opts.AllowedUserGroups {
			spec.WriteString(fmt.Sprintf("  - name: %s\n", group))
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
				spec.WriteString(fmt.Sprintf("      clientId: %s\n", opts.Secret.Keys.ClientID))
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

	return fmt.Sprintf(`apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: %s
  namespace: %s
spec:
%s`, opts.Name, opts.Namespace, spec.String())
}

// --- kubectl Helpers ---

func applyYAML(yaml string) {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yaml)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred())
}

func kubectlGet(args ...string) string {
	fullArgs := append([]string{"get"}, args...)
	cmd := exec.Command("kubectl", fullArgs...)
	output, err := utils.Run(cmd)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(output)
}

func kubectlGetSecretData(secretName, namespace, key string) string {
	output := kubectlGet("secret", secretName, "-n", namespace,
		"-o", fmt.Sprintf("jsonpath={.data.%s}", key))
	if output == "" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(output)
	if err != nil {
		return ""
	}
	return string(decoded)
}

func kubectlDelete(resource, name, namespace string) {
	cmd := exec.Command("kubectl", "delete", resource, name, "-n", namespace, "--ignore-not-found")
	_, _ = utils.Run(cmd)
}

func kubectlDeleteWait(resource, name, namespace string, timeout time.Duration) error {
	cmd := exec.Command("kubectl", "delete", resource, name, "-n", namespace,
		"--ignore-not-found", fmt.Sprintf("--timeout=%s", timeout))
	_, err := utils.Run(cmd)
	return err
}

func kubectlAnnotate(resource, name, namespace, annotation string) error {
	cmd := exec.Command("kubectl", "annotate", resource, name, "-n", namespace, annotation, "--overwrite")
	_, err := utils.Run(cmd)
	return err
}

func removeFinalizers(namespace string) {
	cmd := exec.Command("bash", "-c",
		fmt.Sprintf("kubectl get pocketiduser,pocketidusergroup,pocketidoidcclient,pocketidinstance -n %s -o name 2>/dev/null | xargs -I {} kubectl patch {} -n %s --type=merge -p '{\"metadata\":{\"finalizers\":null}}' 2>/dev/null || true",
			namespace, namespace))
	_, _ = utils.Run(cmd)
}

// --- Wait Helpers ---

func waitForReady(resource, name, namespace string) {
	waitForCondition(resource, name, namespace, "Ready", "True")
}

func waitForCondition(resource, name, namespace, conditionType, status string) {
	Eventually(func(g Gomega) {
		output := kubectlGet(resource, name, "-n", namespace,
			"-o", fmt.Sprintf("jsonpath={.status.conditions[?(@.type=='%s')].status}", conditionType))
		g.Expect(output).To(Equal(status), "%s/%s should have condition %s=%s", resource, name, conditionType, status)
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
}

func waitForConditionReason(resource, name, namespace, conditionType, reason string) {
	Eventually(func(g Gomega) {
		output := kubectlGet(resource, name, "-n", namespace,
			"-o", fmt.Sprintf("jsonpath={.status.conditions[?(@.type=='%s')].reason}", conditionType))
		g.Expect(output).To(Equal(reason))
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
}

func waitForStatusField(resource, name, namespace, jsonpath, expected string) {
	Eventually(func(g Gomega) {
		output := kubectlGet(resource, name, "-n", namespace, "-o", fmt.Sprintf("jsonpath={%s}", jsonpath))
		g.Expect(output).To(Equal(expected))
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
}

func waitForStatusFieldNotEmpty(resource, name, namespace, jsonpath string) string {
	var result string
	Eventually(func(g Gomega) {
		result = kubectlGet(resource, name, "-n", namespace, "-o", fmt.Sprintf("jsonpath={%s}", jsonpath))
		g.Expect(result).NotTo(BeEmpty())
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

func waitForResourceDeleted(resource, name, namespace string) {
	Eventually(func(g Gomega) {
		output := kubectlGet(resource, name, "-n", namespace, "-o", "name")
		g.Expect(output).To(BeEmpty())
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
}

func waitForSecretExists(secretName, namespace string) {
	Eventually(func(g Gomega) {
		output := kubectlGet("secret", secretName, "-n", namespace, "-o", "name")
		g.Expect(output).To(Equal("secret/" + secretName))
	}, time.Minute, 2*time.Second).Should(Succeed())
}

func waitForSecretNotExists(secretName, namespace string) {
	Eventually(func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "secret", secretName, "-n", namespace)
		_, err := utils.Run(cmd)
		g.Expect(err).To(HaveOccurred())
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
		output := kubectlGet("pocketidinstance", opts.Name, "-n", opts.Namespace,
			"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
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
	waitForStatusFieldNotEmpty("pocketidusergroup", opts.Name, opts.Namespace, ".status.groupId")
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

func createPVCYAML(name, namespace, size string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: %s
  namespace: %s
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: %s
`, name, namespace, size)
}

func createCurlPodYAML(name, namespace, script string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  restartPolicy: Never
  containers:
  - name: curl
    image: curlimages/curl:latest
    command: ["/bin/sh", "-c"]
    args:
    - |
%s
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      runAsUser: 1000
`, name, namespace, indentScript(script, 6))
}

func indentScript(script string, spaces int) string {
	indent := strings.Repeat(" ", spaces)
	lines := strings.Split(script, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = indent + line
		}
	}
	return strings.Join(lines, "\n")
}

func waitForPodSucceeded(name, namespace string) {
	Eventually(func(g Gomega) {
		output := kubectlGet("pod", name, "-n", namespace, "-o", "jsonpath={.status.phase}")
		g.Expect(output).To(Equal("Succeeded"))
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
}
