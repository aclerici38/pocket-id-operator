//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Pocket-ID validates its app-config environment variables while it boots and
// aborts with "invalid environment app configuration" when any value is
// malformed (upstream commit 9e637d5, first released in v2.14.0). Unit tests on
// buildEnvVars only assert what the operator emits, not whether Pocket-ID
// accepts it, so this spec applies an instance that populates every
// env-producing field and requires the real container to come up.
//
// Regression cover for issue #583: SIGNUP_DEFAULT_USER_GROUP_IDS was emitted
// comma-separated instead of as a JSON array, which crash-looped the pod on
// v2.14.0 while every unit test still passed.
const envRejectedMarker = "invalid environment app configuration"

// Group IDs are never resolved here because no signup happens during the spec;
// they only have to survive Pocket-ID's json_string_array check.
var maximalSignupGroupIDs = []string{
	"3f2504e0-4f89-11d3-9a0c-0305e82c3301",
	"3f2504e0-4f89-11d3-9a0c-0305e82c3302",
}

var _ = Describe("PocketIDInstance Maximal Environment", Serial, Ordered, func() {
	const maximalInstance = "maximal-env-instance"

	BeforeAll(func() {
		// A leftover second instance would break every later spec that selects the
		// shared instance without a selector, so clean up even on failure.
		DeferCleanup(func() {
			_ = kubectlDeleteWait("pocketidinstance", maximalInstance, instanceNS, 60*time.Second)
		})

		By("applying an instance that populates every env-producing field")
		applyYAML(maximalInstanceYAML(maximalInstance, instanceNS))

		By("waiting for Pocket-ID to accept the environment and become Ready")
		Eventually(func(g Gomega) {
			// Fail immediately rather than burning the full timeout: once
			// Pocket-ID has rejected a variable it exits, and the pod only
			// crash-loops from here.
			if logs := kubectlLogs(pocketIDPodName(maximalInstance), instanceNS); strings.Contains(logs, envRejectedMarker) {
				StopTrying("Pocket-ID rejected the operator's environment").
					Attach("pocket-id logs", logs).
					Now()
			}
			status := kubectlGet("pocketidinstance", maximalInstance, "-n", instanceNS,
				"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
			g.Expect(status).To(Equal("True"))
		}, 5*time.Minute, 5*time.Second).Should(Succeed())
	})

	It("should not have logged an app config validation failure", func() {
		logs := kubectlLogs(pocketIDPodName(maximalInstance), instanceNS)
		Expect(logs).NotTo(ContainSubstring(envRejectedMarker))
	})

	It("should not have restarted the container", func() {
		restarts := kubectlGet("pod", pocketIDPodName(maximalInstance), "-n", instanceNS,
			"-o", "jsonpath={.status.containerStatuses[0].restartCount}")
		Expect(restarts).To(Equal("0"), "Pocket-ID restarted, which a rejected environment causes")
	})

	It("should emit SIGNUP_DEFAULT_USER_GROUP_IDS as a JSON array", func() {
		value := kubectlGet("deployment", maximalInstance, "-n", instanceNS,
			"-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name=='SIGNUP_DEFAULT_USER_GROUP_IDS')].value}")
		Expect(value).To(Equal(fmt.Sprintf(`["%s","%s"]`, maximalSignupGroupIDs[0], maximalSignupGroupIDs[1])))
	})
})

// pocketIDPodName returns the pod backing the named instance, or "" while it is
// still being created.
func pocketIDPodName(instance string) string {
	return kubectlGet("pod", "-n", instanceNS,
		"-l", "app.kubernetes.io/instance="+instance,
		"-o", "jsonpath={.items[0].metadata.name}")
}

// maximalInstanceYAML renders an instance that sets every spec field the
// operator turns into an environment variable. External endpoints (SMTP, LDAP,
// the OTLP collector) are deliberately unreachable: Pocket-ID validates those
// variables at startup but only dials them lazily, and LDAP sync logs failures
// instead of returning them, so an unroutable host still exercises the
// validation without needing real infrastructure.
func maximalInstanceYAML(name, namespace string) string {
	return fmt.Sprintf(`apiVersion: pocketid.internal/v1alpha1
kind: PocketIDInstance
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  image: %[3]s
  appUrl: "http://%[1]s.%[2]s.svc:1411"
  internalAppUrl: "http://%[1]s.%[2]s.svc:1411"
  encryptionKey:
    valueFrom:
      secretKeyRef:
        name: pocket-id-encryption
        key: key
  fileBackend: filesystem
  analyticsDisabled: true
  versionCheckDisabled: true
  rateLimitingDisabled: true
  auditLogRetentionDays: 30
  localIPv6Ranges: "fd00::/8"
  timezone: "UTC"
  trustedProxies:
    enabled: true
    cidrs:
    - "10.0.0.0/8"
    - "192.168.0.0/16"
  metrics:
    enabled: true
    port: 9464
  logging:
    level: info
    json: true
    queryArgs: true
  tracing:
    endpoint: "http://otel-collector.observability.svc:4318/v1/traces"
  geoip:
    dbPath: "/tmp/GeoLite2-City.mmdb"
  ui:
    appName: "E2E Maximal"
    sessionDuration: 60
    homePageUrl: "/settings/account"
    disableAnimations: true
    accentColor: "default"
  userManagement:
    emailsVerified: true
    allowOwnAccountEdit: false
    allowUserSignups: "withToken"
    signupDefaultCustomClaims: '[{"key":"department","value":"platform"}]'
    signupDefaultUserGroupIds:
    - "%[4]s"
    - "%[5]s"
  webauthn:
    userVerification: "preferred"
    allowSyncedPasskeys: false
    authenticatorAttachment: "cross-platform"
  smtp:
    host: "smtp.invalid"
    port: 587
    from: "noreply@example.com"
    user: "pocket-id"
    password:
      value: "smtp-password"
    tls: "starttls"
    skipCertVerify: true
  emailNotifications:
    loginNotification: true
    oneTimeAccessAsAdmin: true
    apiKeyExpiration: true
    oneTimeAccessAsUnauthenticated: true
    verification: true
  ldap:
    url: "ldap://ldap.invalid:389"
    bindDN: "cn=admin,dc=example,dc=com"
    bindPassword:
      value: "ldap-password"
    base: "dc=example,dc=com"
    skipCertVerify: true
    softDeleteUsers: true
    adminGroupName: "pocket-id-admins"
    userSearchFilter: "(objectClass=person)"
    userGroupSearchFilter: "(objectClass=groupOfNames)"
    attributeMapping:
      userUniqueIdentifier: "uuid"
      userUsername: "uid"
      userEmail: "mail"
      userFirstName: "givenName"
      userLastName: "sn"
      userProfilePicture: "jpegPhoto"
      groupMember: "member"
      groupUniqueIdentifier: "uuid"
      groupName: "cn"
  cimdUrlAllowlist:
  - "%[6]s"
`, name, namespace, pocketIDImage(), maximalSignupGroupIDs[0], maximalSignupGroupIDs[1], cimdMetadataURL)
}
