//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/aclerici38/pocket-id-operator/test/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OIDC Client Declarative Client Secret", Ordered, func() {
	// These tests cover spec.clientSecretRef: the operator pushes a user-supplied client
	// secret to Pocket-ID instead of generating one, re-pushes when the source changes, and
	// never generates or rotates the value while the ref is set.

	const (
		sourceSecretName = "declared-client-secret-source"
		sourceKey        = "oidc-client-secret"
		declaredValue    = "declared-secret-value-1"
		rotatedValue     = "declared-secret-value-2"
	)

	apply := func(yaml string) (string, error) {
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(yaml)
		return utils.Run(cmd)
	}

	sourceSecretYAML := func(value string) string {
		return fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque
stringData:
  %s: %s
`, sourceSecretName, userNS, sourceKey, value)
	}

	// declaredClientYAML builds a client referencing the source Secret. isPublic and rotation
	// drive the two admission rules that make a declared secret impossible to honour.
	declaredClientYAML := func(name string, isPublic, rotationEnabled bool) string {
		var rotation string
		if rotationEnabled {
			rotation = `
  clientSecretRotation:
    enabled: true
    interval: 720h`
		}
		return fmt.Sprintf(`apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: %s
  namespace: %s
spec:
  callbackUrls:
  - https://declared-secret-test.example.com/callback
  isPublic: %t
  clientSecretRef:
    name: %s
    key: %s%s
`, name, userNS, isPublic, sourceSecretName, sourceKey, rotation)
	}

	BeforeAll(func() {
		By("creating the Secret holding the declared client secret")
		_, err := apply(sourceSecretYAML(declaredValue))
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		kubectlDelete("secret", sourceSecretName, userNS)
	})

	Context("Declared Secret Lifecycle", func() {
		const clientName = "test-declared-secret"
		var credentialsSecret = clientName + "-oidc-credentials"

		It("should push the declared secret and store it in the generated Secret", func() {
			By("creating a PocketIDOIDCClient with clientSecretRef")
			_, err := apply(declaredClientYAML(clientName, false, false))
			Expect(err).NotTo(HaveOccurred())

			By("waiting for the client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the generated Secret holds the declared value, not a generated one")
			Eventually(func() string {
				return kubectlGetSecretData(credentialsSecret, userNS, "client_secret")
			}, time.Minute, 2*time.Second).Should(Equal(declaredValue))

			By("verifying status records the source revision that was pushed")
			version := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS,
				".status.clientSecretSourceVersion")
			Expect(version).To(HavePrefix(fmt.Sprintf("%s/%s@", sourceSecretName, sourceKey)),
				"status should identify the source Secret name and key")

			// Pocket-ID generates a secret of its own unless it honours the supplied value, and
			// stores every secret hashed, so authenticating is the only proof the declared value
			// is what it actually kept.
			By("verifying Pocket-ID accepts the declared value as the client secret")
			clientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			Expect(clientSecretAuthResult("auth-declared", userNS, clientID, declaredValue)).To(Equal("ok"))
		})

		It("should re-push after the source Secret changes", func() {
			By("recording the source revision pushed so far")
			before := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
				"-o", "jsonpath={.status.clientSecretSourceVersion}")

			By("updating the value in the source Secret")
			_, err := apply(sourceSecretYAML(rotatedValue))
			Expect(err).NotTo(HaveOccurred())

			By("verifying the new value reaches the generated Secret")
			Eventually(func() string {
				return kubectlGetSecretData(credentialsSecret, userNS, "client_secret")
			}, 3*time.Minute, 2*time.Second).Should(Equal(rotatedValue))

			By("verifying the recorded source revision advanced")
			Eventually(func() string {
				return kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
					"-o", "jsonpath={.status.clientSecretSourceVersion}")
			}, time.Minute, 2*time.Second).ShouldNot(Equal(before))

			// A push appends rather than replaces, so without retirement the value the user
			// rotated away from would keep authenticating indefinitely.
			By("verifying the new value works and the one it replaced was retired")
			clientID := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
				"-o", "jsonpath={.status.clientID}")
			Eventually(func() []string {
				return clientSecretIDsFromPocketID(
					fmt.Sprintf("list-declared-%d", time.Now().UnixNano()), userNS, clientID)
			}, time.Minute, 10*time.Second).Should(HaveLen(1))
			Expect(clientSecretAuthResult("auth-declared-new", userNS, clientID, rotatedValue)).To(Equal("ok"))
			Expect(clientSecretAuthResult("auth-declared-old", userNS, clientID, declaredValue)).
				To(Equal("invalid_client"))
		})

		It("should ignore the regenerate-client-secret annotation", func() {
			By("setting the regenerate-client-secret annotation")
			Expect(kubectlAnnotate("pocketidoidcclient", clientName, userNS,
				"pocketid.internal/regenerate-client-secret=true")).To(Succeed())

			By("waiting for the operator to consume and remove the annotation")
			Eventually(func() string {
				return kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
					"-o", "jsonpath={.metadata.annotations.pocketid\\.internal/regenerate-client-secret}")
			}, 2*time.Minute, 2*time.Second).Should(BeEmpty())

			By("verifying the declared secret was not regenerated")
			Consistently(func() string {
				return kubectlGetSecretData(credentialsSecret, userNS, "client_secret")
			}, 15*time.Second, 3*time.Second).Should(Equal(rotatedValue))
		})

		It("should report an error when the referenced key is missing", func() {
			By("pointing clientSecretRef at a key that does not exist")
			Expect(kubectlPatch("pocketidoidcclient", clientName, userNS,
				`{"spec":{"clientSecretRef":{"name":"`+sourceSecretName+`","key":"absent-key"}}}`)).To(Succeed())

			By("verifying the client reports the sync failure rather than generating a secret")
			waitForConditionReason("pocketidoidcclient", clientName, userNS, "Ready", "ClientSecretSyncError")
			Expect(kubectlGetSecretData(credentialsSecret, userNS, "client_secret")).To(Equal(rotatedValue),
				"the previously declared secret should be left untouched")
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})
})
