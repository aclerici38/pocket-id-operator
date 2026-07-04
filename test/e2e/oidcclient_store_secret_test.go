//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/aclerici38/pocket-id-operator/test/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OIDC Client storeClientSecret Validation", Ordered, func() {
	// These tests verify the CEL rule that rejects enabling clientSecretRotation
	// while secret.storeClientSecret is false: a rotation would regenerate a
	// client secret whose value is then discarded.

	const celMessage = "clientSecretRotation cannot be enabled when secret.storeClientSecret is false"

	storeSecretClientYAML := func(name string, rotationEnabled bool) string {
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
  - https://store-secret-test.example.com/callback
  secret:
    storeClientSecret: false%s
`, name, userNS, rotation)
	}

	apply := func(yaml string) (string, error) {
		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(yaml)
		return utils.Run(cmd)
	}

	Context("Rotation Enabled With storeClientSecret False", func() {
		const clientName = "test-store-secret-rejected"

		It("should reject creating a client with rotation enabled and storeClientSecret false", func() {
			By("applying a PocketIDOIDCClient with clientSecretRotation.enabled and secret.storeClientSecret=false")
			output, err := apply(storeSecretClientYAML(clientName, true))
			Expect(err).To(HaveOccurred(), "apply should fail CEL validation")
			Expect(output).To(ContainSubstring(celMessage),
				"error should indicate rotation cannot be enabled without storing the client secret")
		})
	})

	Context("Enabling Rotation On An Existing storeClientSecret=false Client", func() {
		const clientName = "test-store-secret-update"

		It("should accept storeClientSecret false without rotation, then reject enabling rotation", func() {
			By("creating a PocketIDOIDCClient with secret.storeClientSecret=false and no rotation")
			_, err := apply(storeSecretClientYAML(clientName, false))
			Expect(err).NotTo(HaveOccurred(), "storeClientSecret=false without rotation should be admitted")

			By("attempting to enable clientSecretRotation on the same client")
			output, err := apply(storeSecretClientYAML(clientName, true))
			Expect(err).To(HaveOccurred(), "update should fail CEL validation")
			Expect(output).To(ContainSubstring(celMessage),
				"error should indicate rotation cannot be enabled without storing the client secret")
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})
})
