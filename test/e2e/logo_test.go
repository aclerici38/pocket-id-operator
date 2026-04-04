//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Logo Auto-Generation", Ordered, func() {
	// These tests verify that the operator correctly resolves logo URLs
	// and applies them to the OIDC client in Pocket-ID.
	// The e2e overlay disables auto-generation globally, so these tests
	// explicitly opt in via spec.logo.autoGenerate.

	Context("Auto-generated logos", func() {
		const clientName = "test-logo-autogen"

		It("should apply logos when autoGenerate is enabled with a known icon name", func() {
			By("creating an OIDC client with logo auto-generation enabled")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				Logo: &OIDCLogoConfig{
					AutoGenerate: boolPtr(true),
					NameOverride: "grafana",
				},
			}))

			By("waiting for the client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the logo was applied in Pocket-ID")
			oidcClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			Eventually(func(g Gomega) {
				hasLogo := getOIDCClientField("verify-logo-autogen", userNS, oidcClientID, "hasLogo")
				g.Expect(hasLogo).To(Equal("true"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the logo status fields are set")
			logoURL := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
				"-o", "jsonpath={.status.logoUrl}")
			Expect(logoURL).To(ContainSubstring("grafana"))

			logoReachable := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
				"-o", "jsonpath={.status.logoReachable}")
			Expect(logoReachable).To(Equal("true"))
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("Auto-generation disabled", func() {
		const clientName = "test-logo-disabled"

		It("should not set logos when autoGenerate is false", func() {
			By("creating an OIDC client with logo auto-generation explicitly disabled")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				Logo: &OIDCLogoConfig{
					AutoGenerate: boolPtr(false),
				},
			}))

			By("waiting for the client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying no logo was applied in Pocket-ID")
			oidcClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			hasLogo := getOIDCClientField("verify-logo-disabled", userNS, oidcClientID, "hasLogo")
			Expect(hasLogo).To(Equal("false"))
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})
})

// getOIDCClientField queries the Pocket-ID API for a field on an OIDC client.
func getOIDCClientField(podName, namespace, oidcClientID, field string) string {
	staticSecretName := instanceName + "-static-api-key"
	apiKeyBase64 := kubectlGet("secret", staticSecretName, "-n", instanceNS,
		"-o", "jsonpath={.data.token}")
	Expect(apiKeyBase64).NotTo(BeEmpty(), "static API key secret should exist")

	script := fmt.Sprintf(`API_KEY=$(echo '%s' | base64 -d)
RESPONSE=$(curl -s -w '\n%%{http_code}' -H "X-API-KEY: $API_KEY" \
  %s/api/oidc/clients/%s)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
if [ "$HTTP_CODE" != "200" ]; then
  echo "Unexpected HTTP $HTTP_CODE: $BODY" >&2
  exit 1
fi
echo "$BODY" | sed 's/.*"%s":\([^,}]*\).*/\1/'`,
		apiKeyBase64, formatInstanceURL(), oidcClientID, field)

	kubectlDelete("pod", podName, namespace)
	applyYAML(createCurlPodYAML(podName, namespace, script))
	waitForPodSucceeded(podName, namespace)
	return kubectlLogs(podName, namespace)
}
