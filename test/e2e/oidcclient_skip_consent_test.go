//go:build e2e
// +build e2e

package e2e

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OIDC Client Skip Consent", Ordered, func() {
	// Verifies that spec.skipConsent is actually persisted by Pocket-ID, not just
	// mapped into the operator's input. The value is read back from the Pocket-ID
	// API to confirm the full round-trip (serialize -> store -> return).

	const clientName = "test-skip-consent"

	It("should propagate spec.skipConsent to Pocket-ID", func() {
		By("creating a PocketIDOIDCClient with skipConsent: true")
		createOIDCClient(OIDCClientOptions{
			Name:         clientName,
			SkipConsent:  true,
			CallbackURLs: []string{"https://skip-consent.example.com/callback"},
		})

		By("waiting for the client to be ready")
		waitForReady("pocketidoidcclient", clientName, userNS)

		By("capturing the client ID from status")
		clientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

		By("verifying Pocket-ID reports skipConsent: true for the client")
		body := getOIDCClientFromPocketID("skip-consent-verify", userNS, clientID)
		Expect(body).To(ContainSubstring(`"skipConsent":true`),
			"Pocket-ID should persist and return skipConsent: true")
	})

	AfterAll(func() {
		kubectlDelete("pocketidoidcclient", clientName, userNS)
		waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
	})
})

// getOIDCClientFromPocketID fetches a single OIDC client from the Pocket-ID API
// via a curl pod and returns the raw JSON response body.
func getOIDCClientFromPocketID(podName, namespace, clientID string) string {
	staticSecretName := instanceName + "-static-api-key"

	apiKeyBase64 := kubectlGet("secret", staticSecretName, "-n", instanceNS,
		"-o", "jsonpath={.data.token}")
	Expect(apiKeyBase64).NotTo(BeEmpty(), "static API key secret should exist")

	script := fmt.Sprintf(`API_KEY=$(echo '%s' | base64 -d)
RESPONSE=$(curl -s -H "X-API-KEY: $API_KEY" \
  -w '\n%%{http_code}' \
  %s/api/oidc/clients/%s)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
if [ "$HTTP_CODE" != "200" ]; then
  echo "Failed to get OIDC client with HTTP $HTTP_CODE: $BODY" >&2
  exit 1
fi
echo "$BODY"`,
		apiKeyBase64, formatInstanceURL(), clientID)

	applyYAML(createCurlPodYAML(podName, namespace, script))
	body := getPodLogs(podName, namespace)
	kubectlDelete("pod", podName, namespace)
	return body
}
