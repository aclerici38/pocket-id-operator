//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Callback URL Preservation", Ordered, func() {
	// These tests verify that the operator does not overwrite callback URLs
	// in pocket-id when spec.callbackUrls is empty. This is critical for
	// pocket-id's TOFU (Trust On First Use) auto-detect feature, where the
	// first redirect URI used by a client is automatically saved.

	Context("Spec callback URLs are preserved across reconciles", func() {
		const clientName = "test-callback-preserve"

		It("should not lose spec callback URLs after a reconcile", func() {
			By("creating an OIDC client with callback URLs")
			createOIDCClientAndWaitReady(OIDCClientOptions{
				Name:               clientName,
				CallbackURLs:       []string{"https://preserve.example.com/callback"},
				LogoutCallbackURLs: []string{"https://preserve.example.com/logout"},
			})

			clientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

			By("verifying callback URLs are set in pocket-id")
			callbackURLs := getOIDCClientCallbackURLsFromPocketID("cb-preserve-check-pod", userNS, clientID)
			Expect(callbackURLs).To(ContainSubstring("https://preserve.example.com/callback"))

			By("triggering a reconcile by updating the spec (adding a logout URL)")
			createOIDCClient(OIDCClientOptions{
				Name:               clientName,
				CallbackURLs:       []string{"https://preserve.example.com/callback"},
				LogoutCallbackURLs: []string{"https://preserve.example.com/logout", "https://preserve.example.com/logout2"},
			})

			time.Sleep(5 * time.Second)

			By("verifying callback URLs are still set in pocket-id after reconcile")
			Eventually(func(g Gomega) {
				urls := getOIDCClientCallbackURLsFromPocketID("cb-preserve-verify-pod", userNS, clientID)
				g.Expect(urls).To(ContainSubstring("https://preserve.example.com/callback"))
			}, time.Minute, 5*time.Second).Should(Succeed())
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("Server-side callback URLs are preserved when spec omits them", func() {
		const clientName = "test-tofu-preserve"

		It("should not overwrite server-side callback URLs when spec.callbackUrls is removed", func() {
			By("creating an OIDC client with a callback URL")
			createOIDCClientAndWaitReady(OIDCClientOptions{
				Name:         clientName,
				CallbackURLs: []string{"https://initial.example.com/callback"},
			})

			clientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

			By("adding a TOFU callback URL directly to pocket-id via API")
			setOIDCClientCallbackURLsInPocketID("tofu-set-pod", userNS, clientID,
				[]string{"https://tofu-detected.example.com/callback"})

			By("verifying the TOFU callback URL is set in pocket-id")
			callbackURLs := getOIDCClientCallbackURLsFromPocketID("tofu-verify-pod", userNS, clientID)
			Expect(callbackURLs).To(ContainSubstring("https://tofu-detected.example.com/callback"))

			By("re-applying the CR without callbackUrls to trigger a reconcile")
			// The spec no longer has callbackUrls — the operator should preserve
			// whatever pocket-id has server-side rather than overwriting with empty.
			applyYAML(fmt.Sprintf(`apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: %s
  namespace: %s
spec:
  pkceEnabled: true`, clientName, userNS))

			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the TOFU callback URL is still present in pocket-id after reconcile")
			Eventually(func(g Gomega) {
				urls := getOIDCClientCallbackURLsFromPocketID("tofu-after-reconcile-pod", userNS, clientID)
				g.Expect(urls).To(ContainSubstring("https://tofu-detected.example.com/callback"),
					"server-side callback URL should be preserved across reconciles when spec omits callbackUrls")
			}, time.Minute, 5*time.Second).Should(Succeed())
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("Spec callback URLs override server-side URLs", func() {
		const clientName = "test-callback-override"

		It("should use spec callback URLs when provided, overriding server-side values", func() {
			By("creating an OIDC client with initial callback URLs")
			createOIDCClientAndWaitReady(OIDCClientOptions{
				Name:         clientName,
				CallbackURLs: []string{"https://initial.example.com/callback"},
			})

			clientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

			By("updating the spec with new callback URLs")
			createOIDCClient(OIDCClientOptions{
				Name:         clientName,
				CallbackURLs: []string{"https://updated.example.com/callback"},
			})

			By("verifying pocket-id has the updated callback URLs")
			Eventually(func(g Gomega) {
				urls := getOIDCClientCallbackURLsFromPocketID("cb-override-verify-pod", userNS, clientID)
				g.Expect(urls).To(ContainSubstring("https://updated.example.com/callback"))
				g.Expect(urls).NotTo(ContainSubstring("https://initial.example.com/callback"))
			}, time.Minute, 5*time.Second).Should(Succeed())
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})
})

// getOIDCClientCallbackURLsFromPocketID queries pocket-id directly for an OIDC client's callback URLs.
// Returns the raw JSON array string of callbackURLs.
func getOIDCClientCallbackURLsFromPocketID(podName, namespace, clientID string) string {
	staticSecretName := instanceName + "-static-api-key"

	apiKeyBase64 := kubectlGet("secret", staticSecretName, "-n", instanceNS,
		"-o", "jsonpath={.data.token}")
	ExpectWithOffset(1, apiKeyBase64).NotTo(BeEmpty(), "static API key secret should exist")

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

	// Clean up any previous pod with same name
	kubectlDelete("pod", podName, namespace)
	time.Sleep(time.Second)

	applyYAML(createCurlPodYAML(podName, namespace, script))
	logs := getPodLogs(podName, namespace)
	return logs
}

// setOIDCClientCallbackURLsInPocketID updates an OIDC client's callback URLs directly in pocket-id.
func setOIDCClientCallbackURLsInPocketID(podName, namespace, clientID string, callbackURLs []string) {
	staticSecretName := instanceName + "-static-api-key"

	apiKeyBase64 := kubectlGet("secret", staticSecretName, "-n", instanceNS,
		"-o", "jsonpath={.data.token}")
	ExpectWithOffset(1, apiKeyBase64).NotTo(BeEmpty(), "static API key secret should exist")

	// Build callback URLs JSON array
	callbackURLsJSON := "["
	for i, url := range callbackURLs {
		if i > 0 {
			callbackURLsJSON += ","
		}
		callbackURLsJSON += fmt.Sprintf(`"%s"`, url)
	}
	callbackURLsJSON += "]"

	// First GET the current client to preserve other fields in the PUT
	script := fmt.Sprintf(`API_KEY=$(echo '%s' | base64 -d)
# Get current client state
CURRENT=$(curl -s -H "X-API-KEY: $API_KEY" %s/api/oidc/clients/%s)
NAME=$(echo "$CURRENT" | sed 's/.*"name":"\([^"]*\)".*/\1/')

# Update with new callback URLs
RESPONSE=$(curl -s -X PUT -H "X-API-KEY: $API_KEY" -H "Content-Type: application/json" \
  -d "{\"name\": \"$NAME\", \"callbackURLs\": %s}" \
  -w '\n%%{http_code}' \
  %s/api/oidc/clients/%s)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
if [ "$HTTP_CODE" != "200" ]; then
  echo "Failed to update OIDC client with HTTP $HTTP_CODE: $BODY" >&2
  exit 1
fi
echo "Updated callback URLs successfully"`,
		apiKeyBase64, formatInstanceURL(), clientID, callbackURLsJSON, formatInstanceURL(), clientID)

	// Clean up any previous pod with same name
	kubectlDelete("pod", podName, namespace)
	time.Sleep(time.Second)

	applyYAML(createCurlPodYAML(podName, namespace, script))
	waitForPodSucceeded(podName, namespace)
}
