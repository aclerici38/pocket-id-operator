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

			By("verifying callback URLs appear in status")
			Eventually(func(g Gomega) {
				urls := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
					"-o", "jsonpath={.status.callbackUrls}")
				g.Expect(urls).To(ContainSubstring("https://preserve.example.com/callback"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("triggering a reconcile by updating the spec (adding a logout URL)")
			createOIDCClient(OIDCClientOptions{
				Name:               clientName,
				CallbackURLs:       []string{"https://preserve.example.com/callback"},
				LogoutCallbackURLs: []string{"https://preserve.example.com/logout", "https://preserve.example.com/logout2"},
			})

			time.Sleep(5 * time.Second)

			By("verifying callback URLs are still in status after reconcile")
			Eventually(func(g Gomega) {
				urls := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
					"-o", "jsonpath={.status.callbackUrls}")
				g.Expect(urls).To(ContainSubstring("https://preserve.example.com/callback"))
			}, time.Minute, 5*time.Second).Should(Succeed())
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("TOFU callback URLs are preserved when spec has no callbackUrls", func() {
		const clientName = "test-tofu-preserve"

		It("should not overwrite pocket-id TOFU callback URLs on reconcile", func() {
			By("creating an OIDC client without any callbackUrls in the spec")
			applyYAML(fmt.Sprintf(`apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: %s
  namespace: %s
spec: {}`, clientName, userNS))

			waitForReady("pocketidoidcclient", clientName, userNS)
			clientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

			By("simulating TOFU: setting a callback URL directly in pocket-id via API")
			setOIDCClientCallbackURLsInPocketID("tofu-set-pod", userNS, clientID, clientName,
				[]string{"https://tofu-detected.example.com/callback"})

			By("triggering a reconcile via annotation change")
			err := kubectlAnnotate("pocketidoidcclient", clientName, userNS, "test/trigger=reconcile")
			Expect(err).NotTo(HaveOccurred())

			By("verifying the TOFU callback URL appears in status after reconcile")
			Eventually(func(g Gomega) {
				urls := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
					"-o", "jsonpath={.status.callbackUrls}")
				g.Expect(urls).To(ContainSubstring("https://tofu-detected.example.com/callback"),
					"TOFU callback URL must survive operator reconcile when spec has no callbackUrls")
			}, time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the TOFU callback URL persists across multiple reconciles")
			Consistently(func(g Gomega) {
				urls := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
					"-o", "jsonpath={.status.callbackUrls}")
				g.Expect(urls).To(ContainSubstring("https://tofu-detected.example.com/callback"),
					"TOFU callback URL must not be wiped by subsequent reconciles")
			}, 20*time.Second, 5*time.Second).Should(Succeed())
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

			By("verifying initial callback URLs appear in status")
			Eventually(func(g Gomega) {
				urls := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
					"-o", "jsonpath={.status.callbackUrls}")
				g.Expect(urls).To(ContainSubstring("https://initial.example.com/callback"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("updating the spec with new callback URLs")
			createOIDCClient(OIDCClientOptions{
				Name:         clientName,
				CallbackURLs: []string{"https://updated.example.com/callback"},
			})

			By("verifying status reflects the updated callback URLs")
			Eventually(func(g Gomega) {
				urls := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
					"-o", "jsonpath={.status.callbackUrls}")
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

// setOIDCClientCallbackURLsInPocketID updates an OIDC client's callback URLs directly in pocket-id.
// clientName is the pocket-id display name (same as the CR metadata.name).
func setOIDCClientCallbackURLsInPocketID(podName, namespace, clientID, clientName string, callbackURLs []string) {
	staticSecretName := instanceName + "-static-api-key"

	apiKeyBase64 := kubectlGet("secret", staticSecretName, "-n", instanceNS,
		"-o", "jsonpath={.data.token}")
	ExpectWithOffset(1, apiKeyBase64).NotTo(BeEmpty(), "static API key secret should exist")

	// Build the complete update DTO JSON in Go — only "name" is required
	callbackURLsJSON := "["
	for i, url := range callbackURLs {
		if i > 0 {
			callbackURLsJSON += ","
		}
		callbackURLsJSON += fmt.Sprintf(`"%s"`, url)
	}
	callbackURLsJSON += "]"

	updateBody := fmt.Sprintf(`{"name":"%s","callbackURLs":%s}`, clientName, callbackURLsJSON)

	script := fmt.Sprintf(`API_KEY=$(echo '%s' | base64 -d)

RESPONSE=$(curl -s -X PUT -H "X-API-KEY: $API_KEY" -H "Content-Type: application/json" \
  -d '%s' \
  -w '\n%%{http_code}' \
  %s/api/oidc/clients/%s)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
if [ "$HTTP_CODE" != "200" ]; then
  echo "Failed to update OIDC client with HTTP $HTTP_CODE: $BODY" >&2
  exit 1
fi
echo "Updated callback URLs successfully"`,
		apiKeyBase64, updateBody, formatInstanceURL(), clientID)

	// Clean up any previous pod with same name
	kubectlDelete("pod", podName, namespace)
	time.Sleep(time.Second)

	applyYAML(createCurlPodYAML(podName, namespace, script))
	waitForPodSucceeded(podName, namespace)
}
