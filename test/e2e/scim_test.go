//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SCIM Service Provider", Ordered, func() {
	// These tests verify that the operator correctly manages SCIM service provider
	// configurations in Pocket-ID when spec.scim is set on a PocketIDOIDCClient.

	Context("Basic SCIM lifecycle", func() {
		const clientName = "test-scim-basic"

		It("should create a SCIM service provider when spec.scim is set", func() {
			By("creating an OIDC client with a SCIM endpoint")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				SCIM: &SCIMConfig{
					Endpoint: "https://scim.example.com/v2",
				},
			}))

			By("waiting for the OIDC client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the SCIM provider ID is populated in status")
			scimID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.scimProviderID")
			Expect(scimID).NotTo(BeEmpty())

			By("verifying the SCIM provider exists in Pocket-ID via API")
			oidcClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			scimEndpoint := getSCIMProviderEndpoint("verify-scim-basic", userNS, oidcClientID)
			Expect(scimEndpoint).To(Equal("https://scim.example.com/v2"))
		})

		It("should update the SCIM service provider when the endpoint changes", func() {
			By("updating the OIDC client with a new SCIM endpoint")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				SCIM: &SCIMConfig{
					Endpoint: "https://scim-updated.example.com/v2",
				},
			}))

			By("waiting for the change to propagate")
			oidcClientID := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
				"-o", "jsonpath={.status.clientID}")
			Eventually(func(g Gomega) {
				endpoint := getSCIMProviderEndpoint("verify-scim-update", userNS, oidcClientID)
				g.Expect(endpoint).To(Equal("https://scim-updated.example.com/v2"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the OIDC client is still ready")
			waitForReady("pocketidoidcclient", clientName, userNS)
		})

		It("should delete the SCIM service provider when spec.scim is removed", func() {
			By("getting the current SCIM provider ID")
			scimID := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
				"-o", "jsonpath={.status.scimProviderID}")
			Expect(scimID).NotTo(BeEmpty())

			By("removing spec.scim from the OIDC client")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
			}))

			By("waiting for the SCIM provider ID to be cleared from status")
			Eventually(func(g Gomega) {
				id := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
					"-o", "jsonpath={.status.scimProviderID}")
				g.Expect(id).To(BeEmpty())
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the OIDC client is still ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the SCIM provider no longer exists in Pocket-ID")
			oidcClientID := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
				"-o", "jsonpath={.status.clientID}")
			scimExists := checkSCIMProviderExists("verify-scim-deleted", userNS, oidcClientID)
			Expect(scimExists).To(BeFalse())
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("SCIM with bearer token from Secret", func() {
		const clientName = "test-scim-token"
		const secretName = "scim-bearer-token"

		BeforeAll(func() {
			By("creating the bearer token Secret")
			applyYAML(createSecretYAML(secretName, userNS, map[string]string{
				"token": "my-super-secret-token",
			}))
		})

		It("should create a SCIM provider using a bearer token from a Secret", func() {
			By("creating an OIDC client with SCIM and token reference")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				SCIM: &SCIMConfig{
					Endpoint: "https://scim.example.com/v2",
					TokenSecretRef: &SecretKeyRef{
						Name: secretName,
						Key:  "token",
					},
				},
			}))

			By("waiting for the OIDC client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the SCIM provider ID is populated in status")
			scimID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.scimProviderID")
			Expect(scimID).NotTo(BeEmpty())

			By("verifying the SCIM provider was created in Pocket-ID")
			oidcClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			scimEndpoint := getSCIMProviderEndpoint("verify-scim-token", userNS, oidcClientID)
			Expect(scimEndpoint).To(Equal("https://scim.example.com/v2"))
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
			kubectlDelete("secret", secretName, userNS)
		})
	})

	Context("SCIM deletion on OIDC client delete", func() {
		const clientName = "test-scim-delete-cleanup"

		It("should delete the SCIM provider when the OIDC client CR is deleted", func() {
			By("creating an OIDC client with SCIM configured")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				SCIM: &SCIMConfig{
					Endpoint: "https://scim-cleanup.example.com/v2",
				},
			}))

			By("waiting for the OIDC client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("recording the OIDC client ID and SCIM provider ID")
			oidcClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			scimID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.scimProviderID")
			Expect(scimID).NotTo(BeEmpty())

			By("deleting the OIDC client CR")
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)

			By("verifying the SCIM provider no longer exists in Pocket-ID")
			Eventually(func(g Gomega) {
				kubectlDelete("pod", "verify-scim-gone-after-oidc-delete", userNS)
				gone := checkSCIMProviderGone("verify-scim-gone-after-oidc-delete", userNS, oidcClientID)
				g.Expect(gone).To(BeTrue(), "SCIM provider should be deleted after OIDC client deletion")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("SCIM adoption of existing provider", func() {
		const clientName = "test-scim-adopt"

		It("should adopt a pre-existing SCIM provider when taking over an existing OIDC client", func() {
			By("creating an OIDC client directly in Pocket-ID with a SCIM provider")
			pocketIDClientID := "scim-adopt-test-client"
			createOIDCClientInPocketID("create-adopt-scim-oidc", userNS, pocketIDClientID, "SCIM Adopt Test",
				[]string{"https://adopt-scim.example.com/callback"})
			scimID := createSCIMProviderInPocketID("create-adopt-scim-provider", userNS, pocketIDClientID,
				"https://scim-pre-existing.example.com/v2")

			By("creating a PocketIDOIDCClient CR with spec.scim set, adopting the existing OIDC client")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name:     clientName,
				ClientID: pocketIDClientID,
				SCIM: &SCIMConfig{
					Endpoint: "https://scim-pre-existing.example.com/v2",
				},
			}))

			By("waiting for the OIDC client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the operator adopted the existing SCIM provider (same ID)")
			adoptedSCIMID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.scimProviderID")
			Expect(adoptedSCIMID).To(Equal(scimID), "operator should adopt the pre-existing SCIM provider")
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("SCIM stale cleanup on adoption without spec.scim", func() {
		const clientName = "test-scim-stale-cleanup"

		It("should delete a stale SCIM provider when adopting an OIDC client without spec.scim", func() {
			By("creating an OIDC client directly in Pocket-ID with a SCIM provider")
			pocketIDClientID := "scim-stale-cleanup-client"
			createOIDCClientInPocketID("create-stale-scim-oidc", userNS, pocketIDClientID, "SCIM Stale Cleanup Test",
				[]string{"https://stale-scim.example.com/callback"})
			scimID := createSCIMProviderInPocketID("create-stale-scim-provider", userNS, pocketIDClientID,
				"https://scim-stale.example.com/v2")

			By("creating a PocketIDOIDCClient CR without spec.scim, adopting the existing OIDC client")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name:     clientName,
				ClientID: pocketIDClientID,
				// Note: no SCIM spec — operator should clean up the stale SCIM provider
			}))

			By("waiting for the OIDC client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the stale SCIM provider was deleted from Pocket-ID")
			_ = scimID
			Eventually(func(g Gomega) {
				kubectlDelete("pod", "verify-stale-scim-gone", userNS)
				gone := checkSCIMProviderGone("verify-stale-scim-gone", userNS, pocketIDClientID)
				g.Expect(gone).To(BeTrue(), "stale SCIM provider should be deleted")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the scimProviderID status field is empty")
			id := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
				"-o", "jsonpath={.status.scimProviderID}")
			Expect(id).To(BeEmpty())
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})
})

// --- SCIM API Helpers ---

// getSCIMProviderEndpoint queries the Pocket-ID API for the SCIM service provider
// associated with the given OIDC client ID, and returns its endpoint URL.
func getSCIMProviderEndpoint(podName, namespace, oidcClientID string) string {
	staticSecretName := instanceName + "-static-api-key"
	apiKeyBase64 := kubectlGet("secret", staticSecretName, "-n", instanceNS,
		"-o", "jsonpath={.data.token}")
	Expect(apiKeyBase64).NotTo(BeEmpty(), "static API key secret should exist")

	script := fmt.Sprintf(`API_KEY=$(echo '%s' | base64 -d)
RESPONSE=$(curl -s -w '\n%%{http_code}' -H "X-API-KEY: $API_KEY" \
  %s/api/oidc/clients/%s/scim-service-provider)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
if [ "$HTTP_CODE" = "404" ]; then
  echo ""
  exit 0
fi
if [ "$HTTP_CODE" != "200" ]; then
  echo "Unexpected HTTP $HTTP_CODE: $BODY" >&2
  exit 1
fi
echo "$BODY" | sed 's/.*"endpoint":"\([^"]*\)".*/\1/'`,
		apiKeyBase64, formatInstanceURL(), oidcClientID)

	applyYAML(createCurlPodYAML(podName, namespace, script))
	waitForPodSucceeded(podName, namespace)
	return kubectlLogs(podName, namespace)
}

// checkSCIMProviderExists returns true if a SCIM service provider exists for the OIDC client.
func checkSCIMProviderExists(podName, namespace, oidcClientID string) bool {
	staticSecretName := instanceName + "-static-api-key"
	apiKeyBase64 := kubectlGet("secret", staticSecretName, "-n", instanceNS,
		"-o", "jsonpath={.data.token}")
	Expect(apiKeyBase64).NotTo(BeEmpty(), "static API key secret should exist")

	script := fmt.Sprintf(`API_KEY=$(echo '%s' | base64 -d)
HTTP_CODE=$(curl -s -o /dev/null -w '%%{http_code}' -H "X-API-KEY: $API_KEY" \
  %s/api/oidc/clients/%s/scim-service-provider)
if [ "$HTTP_CODE" = "200" ]; then
  echo "true"
else
  echo "false"
fi`,
		apiKeyBase64, formatInstanceURL(), oidcClientID)

	applyYAML(createCurlPodYAML(podName, namespace, script))
	waitForPodSucceeded(podName, namespace)
	result := kubectlLogs(podName, namespace)
	return result == "true"
}

// checkSCIMProviderGone returns true if the SCIM service provider for the given
// OIDC client no longer exists in Pocket-ID. Uses the OIDC-client-scoped GET
// endpoint which returns 404 when the SCIM provider (or the OIDC client itself)
// is missing. We cannot use DELETE /api/scim/service-provider/{id} because
// Pocket-ID always returns 204 on DELETE regardless of whether the record exists.
func checkSCIMProviderGone(podName, namespace, oidcClientID string) bool {
	staticSecretName := instanceName + "-static-api-key"
	apiKeyBase64 := kubectlGet("secret", staticSecretName, "-n", instanceNS,
		"-o", "jsonpath={.data.token}")
	Expect(apiKeyBase64).NotTo(BeEmpty(), "static API key secret should exist")

	script := fmt.Sprintf(`API_KEY=$(echo '%s' | base64 -d)
HTTP_CODE=$(curl -s -o /dev/null -w '%%{http_code}' \
  -H "X-API-KEY: $API_KEY" \
  %s/api/oidc/clients/%s/scim-service-provider)
if [ "$HTTP_CODE" = "404" ]; then
  echo "true"
else
  echo "false"
fi`,
		apiKeyBase64, formatInstanceURL(), oidcClientID)

	applyYAML(createCurlPodYAML(podName, namespace, script))
	waitForPodSucceeded(podName, namespace)
	result := kubectlLogs(podName, namespace)
	return result == "true"
}

// createSCIMProviderInPocketID creates a SCIM service provider directly in Pocket-ID via the API.
// Returns the SCIM provider ID.
func createSCIMProviderInPocketID(podName, namespace, oidcClientID, endpoint string) string {
	staticSecretName := instanceName + "-static-api-key"
	apiKeyBase64 := kubectlGet("secret", staticSecretName, "-n", instanceNS,
		"-o", "jsonpath={.data.token}")
	Expect(apiKeyBase64).NotTo(BeEmpty(), "static API key secret should exist")

	script := fmt.Sprintf(`API_KEY=$(echo '%s' | base64 -d)
BODY=$(curl -s -X POST -H "X-API-KEY: $API_KEY" -H "Content-Type: application/json" \
  -d '{"oidcClientId": "%s", "endpoint": "%s"}' \
  -o /tmp/body -w '%%{http_code}' \
  %s/api/scim/service-provider)
HTTP_CODE="$BODY"
BODY=$(cat /tmp/body)
if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "201" ]; then
  echo "Failed to create SCIM provider with HTTP $HTTP_CODE: $BODY" >&2
  exit 1
fi
echo "$BODY" | grep -o '"id":"[^"]*"' | head -1 | sed 's/"id":"//;s/"//'`,
		apiKeyBase64, oidcClientID, endpoint, formatInstanceURL())

	applyYAML(createCurlPodYAML(podName, namespace, script))
	waitForPodSucceeded(podName, namespace)

	scimID := getPodLogs(podName, namespace)
	Expect(scimID).NotTo(BeEmpty(), "should get SCIM provider ID from API response")
	return scimID
}
