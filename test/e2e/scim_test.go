//go:build e2e
// +build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
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
			scimEndpoint := getSCIMProviderEndpoint(oidcClientID)
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
				endpoint := getSCIMProviderEndpoint(oidcClientID)
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
			scimExists := checkSCIMProviderExists(oidcClientID)
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
			scimEndpoint := getSCIMProviderEndpoint(oidcClientID)
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
				gone := checkSCIMProviderGone(oidcClientID)
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
			createOIDCClientInPocketID(pocketIDClientID, "SCIM Adopt Test",
				[]string{"https://adopt-scim.example.com/callback"})
			scimID := createSCIMProviderInPocketID(pocketIDClientID,
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

	Context("SCIM idempotency", func() {
		const clientName = "test-scim-idempotent"

		It("should not modify SCIM endpoint on reconcile when nothing has changed", func() {
			By("creating an OIDC client with a SCIM endpoint")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				SCIM: &SCIMConfig{
					Endpoint: "https://idempotent.example.com/scim",
				},
			}))
			waitForReady("pocketidoidcclient", clientName, userNS)
			oidcClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

			By("verifying the initial SCIM endpoint in Pocket-ID")
			initialEndpoint := getSCIMProviderEndpoint(oidcClientID)
			Expect(initialEndpoint).To(Equal("https://idempotent.example.com/scim"))

			By("triggering another reconcile by annotating the client")
			Expect(kubectlAnnotate("pocketidoidcclient", clientName, userNS, "test/trigger-reconcile=1")).To(Succeed())
			// The RESYNC_INTERVAL env var is 5s in e2e — wait for at least two cycles.
			time.Sleep(15 * time.Second)
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the SCIM endpoint is unchanged after no-op reconcile")
			// Clean up any previous check pod from this name
			kubectlDelete("pod", "scim-idempotent-check-2", userNS)
			endpointAfter := getSCIMProviderEndpoint(oidcClientID)
			Expect(endpointAfter).To(Equal("https://idempotent.example.com/scim"))
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
			createOIDCClientInPocketID(pocketIDClientID, "SCIM Stale Cleanup Test",
				[]string{"https://stale-scim.example.com/callback"})
			scimID := createSCIMProviderInPocketID(pocketIDClientID,
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
				gone := checkSCIMProviderGone(pocketIDClientID)
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

// getSCIMProviderEndpoint returns the SCIM endpoint configured for the OIDC client, or
// the empty string when Pocket-ID has no provider for it. The raw request is used rather
// than the typed client so a 404 stays distinguishable from a transport failure.
func getSCIMProviderEndpoint(oidcClientID string) string {
	GinkgoHelper()

	body, code := pocketIDRequest(http.MethodGet, "/api/oidc/clients/"+oidcClientID+"/scim-service-provider", nil)
	if code == http.StatusNotFound {
		return ""
	}
	Expect(code).To(Equal(http.StatusOK), "reading SCIM provider: %d: %s", code, body)

	var provider struct {
		Endpoint string `json:"endpoint"`
	}
	Expect(json.Unmarshal([]byte(body), &provider)).To(Succeed(), "decoding SCIM provider")
	return provider.Endpoint
}

// checkSCIMProviderExists reports whether a SCIM service provider exists for the client.
func checkSCIMProviderExists(oidcClientID string) bool {
	GinkgoHelper()
	return getStatusFromPocketID("/api/oidc/clients/"+oidcClientID+"/scim-service-provider") == http.StatusOK
}

// checkSCIMProviderGone reports whether the SCIM service provider for the given OIDC
// client is gone. It reads the client-scoped GET, which 404s when the provider (or the
// client) is missing; DELETE cannot be used because Pocket-ID always answers 204 there,
// whether or not the record existed.
func checkSCIMProviderGone(oidcClientID string) bool {
	GinkgoHelper()
	return getStatusFromPocketID("/api/oidc/clients/"+oidcClientID+"/scim-service-provider") == http.StatusNotFound
}

// createSCIMProviderInPocketID creates a SCIM service provider directly in Pocket-ID and
// returns its ID.
func createSCIMProviderInPocketID(oidcClientID, endpoint string) string {
	GinkgoHelper()
	ctx, cancel := testCtx()
	defer cancel()

	provider, err := pid.CreateSCIMServiceProvider(ctx, pocketid.SCIMServiceProviderInput{
		OIDCClientID: oidcClientID,
		Endpoint:     endpoint,
	})
	Expect(err).NotTo(HaveOccurred(), "creating SCIM provider for client %s", oidcClientID)
	Expect(provider.ID).NotTo(BeEmpty())
	return provider.ID
}
