//go:build e2e
// +build e2e

package e2e

import (
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
		body := getOIDCClientFromPocketID(clientID)
		Expect(body).To(ContainSubstring(`"skipConsent":true`),
			"Pocket-ID should persist and return skipConsent: true")
	})

	AfterAll(func() {
		deleteObject("pocketidoidcclient", clientName, userNS)
		waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
	})
})

// getOIDCClientFromPocketID returns the raw JSON body Pocket-ID reports for a client.
func getOIDCClientFromPocketID(clientID string) string {
	GinkgoHelper()
	return getFromPocketID("/api/oidc/clients/" + clientID)
}
