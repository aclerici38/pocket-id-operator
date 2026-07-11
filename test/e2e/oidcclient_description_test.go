//go:build e2e
// +build e2e

package e2e

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OIDC Client Description", Ordered, func() {
	// Verifies that spec.description is actually persisted by Pocket-ID, not just
	// mapped into the operator's input. The value is read back from the Pocket-ID
	// API to confirm the full round-trip (serialize -> store -> return).

	const clientName = "test-description"

	It("should propagate spec.description to Pocket-ID", func() {
		By("creating a PocketIDOIDCClient with a description")
		createOIDCClient(OIDCClientOptions{
			Name:         clientName,
			Description:  "managed by the operator",
			CallbackURLs: []string{"https://description.example.com/callback"},
		})

		By("waiting for the client to be ready")
		waitForReady("pocketidoidcclient", clientName, userNS)

		By("capturing the client ID from status")
		clientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

		By("verifying Pocket-ID reports the description for the client")
		body := getOIDCClientFromPocketID("description-verify", userNS, clientID)
		Expect(body).To(ContainSubstring(`"description":"managed by the operator"`),
			"Pocket-ID should persist and return the client description")
	})

	AfterAll(func() {
		kubectlDelete("pocketidoidcclient", clientName, userNS)
		waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
	})
})
