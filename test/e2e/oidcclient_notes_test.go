//go:build e2e

package e2e

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OIDC Client Notes", Ordered, func() {
	// Verifies that spec.notes is actually persisted by Pocket-ID, not just
	// mapped into the operator's input. The value is read back from the Pocket-ID
	// API to confirm the full round-trip (serialize -> store -> return).

	const clientName = "test-notes"

	It("should propagate spec.notes to Pocket-ID", func() {
		By("creating a PocketIDOIDCClient with notes")
		createOIDCClient(OIDCClientOptions{
			Name:         clientName,
			Notes:        "managed by the operator",
			CallbackURLs: []string{"https://notes.example.com/callback"},
		})

		By("waiting for the client to be ready")
		waitForReady("pocketidoidcclient", clientName, userNS)

		By("capturing the client ID from status")
		clientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

		By("verifying Pocket-ID reports the notes for the client")
		body := getOIDCClientFromPocketID(clientID)
		Expect(body).To(ContainSubstring(`"notes":"managed by the operator"`),
			"Pocket-ID should persist and return the client notes")
	})

	AfterAll(func() {
		deleteObject("pocketidoidcclient", clientName, userNS)
		waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
	})
})
