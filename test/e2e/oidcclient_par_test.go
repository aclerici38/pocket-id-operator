//go:build e2e
// +build e2e

package e2e

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OIDC Client Pushed Authorization Requests", Ordered, func() {
	// Verifies that spec.requiresPushedAuthorizationRequests is actually persisted
	// by Pocket-ID, not just mapped into the operator's input. The value is read
	// back from the Pocket-ID API to confirm the full round-trip
	// (serialize -> store -> return).

	const clientName = "test-par"

	It("should propagate spec.requiresPushedAuthorizationRequests to Pocket-ID", func() {
		By("creating a PocketIDOIDCClient with requiresPushedAuthorizationRequests: true")
		createOIDCClient(OIDCClientOptions{
			Name:         clientName,
			RequiresPAR:  true,
			CallbackURLs: []string{"https://par.example.com/callback"},
		})

		By("waiting for the client to be ready")
		waitForReady("pocketidoidcclient", clientName, userNS)

		By("capturing the client ID from status")
		clientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

		By("verifying Pocket-ID reports requiresPushedAuthorizationRequests: true for the client")
		body := getOIDCClientFromPocketID(clientID)
		Expect(body).To(ContainSubstring(`"requiresPushedAuthorizationRequests":true`),
			"Pocket-ID should persist and return requiresPushedAuthorizationRequests: true")
	})

	AfterAll(func() {
		deleteObject("pocketidoidcclient", clientName, userNS)
		waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
	})
})
