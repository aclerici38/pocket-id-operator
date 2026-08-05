//go:build e2e
// +build e2e

package e2e

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OIDC Client Federated Identity", Ordered, func() {
	// Verifies that spec.federatedIdentities[].replayProtection is actually
	// persisted by Pocket-ID, not just mapped into the operator's input. The value
	// is read back from the Pocket-ID API to confirm the full round-trip
	// (serialize -> store -> return).

	const clientName = "test-federated-identity"

	It("should propagate replayProtection to Pocket-ID", func() {
		By("creating a PocketIDOIDCClient with a federated identity using replayProtection: true")
		createOIDCClient(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://federated-identity.example.com/callback"},
			FederatedIdentities: []FederatedIdentity{{
				Issuer:           "https://issuer.example.com",
				Subject:          "test-subject",
				Audience:         "test-audience",
				JWKS:             "https://issuer.example.com/.well-known/jwks.json",
				ReplayProtection: true,
			}},
		})

		By("waiting for the client to be ready")
		waitForReady("pocketidoidcclient", clientName, userNS)

		By("capturing the client ID from status")
		clientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

		By("verifying Pocket-ID reports replayProtection: true for the federated identity")
		body := getOIDCClientFromPocketID("federated-identity-verify", userNS, clientID)
		Expect(body).To(ContainSubstring(`"replayProtection":true`),
			"Pocket-ID should persist and return replayProtection: true")
	})

	AfterAll(func() {
		kubectlDelete("pocketidoidcclient", clientName, userNS)
		waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
	})
})
