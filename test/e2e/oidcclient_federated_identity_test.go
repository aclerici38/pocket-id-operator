//go:build e2e
// +build e2e

package e2e

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

var _ = Describe("OIDC Client Federated Identity", Ordered, func() {
	// The operator diffs federated identities against what Pocket-ID returns, so the round
	// trip must be exact: any field Pocket-ID changes on the way back would re-push the client
	// on every reconcile, with nothing in Pocket-ID looking wrong while it happened.

	const clientName = "test-federated-identity"

	var clientID string

	federatedIdentities := federatedIdentitiesFromPocketID

	AfterAll(func() {
		deleteObject("pocketidoidcclient", clientName, userNS)
		waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
	})

	// An identity with only an issuer must come back without the default jwks Pocket-ID derives
	// from it, and the identities must come back in the order they were sent: both are compared
	// as they are.
	It("should store the federated identities exactly as specified", func() {
		createOIDCClientAndWaitReady(OIDCClientOptions{
			Name:         clientName,
			CallbackURLs: []string{"https://federated-identity.example.com/callback"},
			FederatedIdentities: []FederatedIdentity{{
				Issuer:           "https://issuer.example.com",
				Subject:          "test-subject",
				Audience:         "test-audience",
				JWKS:             "https://issuer.example.com/.well-known/jwks.json",
				ReplayProtection: true,
			}, {
				Issuer: "https://another-issuer.example.com",
			}},
		})
		clientID = waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

		Expect(federatedIdentities(clientID)).To(Equal([]pocketid.OIDCClientFederatedIdentity{{
			Issuer:           "https://issuer.example.com",
			Subject:          "test-subject",
			Audience:         "test-audience",
			JWKS:             "https://issuer.example.com/.well-known/jwks.json",
			ReplayProtection: true,
		}, {
			Issuer: "https://another-issuer.example.com",
		}}))
	})

	It("should remove the federated identities when they are dropped from the spec", func() {
		Expect(patchObject("pocketidoidcclient", clientName, userNS,
			`{"spec":{"federatedIdentities":null}}`)).To(Succeed())

		Eventually(func() []pocketid.OIDCClientFederatedIdentity {
			return federatedIdentities(clientID)
		}).Should(BeEmpty())
	})

	Context("Adoption", func() {
		const (
			adoptName     = "test-federated-identity-adopt"
			adoptClientID = "federated-identity-adopt"
		)

		AfterAll(func() {
			deleteObject("pocketidoidcclient", adoptName, userNS)
			waitForResourceDeleted("pocketidoidcclient", adoptName, userNS)
		})

		// The identity carries public keys, as one added in the UI may, so clearing it also
		// shows the operator reads keys back from Pocket-ID.
		It("should clear federated identities the spec does not declare", func() {
			By("creating a client with a federated identity directly in Pocket-ID")
			ctx, cancel := testCtx()
			defer cancel()
			id := adoptClientID
			_, err := pid.CreateOIDCClient(ctx, pocketid.OIDCClientInput{
				ID:           &id,
				Name:         "Federated Identity Adopt",
				CallbackURLs: []string{"https://federated-identity-adopt.example.com/callback"},
				Credentials: &pocketid.OIDCClientCredentials{FederatedIdentities: []pocketid.OIDCClientFederatedIdentity{{
					Issuer: "https://issuer.example.com",
					PublicKeys: []json.RawMessage{json.RawMessage(
						`{"kty":"OKP","crv":"Ed25519","kid":"e2e-key","use":"sig","x":"fxAuz6i2oJCZM8blM5bge1smljJn8qL-yysBgwHBnDA"}`)},
				}}},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(federatedIdentities(adoptClientID)).To(ConsistOf(
				HaveField("PublicKeys", HaveLen(1))))

			By("adopting it with a CR that declares none")
			createOIDCClientAndWaitReady(OIDCClientOptions{
				Name:         adoptName,
				ClientID:     adoptClientID,
				CallbackURLs: []string{"https://federated-identity-adopt.example.com/callback"},
			})

			Eventually(func() []pocketid.OIDCClientFederatedIdentity {
				return federatedIdentities(adoptClientID)
			}).Should(BeEmpty())
		})
	})
})
