//go:build e2e
// +build e2e

package e2e

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OIDC Client Token Lifetimes", Ordered, func() {
	// Verifies that the per-client token lifetimes are persisted by Pocket-ID,
	// and that the CRD defaults are pushed rather than silently left to the
	// server, so drift on these fields is detectable.

	const (
		clientName    = "test-token-duration"
		probeClientID = "token-default-probe"
	)

	It("should propagate the token lifetimes to Pocket-ID", func() {
		By("creating a PocketIDOIDCClient with custom token lifetimes")
		createOIDCClient(OIDCClientOptions{
			Name:                        clientName,
			CallbackURLs:                []string{"https://tokens.example.com/callback"},
			AccessTokenDurationMinutes:  15,
			RefreshTokenDurationMinutes: 1440,
		})

		By("waiting for the client to be ready")
		waitForReady("pocketidoidcclient", clientName, userNS)

		By("capturing the client ID from status")
		clientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

		By("verifying Pocket-ID reports the configured lifetimes")
		body := getOIDCClientFromPocketID(clientID)
		Expect(body).To(ContainSubstring(`"accessTokenDurationMinutes":15`))
		Expect(body).To(ContainSubstring(`"refreshTokenDurationMinutes":1440`))
	})

	// The CRD carries Pocket-ID's own defaults so that an unset spec field is still
	// owned by the operator rather than reported as permanent drift. Nothing in the
	// generated client pins those numbers — swagger omits them — so this checks them
	// against a live server instead of asking anyone to track upstream by hand.
	It("should keep the CRD defaults in step with Pocket-ID's defaults", func() {
		By("creating a client straight through the Pocket-ID API with both lifetimes omitted")
		createOIDCClientInPocketID(probeClientID, "Token Default Probe",
			[]string{"https://probe.example.com/callback"})

		By("reading back the lifetimes Pocket-ID chose for it")
		body := getOIDCClientFromPocketID(probeClientID)

		By("comparing them against the CRD defaults")
		for _, field := range []string{"accessTokenDurationMinutes", "refreshTokenDurationMinutes"} {
			crdDefault := getClusterField("crd", "pocketidoidcclients.pocketid.internal", fmt.Sprintf(
				".spec.versions[0].schema.openAPIV3Schema.properties.spec.properties.%s.default", field))
			Expect(body).To(ContainSubstring(fmt.Sprintf(`"%s":%s`, field, crdDefault)),
				"Pocket-ID's default for %s no longer matches the CRD default of %s — update the "+
					"+kubebuilder:default on PocketIDOIDCClientSpec and regenerate", field, crdDefault)
		}
	})

	AfterAll(func() {
		deleteObject("pocketidoidcclient", clientName, userNS)
		waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
	})
})
