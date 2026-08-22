//go:build e2e
// +build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Logo Auto-Generation", Ordered, func() {
	// These tests verify that the operator correctly resolves logo URLs
	// and applies them to the OIDC client in Pocket-ID.
	// The e2e overlay disables auto-generation globally, so these tests
	// explicitly opt in via spec.logo.autoGenerate.

	Context("Auto-generated logos", func() {
		const clientName = "test-logo-autogen"

		It("should apply logos when autoGenerate is enabled with a known icon name", func() {
			By("creating an OIDC client with logo auto-generation enabled")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				Logo: &OIDCLogoConfig{
					AutoGenerate: boolPtr(true),
					NameOverride: "grafana",
				},
			}))

			By("waiting for the client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the logo was applied in Pocket-ID")
			oidcClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			Eventually(func(g Gomega) {
				hasLogo := getOIDCClientField(oidcClientID, "hasLogo")
				g.Expect(hasLogo).To(Equal("true"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the logo status fields are set")
			logoURL := getField("pocketidoidcclient", clientName, userNS, ".status.logoUrl")
			Expect(logoURL).To(ContainSubstring("grafana"))

			logoReachable := getField("pocketidoidcclient", clientName, userNS, ".status.logoReachable")
			Expect(logoReachable).To(Equal("true"))
		})

		AfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("Auto-generation disabled", func() {
		const clientName = "test-logo-disabled"

		It("should not set logos when autoGenerate is false", func() {
			By("creating an OIDC client with logo auto-generation explicitly disabled")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name: clientName,
				Logo: &OIDCLogoConfig{
					AutoGenerate: boolPtr(false),
				},
			}))

			By("waiting for the client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying no logo was applied in Pocket-ID")
			oidcClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			hasLogo := getOIDCClientField(oidcClientID, "hasLogo")
			Expect(hasLogo).To(Equal("false"))
		})

		AfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})
})

// getOIDCClientField returns one top-level field of an OIDC client as Pocket-ID reports
// it, rendered the way the previous shell version did: bare scalars, so a boolean reads
// as "true" and an absent field as "<nil>".
func getOIDCClientField(oidcClientID, field string) string {
	GinkgoHelper()

	body := getFromPocketID("/api/oidc/clients/" + oidcClientID)

	var client map[string]any
	Expect(json.Unmarshal([]byte(body), &client)).To(Succeed(), "decoding OIDC client")
	return fmt.Sprint(client[field])
}
