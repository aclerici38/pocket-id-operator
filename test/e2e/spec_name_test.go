//go:build e2e
// +build e2e

package e2e

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OIDC Client spec.name", Ordered, func() {
	// These tests verify the behavior of the spec.name field on PocketIDOIDCClient:
	// 1. When spec.name is set, Pocket-ID uses it as the client display name
	// 2. When spec.name differs from metadata.name, adoption matches by spec.name
	// 3. Adding spec.name to an existing resource does not change status.clientID

	Context("Creation with spec.name", func() {
		const clientName = "test-specname-create"

		It("should create the OIDC client in Pocket-ID using spec.name as the display name", func() {
			By("creating a PocketIDOIDCClient with spec.name set to a different value than metadata.name")
			createOIDCClient(OIDCClientOptions{
				Name:         clientName,
				SpecName:     "My Display Name",
				CallbackURLs: []string{"https://specname-create.example.com/callback"},
			})

			By("waiting for the client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying status.name reflects the spec.name sent to Pocket-ID")
			waitForStatusField("pocketidoidcclient", clientName, userNS, ".status.name", "My Display Name")
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("Adoption by spec.name", func() {
		// The OIDC client in Pocket-ID is pre-created with a name matching spec.name,
		// while metadata.name is intentionally different. The operator should adopt it
		// by searching for spec.name rather than metadata.name.
		const (
			clientName   = "test-specname-adopt"
			pocketIDName = "specname-adopt-display"
		)

		It("should adopt an existing OIDC client by matching spec.name when metadata.name differs", func() {
			By("creating an OIDC client directly in Pocket-ID with a name matching spec.name")
			externalClientID := createOIDCClientInPocketIDWithName(
				"create-specname-adopt-pod",
				userNS,
				pocketIDName,
				[]string{"https://specname-adopt.example.com/callback"},
			)

			By("creating a PocketIDOIDCClient CR whose spec.name matches the pre-created client")
			createOIDCClient(OIDCClientOptions{
				Name:         clientName,
				SpecName:     pocketIDName,
				CallbackURLs: []string{"https://specname-adopt.example.com/callback"},
			})

			By("waiting for the client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("verifying the operator adopted the existing client via spec.name lookup")
			adoptedClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			Expect(adoptedClientID).To(Equal(externalClientID),
				"operator should adopt the existing Pocket-ID client found by spec.name, not create a new one")
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("Adding spec.name to existing resource", func() {
		const clientName = "test-specname-update"

		It("should preserve status.clientID when spec.name is added after initial creation", func() {
			By("creating a PocketIDOIDCClient without spec.name")
			createOIDCClient(OIDCClientOptions{
				Name:         clientName,
				CallbackURLs: []string{"https://specname-update.example.com/callback"},
			})

			By("waiting for the client to be ready")
			waitForReady("pocketidoidcclient", clientName, userNS)

			By("capturing the original status.clientID")
			originalClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
			Expect(originalClientID).NotTo(BeEmpty())

			By("updating the resource to add spec.name")
			applyYAML(buildOIDCClientYAML(OIDCClientOptions{
				Name:         clientName,
				SpecName:     "Updated Display Name",
				CallbackURLs: []string{"https://specname-update.example.com/callback"},
			}))

			By("waiting for the controller to reconcile the name change (status.name reflects new spec.name)")
			waitForStatusField("pocketidoidcclient", clientName, userNS, ".status.name", "Updated Display Name")

			By("verifying status.clientID is unchanged after adding spec.name")
			currentClientID := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
				"-o", "jsonpath={.status.clientID}")
			Expect(currentClientID).To(Equal(originalClientID),
				"status.clientID should not change when spec.name is added to an existing resource")
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})
})
