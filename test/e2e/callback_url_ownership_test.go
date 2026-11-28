//go:build e2e

package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	pid "github.com/aclerici38/pocket-id-go-client/v3/client"
	"github.com/oapi-codegen/nullable"
)

var _ = Describe("Callback URL Ownership", Ordered, func() {
	// The spec owns a client's callback URLs: they survive reconciles, replace the
	// server-side values, and an unset spec clears ones set out-of-band.

	Context("Spec callback URLs are preserved across reconciles", func() {
		const clientName = "test-callback-preserve"

		It("should not lose spec callback URLs after a reconcile", func() {
			By("creating an OIDC client with callback URLs")
			createOIDCClientAndWaitReady(OIDCClientOptions{
				Name:               clientName,
				CallbackURLs:       []string{"https://preserve.example.com/callback"},
				LogoutCallbackURLs: []string{"https://preserve.example.com/logout"},
			})

			By("verifying callback URLs appear in status")
			Eventually(func(g Gomega) {
				urls := getField("pocketidoidcclient", clientName, userNS, ".status.callbackUrls")
				g.Expect(urls).To(ContainSubstring("https://preserve.example.com/callback"))
			}).Should(Succeed())

			By("triggering a reconcile by updating the spec (adding a logout URL)")
			createOIDCClient(OIDCClientOptions{
				Name:               clientName,
				CallbackURLs:       []string{"https://preserve.example.com/callback"},
				LogoutCallbackURLs: []string{"https://preserve.example.com/logout", "https://preserve.example.com/logout2"},
			})

			time.Sleep(5 * time.Second)

			By("verifying callback URLs are still in status after reconcile")
			Eventually(func(g Gomega) {
				urls := getField("pocketidoidcclient", clientName, userNS, ".status.callbackUrls")
				g.Expect(urls).To(ContainSubstring("https://preserve.example.com/callback"))
			}).Should(Succeed())
		})

		cleanupAfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("Out-of-band callback URLs are cleared when spec has no callbackUrls", func() {
		const clientName = "test-oob-clear"

		It("should clear out-of-band callback URLs on reconcile", func() {
			By("creating an OIDC client without any callbackUrls in the spec")
			applyYAML(fmt.Sprintf(`apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: %s
  namespace: %s
spec:
%s`, clientName, userNS, instanceSelectorYAML(sharedInstanceLabels)))

			waitForReady("pocketidoidcclient", clientName, userNS)
			clientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

			By("setting a callback URL directly in pocket-id via API")
			setOIDCClientCallbackURLsInPocketID(clientID, []string{"https://oob-set.example.com/callback"})

			By("triggering a reconcile via annotation change")
			err := annotateObject("pocketidoidcclient", clientName, userNS, "test/trigger=reconcile")
			Expect(err).NotTo(HaveOccurred())

			By("verifying the out-of-band callback URL is cleared from Pocket-ID")
			Eventually(func(g Gomega) {
				ctx, cancel := testCtx()
				defer cancel()
				client, err := pid.Decode[pid.OIDCClientWithAllowedUserGroupsDto](pocketID.GetOIDCClient(ctx, pid.OIDCClientID(clientID)))
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(client.CallbackURLs).To(BeEmpty(),
					"an unset spec.callbackUrls must clear out-of-band callback URLs")
			}).Should(Succeed())

			By("verifying status reports no callback URLs")
			Eventually(func(g Gomega) {
				g.Expect(getField("pocketidoidcclient", clientName, userNS, ".status.callbackUrls")).To(BeEmpty())
			}).Should(Succeed())
		})

		cleanupAfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("Spec callback URLs override server-side URLs", func() {
		const clientName = "test-callback-override"

		It("should use spec callback URLs when provided, overriding server-side values", func() {
			By("creating an OIDC client with initial callback URLs")
			createOIDCClientAndWaitReady(OIDCClientOptions{
				Name:         clientName,
				CallbackURLs: []string{"https://initial.example.com/callback"},
			})

			By("verifying initial callback URLs appear in status")
			Eventually(func(g Gomega) {
				urls := getField("pocketidoidcclient", clientName, userNS, ".status.callbackUrls")
				g.Expect(urls).To(ContainSubstring("https://initial.example.com/callback"))
			}).Should(Succeed())

			By("updating the spec with new callback URLs")
			createOIDCClient(OIDCClientOptions{
				Name:         clientName,
				CallbackURLs: []string{"https://updated.example.com/callback"},
			})

			By("verifying status reflects the updated callback URLs")
			Eventually(func(g Gomega) {
				urls := getField("pocketidoidcclient", clientName, userNS, ".status.callbackUrls")
				g.Expect(urls).To(ContainSubstring("https://updated.example.com/callback"))
				g.Expect(urls).NotTo(ContainSubstring("https://initial.example.com/callback"))
			}).Should(Succeed())
		})

		cleanupAfterAll(func() {
			deleteObject("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})
})

// setOIDCClientCallbackURLsInPocketID rewrites a client's callback URLs directly through
// the API, simulating an out-of-band edit.
func setOIDCClientCallbackURLsInPocketID(clientID string, callbackURLs []string) {
	GinkgoHelper()
	ctx, cancel := testCtx()
	defer cancel()

	err := pid.Check(pocketID.PatchOIDCClient(ctx, pid.OIDCClientID(clientID), pid.PatchOIDCClientJSONRequestBody{
		CallbackURLs: nullable.NewNullableWithValue(callbackURLs),
	}))
	Expect(err).NotTo(HaveOccurred(), "updating callback URLs of client %s", clientID)
}
