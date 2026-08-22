//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aclerici38/pocket-id-operator/internal/pocketid"
)

var _ = Describe("Callback URL Preservation", Ordered, func() {
	// These tests verify that the operator does not overwrite callback URLs
	// in pocket-id when spec.callbackUrls is empty, preserving any values set
	// out-of-band via the pocket-id UI or API.

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
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

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
			}, time.Minute, 5*time.Second).Should(Succeed())
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})

	Context("Out-of-band callback URLs are preserved when spec has no callbackUrls", func() {
		const clientName = "test-oob-preserve"

		It("should not overwrite out-of-band callback URLs on reconcile", func() {
			By("creating an OIDC client without any callbackUrls in the spec")
			applyYAML(fmt.Sprintf(`apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: %s
  namespace: %s
spec: {}`, clientName, userNS))

			waitForReady("pocketidoidcclient", clientName, userNS)
			clientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

			By("setting a callback URL directly in pocket-id via API")
			setOIDCClientCallbackURLsInPocketID(clientID, clientName,
				[]string{"https://oob-set.example.com/callback"})

			By("triggering a reconcile via annotation change")
			err := kubectlAnnotate("pocketidoidcclient", clientName, userNS, "test/trigger=reconcile")
			Expect(err).NotTo(HaveOccurred())

			By("verifying the out-of-band callback URL appears in status after reconcile")
			Eventually(func(g Gomega) {
				urls := getField("pocketidoidcclient", clientName, userNS, ".status.callbackUrls")
				g.Expect(urls).To(ContainSubstring("https://oob-set.example.com/callback"),
					"out-of-band callback URL must survive operator reconcile when spec has no callbackUrls")
			}, time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the out-of-band callback URL persists across multiple reconciles")
			Consistently(func(g Gomega) {
				urls := getField("pocketidoidcclient", clientName, userNS, ".status.callbackUrls")
				g.Expect(urls).To(ContainSubstring("https://oob-set.example.com/callback"),
					"out-of-band callback URL must not be wiped by subsequent reconciles")
			}, 20*time.Second, 5*time.Second).Should(Succeed())
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
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
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

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
			}, time.Minute, 5*time.Second).Should(Succeed())
		})

		AfterAll(func() {
			kubectlDelete("pocketidoidcclient", clientName, userNS)
			waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
		})
	})
})

// setOIDCClientCallbackURLsInPocketID rewrites a client's callback URLs directly through
// the API, simulating an out-of-band edit. Only name and callbackURLs are sent, matching
// the minimal update DTO the UI submits.
func setOIDCClientCallbackURLsInPocketID(clientID, clientName string, callbackURLs []string) {
	GinkgoHelper()
	ctx, cancel := testCtx()
	defer cancel()

	_, err := pid.UpdateOIDCClient(ctx, clientID, pocketid.OIDCClientInput{
		Name:         clientName,
		CallbackURLs: callbackURLs,
	})
	Expect(err).NotTo(HaveOccurred(), "updating callback URLs of client %s", clientID)
}
