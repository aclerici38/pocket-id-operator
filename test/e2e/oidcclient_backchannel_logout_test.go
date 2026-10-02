//go:build e2e
// +build e2e

package e2e

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OIDC Client Back-Channel Logout", Ordered, func() {
	// Verifies that spec.backchannelLogoutUrl is persisted and returned by Pocket-ID, which is
	// what keeps it from diffing on every reconcile, and that removing it clears the server
	// value: the operator omits an empty URL and relies on Pocket-ID treating that as unset.

	const (
		clientName = "test-backchannel-logout"
		logoutURL  = "https://backchannel.example.com/logout"
	)

	var clientID string

	AfterAll(func() {
		deleteObject("pocketidoidcclient", clientName, userNS)
		waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
	})

	It("should propagate spec.backchannelLogoutUrl to Pocket-ID", func() {
		createOIDCClientAndWaitReady(OIDCClientOptions{
			Name:                 clientName,
			CallbackURLs:         []string{"https://backchannel.example.com/callback"},
			BackchannelLogoutURL: logoutURL,
		})
		clientID = waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

		Expect(getOIDCClientFromPocketID(clientID)).To(ContainSubstring(`"backchannelLogoutURL":"` + logoutURL + `"`))
	})

	It("should clear the URL in Pocket-ID when removed from the spec", func() {
		Expect(patchObject("pocketidoidcclient", clientName, userNS,
			`{"spec":{"backchannelLogoutUrl":null}}`)).To(Succeed())

		Eventually(func() string {
			return getOIDCClientFromPocketID(clientID)
		}).Should(ContainSubstring(`"backchannelLogoutURL":""`))
	})
})
