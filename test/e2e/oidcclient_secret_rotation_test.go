//go:build e2e
// +build e2e

package e2e

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Since Pocket-ID v2.14.0 a client holds a set of secrets rather than one, and creating a secret
// appends instead of replacing. Everything the operator does with that set — identifying its own
// secret by the clear-text prefix, retiring the rest, holding a superseded one for the configured
// overlap — rests on Pocket-ID's behaviour, so it is asserted here against a live instance.
//
// The decisive check is whether a secret still authenticates. Pocket-ID lists a secret whether or
// not it is usable, so only the token endpoint distinguishes "retired" from "still listed", and
// only it can show that an overlapping secret really does keep working.
var _ = Describe("OIDC Client Secret Rotation", Ordered, func() {
	const (
		clientName        = "test-secret-rotation"
		credentialsSecret = clientName + "-oidc-credentials"
	)

	var clientID string

	// authResult asks Pocket-ID whether a client_id/secret pair is still accepted.
	authResult := func(secret string) string {
		return clientSecretAuthResult(clientID, secret)
	}

	BeforeAll(func() {
		By("creating a confidential client whose secret the operator generates")
		createOIDCClientAndWaitReady(OIDCClientOptions{
			Name:         clientName,
			Namespace:    userNS,
			CallbackURLs: []string{"https://example.com/callback"},
		})
		clientID = waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")
	})

	AfterAll(func() {
		deleteObject("pocketidoidcclient", clientName, userNS)
		waitForResourceDeleted("pocketidoidcclient", clientName, userNS)
	})

	Context("Initial secret", func() {
		It("should mint exactly one secret that authenticates", func() {
			secret := waitForSecretKey(credentialsSecret, userNS, "client_secret")
			Expect(secret).NotTo(BeEmpty())

			By("verifying the stored credential is accepted by Pocket-ID")
			Expect(authResult(secret)).To(Equal("ok"))

			By("verifying the client holds exactly the one secret")
			Expect(clientSecretIDsFromPocketID(clientID)).To(HaveLen(1))
		})

		// The operator matches a stored credential against these prefixes to decide what to
		// retire. If Pocket-ID ever changed how much it records, resolution would silently start
		// picking the wrong secret, so the contract is pinned here rather than assumed.
		It("should record the first four characters of the value in clear text", func() {
			secret := secretData(credentialsSecret, userNS, "client_secret")
			Expect(len(secret)).To(BeNumerically(">", 4))

			Expect(clientSecretPrefixesFromPocketID(clientID)).
				To(ConsistOf(secret[:4]))
		})
	})

	Context("Rotation without overlap", func() {
		var previousSecret string

		It("should replace the credential and revoke the one it superseded", func() {
			previousSecret = secretData(credentialsSecret, userNS, "client_secret")

			By("requesting a rotation")
			Expect(annotateObject("pocketidoidcclient", clientName, userNS,
				"pocketid.internal/regenerate-client-secret=true")).To(Succeed())

			By("waiting for a different value to reach the generated Secret")
			Eventually(func() string {
				return secretData(credentialsSecret, userNS, "client_secret")
			}).ShouldNot(Equal(previousSecret))

			By("waiting for the superseded secret to be retired in Pocket-ID")
			Eventually(func() []string {
				return clientSecretIDsFromPocketID(clientID)
			}).Should(HaveLen(1),
				"with no overlap configured only the replacement should remain")

			By("verifying the replacement authenticates")
			Expect(authResult(secretData(credentialsSecret, userNS, "client_secret"))).
				To(Equal("ok"))

			By("verifying the superseded value no longer authenticates")
			Expect(authResult(previousSecret)).To(Equal("invalid_client"))
		})
	})

	Context("Rotation with an overlap", func() {
		var supersededSecret string

		It("should keep the superseded secret working during the overlap", func() {
			By("configuring an overlap long enough to observe")
			Expect(patchObject("pocketidoidcclient", clientName, userNS,
				`{"spec":{"clientSecretOverlap":"1h"}}`)).To(Succeed())
			waitForReconciled("pocketidoidcclient", clientName, userNS)

			supersededSecret = secretData(credentialsSecret, userNS, "client_secret")

			By("requesting a rotation")
			Expect(annotateObject("pocketidoidcclient", clientName, userNS,
				"pocketid.internal/regenerate-client-secret=true")).To(Succeed())

			By("waiting for the replacement to reach the generated Secret")
			Eventually(func() string {
				return secretData(credentialsSecret, userNS, "client_secret")
			}).ShouldNot(Equal(supersededSecret))

			By("verifying both the replacement and the secret it superseded authenticate")
			Expect(authResult(secretData(credentialsSecret, userNS, "client_secret"))).
				To(Equal("ok"))
			Expect(authResult(supersededSecret)).To(Equal("ok"),
				"the whole point of the overlap is that a consumer holding the old value keeps working")

			By("verifying Pocket-ID is holding both, and the operator leaves them alone")
			Consistently(func() []string {
				return clientSecretIDsFromPocketID(clientID)
			}, 20*time.Second).Should(HaveLen(2))
		})

		It("should retire the superseded secret once the overlap is gone", func() {
			By("dropping the overlap, which makes the held secret due for retirement")
			Expect(patchObject("pocketidoidcclient", clientName, userNS,
				`{"spec":{"clientSecretOverlap":null}}`)).To(Succeed())

			By("waiting for the client to hold only the current secret again")
			Eventually(func() []string {
				return clientSecretIDsFromPocketID(clientID)
			}).Should(HaveLen(1))

			By("verifying the superseded value stopped authenticating")
			Expect(authResult(supersededSecret)).To(Equal("invalid_client"))
			Expect(authResult(secretData(credentialsSecret, userNS, "client_secret"))).
				To(Equal("ok"))
		})
	})

	// A secret revoked out-of-band leaves the client unable to authenticate with the value the
	// cluster holds. The operator detects this from the secret set it reads each reconcile — the
	// prefix no longer matching anything — and mints a replacement outside any rotation schedule.
	Context("Self-healing after an out-of-band deletion", func() {
		It("should mint a replacement when its secret is deleted in Pocket-ID", func() {
			before := secretData(credentialsSecret, userNS, "client_secret")

			ids := clientSecretIDsFromPocketID(clientID)
			Expect(ids).To(HaveLen(1))

			By("deleting the operator's secret directly in Pocket-ID")
			deleteClientSecretInPocketID(clientID, ids[0])
			Expect(authResult(before)).To(Equal("invalid_client"))

			By("waiting for the operator to notice and mint a replacement")
			Eventually(func() string {
				return secretData(credentialsSecret, userNS, "client_secret")
			}).ShouldNot(Equal(before))

			By("verifying the replacement authenticates and is the only secret held")
			Expect(authResult(secretData(credentialsSecret, userNS, "client_secret"))).
				To(Equal("ok"))
			Expect(clientSecretIDsFromPocketID(clientID)).To(HaveLen(1))
		})
	})
})
