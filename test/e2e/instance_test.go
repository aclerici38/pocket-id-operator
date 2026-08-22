//go:build e2e
// +build e2e

package e2e

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("PocketIDInstance", Serial, Ordered, func() {
	// All tests use the shared instance created in BeforeSuite

	Context("Core Functionality", func() {
		It("should be Ready", func() {
			// The shared instance can be briefly rolling (e.g. after the HTTPRoute
			// suite toggles its route), so poll rather than asserting once.
			waitForReady("pocketidinstance", instanceName, instanceNS)
		})

	})

	Context("Static API Key Secret Lifecycle", func() {
		It("should regenerate static API key secret if deleted and rollout instance", func() {
			staticSecretName := instanceName + "-static-api-key"

			By("reading the original token")
			originalToken := waitForSecretKey(staticSecretName, instanceNS, "token")

			By("getting the current deployment's pod template hash annotation")
			originalHash := getField("deployment", instanceName, instanceNS,
				".spec.template.metadata.annotations.pocketid\\.internal/static-api-key-hash")
			Expect(originalHash).NotTo(BeEmpty(), "Deployment should have static-api-key-hash annotation")

			By("getting the current pod name")
			originalPodName := getFieldBySelector("pod", instanceNS, "app.kubernetes.io/instance="+instanceName,
				".metadata.name")
			Expect(originalPodName).NotTo(BeEmpty())

			By("deleting the static API key secret")
			Expect(deleteObjectAndWait("secret", staticSecretName, instanceNS, 30*time.Second)).To(Succeed())

			By("verifying secret is recreated with new token")
			Eventually(func(g Gomega) {
				newToken := secretData(staticSecretName, instanceNS, "token")
				g.Expect(newToken).NotTo(BeEmpty())
				g.Expect(newToken).NotTo(Equal(originalToken))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying deployment's hash annotation changed (triggers rollout)")
			Eventually(func(g Gomega) {
				newHash := getField("deployment", instanceName, instanceNS,
					".spec.template.metadata.annotations.pocketid\\.internal/static-api-key-hash")
				g.Expect(newHash).NotTo(BeEmpty())
				g.Expect(newHash).NotTo(Equal(originalHash))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying instance rolled out with new pod")
			Eventually(func(g Gomega) {
				// Get the current pod name - should be different after rollout
				currentPodName := getFieldBySelector("pod", instanceNS, "app.kubernetes.io/instance="+instanceName,
					".metadata.name")
				g.Expect(currentPodName).NotTo(BeEmpty())
				g.Expect(currentPodName).NotTo(Equal(originalPodName), "Pod should have been replaced by rollout")
			}, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the new pod is running")
			Eventually(func(g Gomega) {
				status := getFieldBySelector("pod", instanceNS, "app.kubernetes.io/instance="+instanceName, ".status.phase")
				g.Expect(status).To(Equal("Running"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying operator can still authenticate with new API key by creating a user")
			testUserName := "api-key-rotation-test-user"
			createUser(UserOptions{
				Name:      testUserName,
				Username:  "api-key-rotation-test",
				FirstName: "APIKey",
				LastName:  "RotationTest",
				Email:     "apikey-rotation@example.local",
			})

			By("verifying the user becomes Ready (confirms operator authenticated successfully)")
			waitForReady("pocketiduser", testUserName, userNS)

			By("verifying the user has a userID in status (confirms API call succeeded)")
			userID := waitForStatusFieldNotEmpty("pocketiduser", testUserName, userNS, ".status.userID")
			Expect(userID).NotTo(BeEmpty())

			By("cleaning up test user")
			deleteObject("pocketiduser", testUserName, userNS)
		})
	})
})

// Tests that require creating additional instances - must run serially
var _ = Describe("PocketIDInstance Multi-Instance Features", Serial, Ordered, func() {
	Context("Instance Selector", func() {
		It("should reconcile a labeled instance with a matching user selector", func() {
			const selectorUser = "selector-test-user"
			const selectorInstance = "selector-test-instance"

			By("creating a test instance with labels")
			createInstanceAndWaitReady(InstanceOptions{
				Name: selectorInstance,
				Labels: map[string]string{
					"environment": "test",
					"team":        "platform",
				},
			})

			By("creating a user with instance selector")
			createUserAndWaitReady(UserOptions{
				Name:  selectorUser,
				Admin: boolPtr(true),
				InstanceSelector: map[string]string{
					"environment": "test",
					"team":        "platform",
				},
			})

			By("verifying userID is set")
			userID := getField("pocketiduser", selectorUser, userNS, ".status.userID")
			Expect(userID).NotTo(BeEmpty())

			By("cleaning up user")
			Expect(deleteObjectAndWait("pocketiduser", selectorUser, userNS, 30*time.Second)).To(Succeed())

			By("cleaning up instance")
			Expect(deleteObjectAndWait("pocketidinstance", selectorInstance, instanceNS, 60*time.Second)).To(Succeed())
		})
	})

	Context("TLS Termination", func() {
		It("should serve HTTPS from the mounted certificate and stay manageable", func() {
			const tlsInstance = "tls-test-instance"
			const tlsSecret = "tls-test-cert"
			const tlsUser = "tls-test-user"
			tlsLabels := map[string]string{"tls": "enabled"}

			// A leftover second instance would break every later spec that selects the
			// shared instance without a selector, so clean up even on failure.
			DeferCleanup(func() {
				deleteObject("pocketiduser", tlsUser, userNS)
				_ = deleteObjectAndWait("pocketidinstance", tlsInstance, instanceNS, 60*time.Second)
				deleteObject("secret", tlsSecret, instanceNS)
			})

			// The hostname is not the Service DNS name the operator dials, mirroring a
			// real certificate issued for the instance's public URL.
			By("creating a self-signed certificate for an unrelated hostname")
			applyTLSSecret(tlsSecret, instanceNS, "pocket-id.example.com")

			By("creating a TLS-enabled instance")
			createInstanceAndWaitReady(InstanceOptions{
				Name:          tlsInstance,
				Labels:        tlsLabels,
				TLSSecretName: tlsSecret,
			})

			By("verifying the reported version proves an API call over TLS")
			waitForStatusFieldNotEmpty("pocketidinstance", tlsInstance, instanceNS, ".status.version")

			// An API key goes through the session-auth path, which uses a separate HTTP
			// client from the generated API client and needs the same trust store.
			By("provisioning a user with an API key against the TLS instance")
			createUserAndWaitReady(UserOptions{
				Name:             tlsUser,
				Admin:            boolPtr(true),
				InstanceSelector: tlsLabels,
				APIKeys:          []APIKeySpec{{Name: "tls-key", Description: "over TLS"}},
			})
			secretName := getField("pocketiduser", tlsUser, userNS, ".status.apiKeys[0].secretName")
			Expect(secretName).NotTo(BeEmpty())
			waitForSecretKey(secretName, userNS, "token")
		})
	})

	Context("Instance Deletion Cascades Secret Deletion", func() {
		It("should delete static API key secret when instance is deleted", func() {
			const testInstance = "static-key-deletion-test"
			staticSecretName := testInstance + "-static-api-key"

			By("creating a test instance")
			createInstanceAndWaitReady(InstanceOptions{
				Name: testInstance,
			})

			By("waiting for static API key secret")
			waitForSecretKey(staticSecretName, instanceNS, "token")

			By("deleting the instance")
			Expect(deleteObjectAndWait("pocketidinstance", testInstance, instanceNS, 30*time.Second)).To(Succeed())

			By("verifying secret is deleted")
			waitForSecretNotExists(staticSecretName, instanceNS)
		})
	})

})
