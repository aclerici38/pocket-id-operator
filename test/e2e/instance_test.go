//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("PocketIDInstance", Ordered, func() {

	Context("Core Functionality", func() {
		It("should be Ready", func() {
			// Read-only against the shared instance: nothing in this file rolls it any
			// more, but polling costs nothing and tolerates a resync landing mid-check.
			waitForReady("pocketidinstance", instanceName, instanceNS)
		})

	})

	Context("Static API Key Secret Lifecycle", func() {
		It("should regenerate static API key secret if deleted and rollout instance", func() {
			// Its own instance: this deletes the static API key and waits out a full
			// rollout. Doing that to the shared instance would restart the Pocket-ID
			// every other spec is talking to, and with no persistence configured a
			// restart takes its database with it.
			const keyInstance = "static-key-test-instance"
			keyInstanceLabels := map[string]string{"e2e-instance": "static-key"}
			staticSecretName := keyInstance + "-static-api-key"

			DeferCleanup(func() {
				_ = deleteObjectAndWait("pocketidinstance", keyInstance, instanceNS, 2*time.Minute)
			})

			By("creating an instance of its own to rotate the key on")
			createInstanceAndWaitReady(InstanceOptions{
				Name:   keyInstance,
				Labels: keyInstanceLabels,
			})

			By("reading the original token")
			originalToken := waitForSecretKey(staticSecretName, instanceNS, "token")

			By("getting the current deployment's pod template hash annotation")
			originalHash := getField("deployment", keyInstance, instanceNS,
				".spec.template.metadata.annotations.pocketid\\.internal/static-api-key-hash")
			Expect(originalHash).NotTo(BeEmpty(), "Deployment should have static-api-key-hash annotation")

			By("getting the current pod name")
			originalPodName := getFieldBySelector("pod", instanceNS, "app.kubernetes.io/instance="+keyInstance,
				".metadata.name")
			Expect(originalPodName).NotTo(BeEmpty())

			By("deleting the static API key secret")
			Expect(deleteObjectAndWait("secret", staticSecretName, instanceNS, 30*time.Second)).To(Succeed())

			By("verifying secret is recreated with new token")
			Eventually(func(g Gomega) {
				newToken := secretData(staticSecretName, instanceNS, "token")
				g.Expect(newToken).NotTo(BeEmpty())
				g.Expect(newToken).NotTo(Equal(originalToken))
			}).Should(Succeed())

			By("verifying deployment's hash annotation changed (triggers rollout)")
			Eventually(func(g Gomega) {
				newHash := getField("deployment", keyInstance, instanceNS,
					".spec.template.metadata.annotations.pocketid\\.internal/static-api-key-hash")
				g.Expect(newHash).NotTo(BeEmpty())
				g.Expect(newHash).NotTo(Equal(originalHash))
			}).Should(Succeed())

			By("verifying instance rolled out with new pod")
			Eventually(func(g Gomega) {
				// Get the current pod name - should be different after rollout
				currentPodName := getFieldBySelector("pod", instanceNS, "app.kubernetes.io/instance="+keyInstance,
					".metadata.name")
				g.Expect(currentPodName).NotTo(BeEmpty())
				g.Expect(currentPodName).NotTo(Equal(originalPodName), "Pod should have been replaced by rollout")
			}).Should(Succeed())

			By("verifying the new pod is running")
			Eventually(func(g Gomega) {
				status := getFieldBySelector("pod", instanceNS, "app.kubernetes.io/instance="+keyInstance, ".status.phase")
				g.Expect(status).To(Equal("Running"))
			}).Should(Succeed())

			// Selected onto the rotated instance on purpose: against the shared instance
			// this would succeed using a key that never changed, proving nothing.
			By("verifying operator can still authenticate with new API key by creating a user")
			testUserName := "api-key-rotation-test-user"
			createUser(UserOptions{
				Name:             testUserName,
				Username:         "api-key-rotation-test",
				FirstName:        "APIKey",
				LastName:         "RotationTest",
				Email:            "apikey-rotation@example.local",
				InstanceSelector: keyInstanceLabels,
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
var _ = Describe("PocketIDInstance Multi-Instance Features", Ordered, func() {
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

// Ginkgo runs Serial specs last, on process 1, once every parallel spec has finished and its
// own instance has been cleaned up — so by the time this runs the shared instance is the only
// one in the cluster. That is exactly the condition it needs, and the scheduler provides it
// without any coordination of our own.
//
// Every other resource in this suite names its instance explicitly, which keeps second
// instances from making anyone's reconcile ambiguous but also means nothing else exercises the
// default: no instanceSelector at all. That is the configuration nearly every real deployment
// has, so it is worth one spec that pays for a short serial tail.
//
// A failure here reads two ways, and both are worth knowing: either the selectorless path
// broke, or a spec leaked an instance and left the cluster ambiguous.
var _ = Describe("PocketIDInstance Default Selection", Serial, func() {
	It("should reconcile a resource that names no instance when only one exists", func() {
		const defaultUser = "default-selection-user"

		DeferCleanup(func() {
			_ = deleteObjectAndWait("pocketiduser", defaultUser, userNS, time.Minute)
		})

		By("confirming the shared instance is the only one in the cluster")
		Expect(listNames("pocketidinstance", instanceNS)).To(ConsistOf(instanceName),
			"a spec leaked an instance; a resource without a selector cannot resolve one")

		// Written out rather than built through createUser: the helper defaults an unset
		// selector to the shared instance, which is the opposite of what this asserts. The
		// manifest below is what a user's first PocketIDUser actually looks like.
		By("creating a user whose manifest has no instanceSelector")
		applyYAML(fmt.Sprintf(`apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
spec: {}`, defaultUser, userNS))

		By("verifying it reconciled against the only instance")
		waitForReady("pocketiduser", defaultUser, userNS)
		Expect(getField("pocketiduser", defaultUser, userNS, ".status.userID")).NotTo(BeEmpty())
	})
})
