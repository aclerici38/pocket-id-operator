//go:build e2e
// +build e2e

package e2e

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Operator Health", Serial, func() {
	It("should have the operator running", func() {
		Eventually(func(g Gomega) {
			output := kubectlGet("deployment", "pocket-id-operator", "-n", namespace,
				"-o", "jsonpath={.status.availableReplicas}")
			g.Expect(output).To(Equal("1"), "Operator should have 1 available replica")
		}).Should(Succeed())
	})
})

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
			originalHash := kubectlGet("deployment", instanceName, "-n", instanceNS,
				"-o", "jsonpath={.spec.template.metadata.annotations.pocketid\\.internal/static-api-key-hash}")
			Expect(originalHash).NotTo(BeEmpty(), "Deployment should have static-api-key-hash annotation")

			By("getting the current pod name")
			originalPodName := kubectlGet("pod", "-l", "app.kubernetes.io/instance="+instanceName, "-n", instanceNS,
				"-o", "jsonpath={.items[0].metadata.name}")
			Expect(originalPodName).NotTo(BeEmpty())

			By("deleting the static API key secret")
			Expect(kubectlDeleteWait("secret", staticSecretName, instanceNS, 30*time.Second)).To(Succeed())

			By("verifying secret is recreated with new token")
			Eventually(func(g Gomega) {
				newToken := kubectlGetSecretData(staticSecretName, instanceNS, "token")
				g.Expect(newToken).NotTo(BeEmpty())
				g.Expect(newToken).NotTo(Equal(originalToken))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying deployment's hash annotation changed (triggers rollout)")
			Eventually(func(g Gomega) {
				newHash := kubectlGet("deployment", instanceName, "-n", instanceNS,
					"-o", "jsonpath={.spec.template.metadata.annotations.pocketid\\.internal/static-api-key-hash}")
				g.Expect(newHash).NotTo(BeEmpty())
				g.Expect(newHash).NotTo(Equal(originalHash))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying instance rolled out with new pod")
			Eventually(func(g Gomega) {
				// Get the current pod name - should be different after rollout
				currentPodName := kubectlGet("pod", "-l", "app.kubernetes.io/instance="+instanceName, "-n", instanceNS,
					"-o", "jsonpath={.items[0].metadata.name}")
				g.Expect(currentPodName).NotTo(BeEmpty())
				g.Expect(currentPodName).NotTo(Equal(originalPodName), "Pod should have been replaced by rollout")
			}, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the new pod is running")
			Eventually(func(g Gomega) {
				status := kubectlGet("pod", "-l", "app.kubernetes.io/instance="+instanceName, "-n", instanceNS,
					"-o", "jsonpath={.items[0].status.phase}")
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
			kubectlDelete("pocketiduser", testUserName, userNS)
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
			userID := kubectlGet("pocketiduser", selectorUser, "-n", userNS,
				"-o", "jsonpath={.status.userID}")
			Expect(userID).NotTo(BeEmpty())

			By("cleaning up user")
			Expect(kubectlDeleteWait("pocketiduser", selectorUser, userNS, 30*time.Second)).To(Succeed())

			By("cleaning up instance")
			Expect(kubectlDeleteWait("pocketidinstance", selectorInstance, instanceNS, 60*time.Second)).To(Succeed())
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
				kubectlDelete("pocketiduser", tlsUser, userNS)
				_ = kubectlDeleteWait("pocketidinstance", tlsInstance, instanceNS, 60*time.Second)
				kubectlDelete("secret", tlsSecret, instanceNS)
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

			By("verifying the certificate is mounted and pointed at with the _FILE variants")
			Expect(kubectlGet("deployment", tlsInstance, "-n", instanceNS,
				"-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name=='TLS_CERT_FILE')].value}")).
				To(Equal("/etc/pocket-id/tls/tls.crt"))
			Expect(kubectlGet("deployment", tlsInstance, "-n", instanceNS,
				"-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name=='TLS_KEY_FILE')].value}")).
				To(Equal("/etc/pocket-id/tls/tls.key"))
			Expect(kubectlGet("deployment", tlsInstance, "-n", instanceNS,
				"-o", "jsonpath={.spec.template.spec.volumes[?(@.name=='tls')].secret.secretName}")).
				To(Equal(tlsSecret))

			By("verifying the probes use the HTTPS scheme")
			Expect(kubectlGet("deployment", tlsInstance, "-n", instanceNS,
				"-o", "jsonpath={.spec.template.spec.containers[0].readinessProbe.httpGet.scheme}")).
				To(Equal("HTTPS"))

			By("verifying the Service advertises the https appProtocol")
			Expect(kubectlGet("service", tlsInstance, "-n", instanceNS,
				"-o", "jsonpath={.spec.ports[?(@.name=='http')].appProtocol}")).
				To(Equal("https"))

			// Readiness only proves the pod passes its HTTPS probes; the reported version
			// comes from the operator's own API call, so it also covers the client side.
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
			secretName := kubectlGet("pocketiduser", tlsUser, "-n", userNS,
				"-o", "jsonpath={.status.apiKeys[0].secretName}")
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
			Expect(kubectlDeleteWait("pocketidinstance", testInstance, instanceNS, 30*time.Second)).To(Succeed())

			By("verifying secret is deleted")
			waitForSecretNotExists(staticSecretName, instanceNS)
		})
	})

})
