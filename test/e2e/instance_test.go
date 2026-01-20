//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Operator Health", func() {
	It("should have the operator running", func() {
		Eventually(func(g Gomega) {
			output := kubectlGet("deployment", "pocket-id-operator", "-n", namespace,
				"-o", "jsonpath={.status.availableReplicas}")
			g.Expect(output).To(Equal("1"), "Operator should have 1 available replica")
		}).Should(Succeed())
	})
})

var _ = Describe("PocketIDInstance", Ordered, func() {
	// All tests use the shared instance created in BeforeSuite

	Context("Core Functionality", func() {
		It("should create a Deployment", func() {
			Eventually(func(g Gomega) {
				output := kubectlGet("deployment", instanceName, "-n", instanceNS,
					"-o", "jsonpath={.metadata.name}")
				g.Expect(output).To(Equal(instanceName))
			}).Should(Succeed())
		})

		It("should create a Service on port 1411", func() {
			Eventually(func(g Gomega) {
				output := kubectlGet("service", instanceName, "-n", instanceNS,
					"-o", "jsonpath={.spec.ports[0].port}")
				g.Expect(output).To(Equal("1411"))
			}).Should(Succeed())
		})

		It("should be Ready", func() {
			output := kubectlGet("pocketidinstance", instanceName, "-n", instanceNS,
				"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
			Expect(output).To(Equal("True"))
		})

		It("should create static API key secret automatically", func() {
			staticSecretName := instanceName + "-static-api-key"
			waitForSecretKey(staticSecretName, instanceNS, "token")
		})

		It("should inject STATIC_API_KEY env var into deployment", func() {
			staticSecretName := instanceName + "-static-api-key"
			Eventually(func(g Gomega) {
				envVarName := kubectlGet("deployment", instanceName, "-n", instanceNS,
					"-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name=='STATIC_API_KEY')].name}")
				g.Expect(envVarName).To(Equal("STATIC_API_KEY"))

				secretName := kubectlGet("deployment", instanceName, "-n", instanceNS,
					"-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name=='STATIC_API_KEY')].valueFrom.secretKeyRef.name}")
				g.Expect(secretName).To(Equal(staticSecretName))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should set static API key secret name in instance status", func() {
			staticSecretName := instanceName + "-static-api-key"
			waitForStatusField("pocketidinstance", instanceName, instanceNS,
				".status.staticApiKeySecretName", staticSecretName)
		})

		It("should set owner reference on static API key secret for garbage collection", func() {
			staticSecretName := instanceName + "-static-api-key"
			Eventually(func(g Gomega) {
				ownerKind := kubectlGet("secret", staticSecretName, "-n", instanceNS,
					"-o", "jsonpath={.metadata.ownerReferences[0].kind}")
				g.Expect(ownerKind).To(Equal("PocketIDInstance"))

				ownerName := kubectlGet("secret", staticSecretName, "-n", instanceNS,
					"-o", "jsonpath={.metadata.ownerReferences[0].name}")
				g.Expect(ownerName).To(Equal(instanceName))

				controller := kubectlGet("secret", staticSecretName, "-n", instanceNS,
					"-o", "jsonpath={.metadata.ownerReferences[0].controller}")
				g.Expect(controller).To(Equal("true"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should set DISABLE_RATE_LIMITING env var (shared instance has it disabled)", func() {
			Eventually(func(g Gomega) {
				output := kubectlGet("deployment", instanceName, "-n", instanceNS,
					"-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name=='DISABLE_RATE_LIMITING')].value}")
				g.Expect(output).To(Equal("true"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
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

// Tests that require creating additional instances
var _ = Describe("PocketIDInstance Multi-Instance Features", Ordered, func() {
	Context("Instance Selector", func() {
		It("should reconcile a labeled instance with a matching user selector", func() {
			const selectorUser = "selector-test-user"
			const selectorInstance = "selector-test-instance"

			By("creating a test instance with labels")
			createInstanceAndWaitReady(InstanceOptions{
				Name:                      selectorInstance,
				DisableGlobalRateLimiting: boolPtr(true),
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

	Context("Instance Deletion Cascades Secret Deletion", func() {
		It("should delete static API key secret when instance is deleted", func() {
			const testInstance = "static-key-deletion-test"
			staticSecretName := testInstance + "-static-api-key"

			By("creating a test instance")
			createInstanceAndWaitReady(InstanceOptions{
				Name:                      testInstance,
				DisableGlobalRateLimiting: boolPtr(true),
			})

			By("waiting for static API key secret")
			waitForSecretKey(staticSecretName, instanceNS, "token")

			By("deleting the instance")
			Expect(kubectlDeleteWait("pocketidinstance", testInstance, instanceNS, 30*time.Second)).To(Succeed())

			By("verifying secret is deleted")
			waitForSecretNotExists(staticSecretName, instanceNS)
		})
	})

	Context("Storage Persistence", func() {
		It("should provision storage when persistence is enabled", func() {
			const persistenceInstance = "persistence-test-instance"
			pvcName := persistenceInstance + "-data"

			By("creating an instance with persistence enabled")
			createInstance(InstanceOptions{
				Name:                      persistenceInstance,
				DisableGlobalRateLimiting: boolPtr(true),
				PersistenceEnabled:        boolPtr(true),
				PersistenceSize:           "2Gi",
			})

			By("verifying PVC is created with correct size")
			Eventually(func(g Gomega) {
				output := kubectlGet("pvc", pvcName, "-n", instanceNS,
					"-o", "jsonpath={.spec.resources.requests.storage}")
				g.Expect(output).To(Equal("2Gi"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying deployment mounts the PVC")
			Eventually(func(g Gomega) {
				volumeName := kubectlGet("deployment", persistenceInstance, "-n", instanceNS,
					"-o", "jsonpath={.spec.template.spec.volumes[?(@.name=='data')].persistentVolumeClaim.claimName}")
				g.Expect(volumeName).To(Equal(pvcName))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("cleaning up")
			Expect(kubectlDeleteWait("pocketidinstance", persistenceInstance, instanceNS, 60*time.Second)).To(Succeed())
		})

		It("should mount existing claims when configured", func() {
			const existingClaimInstance = "existing-claim-test-instance"
			const existingPVC = "my-existing-pvc"

			By("creating an existing PVC")
			applyYAML(createPVCYAML(existingPVC, instanceNS, "3Gi"))

			By("creating an instance that references the existing PVC")
			createInstance(InstanceOptions{
				Name:                      existingClaimInstance,
				DisableGlobalRateLimiting: boolPtr(true),
				PersistenceEnabled:        boolPtr(true),
				ExistingClaim:             existingPVC,
			})

			By("verifying deployment mounts the existing PVC")
			Eventually(func(g Gomega) {
				volumeName := kubectlGet("deployment", existingClaimInstance, "-n", instanceNS,
					"-o", "jsonpath={.spec.template.spec.volumes[?(@.name=='data')].persistentVolumeClaim.claimName}")
				g.Expect(volumeName).To(Equal(existingPVC))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying no new PVC was created")
			output := kubectlGet("pvc", existingClaimInstance+"-data", "-n", instanceNS, "-o", "name")
			Expect(output).To(BeEmpty(), "Should not create a new PVC when existingClaim is specified")

			By("cleaning up")
			Expect(kubectlDeleteWait("pocketidinstance", existingClaimInstance, instanceNS, 60*time.Second)).To(Succeed())
			kubectlDelete("pvc", existingPVC, instanceNS)
		})
	})

	Context("Rate Limiting Configuration", func() {
		It("should NOT set DISABLE_RATE_LIMITING when rate limiting is enabled (default)", func() {
			const rateLimitInstance = "rate-limit-enabled-instance"

			By("creating an instance with default rate limiting (enabled)")
			createInstance(InstanceOptions{
				Name:                      rateLimitInstance,
				DisableGlobalRateLimiting: boolPtr(false),
			})

			By("verifying DISABLE_RATE_LIMITING env var is not set")
			Eventually(func(g Gomega) {
				output := kubectlGet("deployment", rateLimitInstance, "-n", instanceNS,
					"-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name=='DISABLE_RATE_LIMITING')].name}")
				g.Expect(output).To(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("cleaning up")
			Expect(kubectlDeleteWait("pocketidinstance", rateLimitInstance, instanceNS, 60*time.Second)).To(Succeed())
		})
	})
})

// Helper to format instance URL for curl pods
func formatInstanceURL() string {
	return fmt.Sprintf("http://%s.%s.svc.cluster.local:1411", instanceName, instanceNS)
}
