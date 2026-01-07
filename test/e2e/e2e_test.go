//go:build e2e
// +build e2e

/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aclerici38/pocket-id-operator/test/utils"
)

// namespace where the project is deployed in
const namespace = "pocket-id-operator-system"

// testNamespace where test resources are created
const testNamespace = "pocket-id-test"

// serviceAccountName created for the project
const serviceAccountName = "pocket-id-operator"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "pocket-id-operator-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "pocket-id-operator-metrics-binding"

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("cleaning up the metrics ClusterRoleBinding")
		cmd = exec.Command("kubectl", "delete", "clusterrolebinding", metricsRoleBindingName, "--ignore-not-found")
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Metrics logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl-metrics logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				// Get the name of the controller-manager pod
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("pocket-id-operator"))

				// Validate the pod's status
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			// Delete existing binding first to avoid "already exists" error
			cmd := exec.Command("kubectl", "delete", "clusterrolebinding", metricsRoleBindingName, "--ignore-not-found")
			_, _ = utils.Run(cmd)

			cmd = exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				"--clusterrole=pocket-id-operator-metrics-reader",
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
			)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create ClusterRoleBinding")

			By("validating that the metrics service is available")
			cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("getting the service account token")
			token, err := serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("ensuring the controller pod is ready")
			verifyControllerPodReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", controllerPodName, "-n", namespace,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "Controller pod not ready")
			}
			Eventually(verifyControllerPodReady, 3*time.Minute, time.Second).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("Serving metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted, 3*time.Minute, time.Second).Should(Succeed())

			// +kubebuilder:scaffold:e2e-metrics-webhooks-readiness

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"command": ["/bin/sh", "-c"],
							"args": ["curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics"],
							"securityContext": {
								"readOnlyRootFilesystem": true,
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccountName": "%s"
					}
				}`, token, metricsServiceName, namespace, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 5*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			verifyMetricsAvailable := func(g Gomega) {
				metricsOutput, err := getMetricsOutput()
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
				g.Expect(metricsOutput).NotTo(BeEmpty())
				g.Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
			}
			Eventually(verifyMetricsAvailable, 2*time.Minute).Should(Succeed())
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks
	})

	Context("PocketIDInstance CR", func() {
		BeforeAll(func() {
			By("creating the test namespace")
			cmd := exec.Command("kubectl", "create", "ns", testNamespace, "--dry-run=client", "-o", "yaml")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(output)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("creating a secret for encryption key")
			cmd = exec.Command("kubectl", "create", "secret", "generic", "pocket-id-encryption",
				"--from-literal=key=test-encryption-key-32chars",
				"-n", testNamespace)
			_, _ = utils.Run(cmd) // Ignore error if already exists
		})

		AfterAll(func() {
			By("removing finalizers from any stuck resources in test namespace")
			// Remove finalizers from PocketIDUsers
			cmd := exec.Command("kubectl", "get", "pocketidusers", "-n", testNamespace,
				"-o", "jsonpath={.items[*].metadata.name}")
			if output, err := utils.Run(cmd); err == nil && output != "" {
				for _, name := range strings.Fields(output) {
					patchCmd := exec.Command("kubectl", "patch", "pocketiduser", name,
						"-n", testNamespace,
						"--type=merge", "-p", `{"metadata":{"finalizers":null}}`)
					_, _ = utils.Run(patchCmd)
				}
			}

			// Remove finalizers from PocketIDInstances
			cmd = exec.Command("kubectl", "get", "pocketidinstances", "-n", testNamespace,
				"-o", "jsonpath={.items[*].metadata.name}")
			if output, err := utils.Run(cmd); err == nil && output != "" {
				for _, name := range strings.Fields(output) {
					patchCmd := exec.Command("kubectl", "patch", "pocketidinstance", name,
						"-n", testNamespace,
						"--type=merge", "-p", `{"metadata":{"finalizers":null}}`)
					_, _ = utils.Run(patchCmd)
				}
			}

			By("cleaning up test namespace")
			cmd = exec.Command("kubectl", "delete", "ns", testNamespace, "--ignore-not-found", "--timeout=60s")
			_, _ = utils.Run(cmd)
		})

		It("should create a PocketIDInstance with Deployment", func() {
			instanceYAML := fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDInstance
metadata:
  name: test-instance
  namespace: %s
spec:
  deploymentType: Deployment
  image: ghcr.io/pocket-id/pocket-id:latest
  encryptionKey:
    valueFrom:
      secretKeyRef:
        name: pocket-id-encryption
        key: key
  appUrl: "https://auth.example.com"
`, testNamespace)

			By("applying the PocketIDInstance CR")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(instanceYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create PocketIDInstance")

			By("verifying the Deployment is created")
			verifyDeployment := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "deployment", "test-instance",
					"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("test-instance"))
			}
			Eventually(verifyDeployment, 2*time.Minute, time.Second).Should(Succeed())

			By("verifying the Service is created")
			verifyService := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "service", "test-instance",
					"-n", testNamespace, "-o", "jsonpath={.spec.ports[0].port}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("1411"))
			}
			Eventually(verifyService, time.Minute, time.Second).Should(Succeed())

			By("cleaning up the instance")
			cmd = exec.Command("kubectl", "delete", "pocketidinstance", "test-instance",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should create a PocketIDInstance with StatefulSet", func() {
			instanceYAML := fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDInstance
metadata:
  name: test-sts-instance
  namespace: %s
spec:
  deploymentType: StatefulSet
  encryptionKey:
    valueFrom:
      secretKeyRef:
        name: pocket-id-encryption
        key: key
`, testNamespace)

			By("applying the PocketIDInstance CR")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(instanceYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create PocketIDInstance")

			By("verifying the StatefulSet is created")
			verifyStatefulSet := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "statefulset", "test-sts-instance",
					"-n", testNamespace, "-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("test-sts-instance"))
			}
			Eventually(verifyStatefulSet, 2*time.Minute, time.Second).Should(Succeed())

			By("cleaning up the instance")
			cmd = exec.Command("kubectl", "delete", "pocketidinstance", "test-sts-instance",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})
	})

	Context("Bootstrap and API Key Authentication", func() {
		const bootstrapNamespace = "pocket-id-bootstrap-test"

		BeforeAll(func() {
			By("creating the bootstrap test namespace")
			cmd := exec.Command("kubectl", "create", "ns", bootstrapNamespace)
			_, _ = utils.Run(cmd) // Ignore if exists

			By("labeling the namespace to enforce the restricted security policy")
			cmd = exec.Command("kubectl", "label", "--overwrite", "ns", bootstrapNamespace,
				"pod-security.kubernetes.io/enforce=baseline",
				"pod-security.kubernetes.io/warn=restricted")
			_, _ = utils.Run(cmd)

			By("creating a secret for encryption key")
			cmd = exec.Command("kubectl", "create", "secret", "generic", "pocket-id-encryption",
				"--from-literal=key=bootstrap-test-encryption-key-32chars",
				"-n", bootstrapNamespace)
			_, _ = utils.Run(cmd) // Ignore if exists
		})

		AfterAll(func() {
			By("removing finalizers from any stuck resources")
			// Remove finalizers from PocketIDUsers to prevent namespace from being stuck
			cmd := exec.Command("kubectl", "get", "pocketidusers", "-n", bootstrapNamespace,
				"-o", "jsonpath={.items[*].metadata.name}")
			if output, err := utils.Run(cmd); err == nil && output != "" {
				for _, name := range strings.Fields(output) {
					patchCmd := exec.Command("kubectl", "patch", "pocketiduser", name,
						"-n", bootstrapNamespace,
						"--type=merge", "-p", `{"metadata":{"finalizers":null}}`)
					_, _ = utils.Run(patchCmd)
				}
			}

			// Remove finalizers from PocketIDInstances
			cmd = exec.Command("kubectl", "get", "pocketidinstances", "-n", bootstrapNamespace,
				"-o", "jsonpath={.items[*].metadata.name}")
			if output, err := utils.Run(cmd); err == nil && output != "" {
				for _, name := range strings.Fields(output) {
					patchCmd := exec.Command("kubectl", "patch", "pocketidinstance", name,
						"-n", bootstrapNamespace,
						"--type=merge", "-p", `{"metadata":{"finalizers":null}}`)
					_, _ = utils.Run(patchCmd)
				}
			}

			By("cleaning up bootstrap test namespace")
			cmd = exec.Command("kubectl", "delete", "ns", bootstrapNamespace, "--ignore-not-found", "--timeout=60s")
			_, _ = utils.Run(cmd)
		})

		It("should bootstrap an instance and create the operator user with API key", func(ctx SpecContext) {
			// Ensure cleanup happens regardless of test outcome
			DeferCleanup(func() {
				By("cleaning up bootstrap test resources")
				// Remove finalizers first to prevent stuck deletion
				cmd := exec.Command("kubectl", "patch", "pocketiduser", "pocket-id-operator",
					"-n", bootstrapNamespace,
					"--type=merge", "-p", `{"metadata":{"finalizers":null}}`)
				_, _ = utils.Run(cmd)

				cmd = exec.Command("kubectl", "patch", "pocketidinstance", "bootstrap-test",
					"-n", bootstrapNamespace,
					"--type=merge", "-p", `{"metadata":{"finalizers":null}}`)
				_, _ = utils.Run(cmd)

				cmd = exec.Command("kubectl", "delete", "pocketidinstance", "bootstrap-test",
					"-n", bootstrapNamespace, "--ignore-not-found", "--timeout=30s")
				_, _ = utils.Run(cmd)

				cmd = exec.Command("kubectl", "delete", "pocketiduser", "pocket-id-operator",
					"-n", bootstrapNamespace, "--ignore-not-found", "--timeout=30s")
				_, _ = utils.Run(cmd)

				cmd = exec.Command("kubectl", "delete", "pod", "api-key-test",
					"-n", bootstrapNamespace, "--ignore-not-found")
				_, _ = utils.Run(cmd)
			})

			// Create the User CR first - the instance will wait for it before bootstrapping
			userYAML := fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: pocket-id-operator
  namespace: %s
spec:
  username:
    value: pocket-id-operator
  firstName:
    value: Operator
  lastName:
    value: Admin
  email:
    value: operator@test.local
  admin: true
  apiKeys:
  - name: pocket-id-operator
    description: Operator API key for bootstrap
`, bootstrapNamespace)

			By("creating the PocketIDUser CR first")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(userYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create PocketIDUser")

			// Create a PocketIDInstance without explicit auth config
			// The controller should use defaults (pocket-id-operator user and API key)
			instanceYAML := fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDInstance
metadata:
  name: bootstrap-test
  namespace: %s
spec:
  deploymentType: Deployment
  image: ghcr.io/pocket-id/pocket-id:latest
  encryptionKey:
    valueFrom:
      secretKeyRef:
        name: pocket-id-encryption
        key: key
  appUrl: "http://bootstrap-test.%s.svc.cluster.local:1411"
`, bootstrapNamespace, bootstrapNamespace)

			By("applying the PocketIDInstance CR without auth config")
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(instanceYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create PocketIDInstance")

			By("verifying the Deployment is created")
			verifyDeployment := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "deployment", "bootstrap-test",
					"-n", bootstrapNamespace, "-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("bootstrap-test"))
			}
			Eventually(verifyDeployment, 2*time.Minute, time.Second).Should(Succeed())

			By("verifying the Service is created")
			verifyService := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "service", "bootstrap-test",
					"-n", bootstrapNamespace, "-o", "jsonpath={.spec.ports[0].port}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("1411"))
			}
			Eventually(verifyService, time.Minute, time.Second).Should(Succeed())

			By("waiting for the deployment to be available")
			verifyDeploymentReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "rollout", "status", "deployment/bootstrap-test",
					"-n", bootstrapNamespace, "--timeout=30s")
				_, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
			}
			Eventually(verifyDeploymentReady, 5*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the instance becomes Available")
			verifyInstanceAvailable := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pocketidinstance", "bootstrap-test",
					"-n", bootstrapNamespace,
					"-o", "jsonpath={.status.conditions[?(@.type=='Available')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "Instance should be Available")
			}
			Eventually(verifyInstanceAvailable, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the API key secret is created with correct naming")
			// Secret name follows pattern: {userRef}-{apiKeyName}-key
			verifyAPIKeySecret := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "secret", "pocket-id-operator-pocket-id-operator-key",
					"-n", bootstrapNamespace, "-o", "jsonpath={.data.token}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty(), "API key token should exist in secret")
			}
			Eventually(verifyAPIKeySecret, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the instance status reflects bootstrap completion")
			verifyInstanceBootstrapped := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pocketidinstance", "bootstrap-test",
					"-n", bootstrapNamespace, "-o", "jsonpath={.status.bootstrapped}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"), "Instance should be bootstrapped")
			}
			Eventually(verifyInstanceBootstrapped, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the user status has the user ID from Pocket-ID")
			verifyUserStatus := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pocketiduser", "pocket-id-operator",
					"-n", bootstrapNamespace, "-o", "jsonpath={.status.userID}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty(), "User should have a userID from Pocket-ID")
			}
			Eventually(verifyUserStatus, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the API key can be used to authenticate with the Pocket-ID API")
			verifyAPIKeyWorks := func(g Gomega) {
				// Get the API key token from the secret (named {userRef}-{apiKeyName}-key)
				cmd := exec.Command("kubectl", "get", "secret", "pocket-id-operator-pocket-id-operator-key",
					"-n", bootstrapNamespace, "-o", "jsonpath={.data.token}")
				tokenBase64, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())

				// Create a pod that uses the API key to call the Pocket-ID API
				curlPodYAML := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: api-key-test
  namespace: %s
spec:
  restartPolicy: Never
  containers:
  - name: curl
    image: curlimages/curl:latest
    command: ["/bin/sh", "-c"]
    args:
    - |
      TOKEN=$(echo '%s' | base64 -d)
      curl -s -f -H "X-API-KEY: $TOKEN" http://bootstrap-test.%s.svc.cluster.local:1411/api/users/me
    securityContext:
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      runAsUser: 1000
`, bootstrapNamespace, tokenBase64, bootstrapNamespace)

				// Delete any existing test pod
				delCmd := exec.Command("kubectl", "delete", "pod", "api-key-test",
					"-n", bootstrapNamespace, "--ignore-not-found")
				_, _ = utils.Run(delCmd)

				// Create the test pod
				cmd = exec.Command("kubectl", "apply", "-f", "-")
				cmd.Stdin = strings.NewReader(curlPodYAML)
				_, err = utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
			}
			Eventually(verifyAPIKeyWorks, time.Minute, 5*time.Second).Should(Succeed())

			By("waiting for the API key test pod to complete")
			verifyAPITestComplete := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", "api-key-test",
					"-n", bootstrapNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "API key test pod should succeed")
			}
			Eventually(verifyAPITestComplete, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the API response contains the operator user")
			cmd = exec.Command("kubectl", "logs", "api-key-test", "-n", bootstrapNamespace)
			logs, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(logs).To(ContainSubstring("pocket-id-operator"), "API response should contain the operator username")
		}, SpecTimeout(10*time.Minute))
	})

	Context("PocketIDUser CR", func() {
		BeforeAll(func() {
			By("ensuring test namespace exists")
			cmd := exec.Command("kubectl", "create", "ns", testNamespace, "--dry-run=client", "-o", "yaml")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(output)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should create a PocketIDUser with plain values", func() {
			userYAML := fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: test-user
  namespace: %s
spec:
  username:
    value: testuser
  firstName:
    value: Test
  lastName:
    value: User
  email:
    value: test@example.com
  admin: false
`, testNamespace)

			By("applying the PocketIDUser CR")
			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(userYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create PocketIDUser")

			By("verifying the PocketIDUser is created")
			verifyUser := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pocketiduser", "test-user",
					"-n", testNamespace, "-o", "jsonpath={.spec.username.value}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("testuser"))
			}
			Eventually(verifyUser, time.Minute, time.Second).Should(Succeed())

			By("cleaning up the user")
			cmd = exec.Command("kubectl", "delete", "pocketiduser", "test-user",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should create a PocketIDUser with secret references", func() {
			By("creating secrets for user data")
			cmd := exec.Command("kubectl", "create", "secret", "generic", "user-data",
				"--from-literal=username=secretuser",
				"--from-literal=email=secret@example.com",
				"-n", testNamespace)
			_, _ = utils.Run(cmd) // Ignore error if already exists

			userYAML := fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: test-secret-user
  namespace: %s
spec:
  username:
    valueFrom:
      name: user-data
      key: username
  firstName:
    value: Secret
  email:
    valueFrom:
      name: user-data
      key: email
  admin: true
`, testNamespace)

			By("applying the PocketIDUser CR")
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(userYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create PocketIDUser")

			By("verifying the PocketIDUser is created")
			verifyUser := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pocketiduser", "test-secret-user",
					"-n", testNamespace, "-o", "jsonpath={.spec.admin}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"))
			}
			Eventually(verifyUser, time.Minute, time.Second).Should(Succeed())

			By("cleaning up")
			cmd = exec.Command("kubectl", "delete", "pocketiduser", "test-secret-user",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "secret", "user-data",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})

		It("should create a PocketIDUser with API key using SecretRef", func() {
			By("creating a secret for existing API key")
			cmd := exec.Command("kubectl", "create", "secret", "generic", "existing-api-key",
				"--from-literal=token=my-existing-api-key-token",
				"-n", testNamespace)
			_, _ = utils.Run(cmd) // Ignore error if already exists

			userYAML := fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: test-apikey-user
  namespace: %s
spec:
  username:
    value: apikeyuser
  firstName:
    value: APIKey
  admin: false
  apiKeys:
  - name: existing-key
    description: Pre-existing API key
    secretRef:
      name: existing-api-key
      key: token
`, testNamespace)

			By("applying the PocketIDUser CR")
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = strings.NewReader(userYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create PocketIDUser")

			By("verifying the PocketIDUser is created with API key")
			verifyUser := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pocketiduser", "test-apikey-user",
					"-n", testNamespace, "-o", "jsonpath={.spec.apiKeys[0].name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("existing-key"))
			}
			Eventually(verifyUser, time.Minute, time.Second).Should(Succeed())

			By("cleaning up")
			cmd = exec.Command("kubectl", "delete", "pocketiduser", "test-apikey-user",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
			cmd = exec.Command("kubectl", "delete", "secret", "existing-api-key",
				"-n", testNamespace, "--ignore-not-found")
			_, _ = utils.Run(cmd)
		})
	})
})

// serviceAccountToken returns a token for the specified service account in the given namespace.
// It uses the Kubernetes TokenRequest API to generate a token by directly sending a request
// and parsing the resulting token from the API response.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	// Temporary file to store the token request
	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		// Execute kubectl command to create the token
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		// Parse the JSON output to extract the token
		var token tokenRequest
		err = json.Unmarshal(output, &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() (string, error) {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	return utils.Run(cmd)
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}
