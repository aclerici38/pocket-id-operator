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
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aclerici38/pocket-id-operator/test/utils"
)

const (
	instanceName     = "e2e-instance"
	operatorUserName = "pocket-id-operator"
)

var _ = Describe("Pocket-ID Operator", Ordered, func() {
	// Single test namespace with a running Pocket-ID instance for all user tests
	const testNS = "pocket-id-e2e-test"

	BeforeAll(func() {
		By("creating test namespace")
		kubectl("create", "ns", testNS, "--dry-run=client", "-o", "yaml").Apply()

		By("creating encryption key secret")
		kubectl("create", "secret", "generic", "pocket-id-encryption",
			"--from-literal=key=e2e-test-encryption-key-32chars!",
			"-n", testNS, "--dry-run=client", "-o", "yaml").Apply()
	})

	AfterAll(func() {
		By("cleaning up test namespace resources")
		removeFinalizers(testNS)

		By("deleting test namespace")
		cmd := exec.Command("kubectl", "delete", "ns", testNS, "--ignore-not-found", "--timeout=60s")
		_, _ = utils.Run(cmd)
	})

	Context("Operator Health", func() {
		It("should have the operator running", func() {
			Eventually(func(g Gomega) {
				output := kubectlGet("deployment", "pocket-id-operator", "-n", namespace,
					"-o", "jsonpath={.status.availableReplicas}")
				g.Expect(output).To(Equal("1"), "Operator should have 1 available replica")
			}).Should(Succeed())
		})
	})

	Context("PocketIDInstance", func() {
		BeforeAll(func() {
			By("creating the operator user for bootstrap")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
spec:
  admin: true
  apiKeys:
  - name: pocket-id-operator
    description: Operator API key
`, operatorUserName, testNS))

			By("creating a PocketIDInstance")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDInstance
metadata:
  name: %s
  namespace: %s
spec:
  image: ghcr.io/pocket-id/pocket-id:latest
  encryptionKey:
    valueFrom:
      secretKeyRef:
        name: pocket-id-encryption
        key: key
  appUrl: "http://%s.%s.svc.cluster.local:1411"
`, instanceName, testNS, instanceName, testNS))
		})

		It("should create a Deployment", func() {
			Eventually(func(g Gomega) {
				output := kubectlGet("deployment", instanceName, "-n", testNS,
					"-o", "jsonpath={.metadata.name}")
				g.Expect(output).To(Equal(instanceName))
			}).Should(Succeed())
		})

		It("should create a Service on port 1411", func() {
			Eventually(func(g Gomega) {
				output := kubectlGet("service", instanceName, "-n", testNS,
					"-o", "jsonpath={.spec.ports[0].port}")
				g.Expect(output).To(Equal("1411"))
			}).Should(Succeed())
		})

		It("should become Available", func() {
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidinstance", instanceName, "-n", testNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Available')].status}")
				g.Expect(output).To(Equal("True"))
			}, 5*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should bootstrap and set status.bootstrapped=true", func() {
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidinstance", instanceName, "-n", testNS,
					"-o", "jsonpath={.status.bootstrapped}")
				g.Expect(output).To(Equal("true"))
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should create the operator API key secret", func() {
			// Secret name format: {userRef}-{apiKeyName}-key
			secretName := "pocket-id-operator-pocket-id-operator-key"
			Eventually(func(g Gomega) {
				output := kubectlGet("secret", secretName, "-n", testNS,
					"-o", "jsonpath={.data.token}")
				g.Expect(output).NotTo(BeEmpty(), "API key token should exist")
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should set authUserRef and authAPIKeyName in instance status", func() {
			Eventually(func(g Gomega) {
				userRef := kubectlGet("pocketidinstance", instanceName, "-n", testNS,
					"-o", "jsonpath={.status.authUserRef}")
				apiKeyName := kubectlGet("pocketidinstance", instanceName, "-n", testNS,
					"-o", "jsonpath={.status.authApiKeyName}")
				g.Expect(userRef).To(Equal(operatorUserName))
				g.Expect(apiKeyName).To(Equal("pocket-id-operator"))
			}).Should(Succeed())
		})

		It("should set userID in operator user status", func() {
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", operatorUserName, "-n", testNS,
					"-o", "jsonpath={.status.userID}")
				g.Expect(output).NotTo(BeEmpty(), "User should have userID from Pocket-ID")
			}).Should(Succeed())
		})

		It("should set one-time login details in operator user status", func() {
			Eventually(func(g Gomega) {
				token := kubectlGet("pocketiduser", operatorUserName, "-n", testNS,
					"-o", "jsonpath={.status.oneTimeLoginToken}")
				loginURL := kubectlGet("pocketiduser", operatorUserName, "-n", testNS,
					"-o", "jsonpath={.status.oneTimeLoginURL}")
				expiresAt := kubectlGet("pocketiduser", operatorUserName, "-n", testNS,
					"-o", "jsonpath={.status.oneTimeLoginExpiresAt}")
				g.Expect(token).NotTo(BeEmpty())
				g.Expect(loginURL).To(ContainSubstring("/lc/"))
				g.Expect(loginURL).To(ContainSubstring(token))
				g.Expect(expiresAt).NotTo(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should set operator user Ready condition to True", func() {
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", operatorUserName, "-n", testNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}).Should(Succeed())
		})
	})

	Context("PocketIDUser", func() {
		It("should create a user with minimal spec and set defaults", func() {
			const userName = "test-minimal-user"

			By("creating user with minimal spec")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
`, userName, testNS))

			By("verifying user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying userID is set")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.userID}")
				g.Expect(output).NotTo(BeEmpty())
			}).Should(Succeed())

			By("verifying username defaults to CR name")
			output := kubectlGet("pocketiduser", userName, "-n", testNS,
				"-o", "jsonpath={.status.username}")
			Expect(output).To(Equal(userName))

			By("verifying email has placeholder default")
			output = kubectlGet("pocketiduser", userName, "-n", testNS,
				"-o", "jsonpath={.status.email}")
			Expect(output).To(Equal(userName + "@placeholder.local"))

			By("verifying one-time login status fields are set")
			Eventually(func(g Gomega) {
				token := kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.oneTimeLoginToken}")
				loginURL := kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.oneTimeLoginURL}")
				expiresAt := kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.oneTimeLoginExpiresAt}")
				g.Expect(token).NotTo(BeEmpty())
				g.Expect(loginURL).To(ContainSubstring("/lc/"))
				g.Expect(loginURL).To(ContainSubstring(token))
				g.Expect(expiresAt).NotTo(BeEmpty())
			}, time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should exchange the one-time access token for a session", func() {
			const userName = "test-login-token-exchange"

			By("creating user with minimal spec")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
`, userName, testNS))

			By("verifying user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			var token string
			By("reading the one-time login token from status")
			Eventually(func(g Gomega) {
				token = kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.oneTimeLoginToken}")
				g.Expect(token).NotTo(BeEmpty())
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("creating a curl pod to exchange the token for a session")
			applyYAML(fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: login-token-exchange-test
  namespace: %s
spec:
  restartPolicy: Never
  containers:
  - name: curl
    image: curlimages/curl:latest
    command: ["/bin/sh", "-c"]
    args:
    - |
      TOKEN='%s'
      curl -sf -D /tmp/headers -o /tmp/user.json -X POST http://e2e-instance.%s.svc.cluster.local:1411/api/one-time-access-token/$TOKEN
      COOKIE=$(awk -F': ' 'tolower($1)=="set-cookie" && $2 ~ /access_token=/ {print $2; exit}' /tmp/headers)
      if [ -z "$COOKIE" ]; then
        echo "missing access token cookie" >&2
        exit 1
      fi
      COOKIE_PAIR=$(echo "$COOKIE" | cut -d';' -f1)
      curl -sf -H "Cookie: $COOKIE_PAIR" http://e2e-instance.%s.svc.cluster.local:1411/api/users/me | grep -q '"username":"%s"'
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      runAsUser: 1000
`, testNS, token, testNS, testNS, userName))

			By("waiting for token exchange pod to succeed")
			Eventually(func(g Gomega) {
				output := kubectlGet("pod", "login-token-exchange-test", "-n", testNS,
					"-o", "jsonpath={.status.phase}")
				g.Expect(output).To(Equal("Succeeded"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should store one-time login details in status", func() {
			const userName = "test-login-token-user"

			By("creating user with minimal spec")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
`, userName, testNS))

			By("verifying user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying one-time login status fields are populated and future-dated")
			Eventually(func(g Gomega) {
				token := kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.oneTimeLoginToken}")
				loginURL := kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.oneTimeLoginURL}")
				expiresAt := kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.oneTimeLoginExpiresAt}")
				g.Expect(token).NotTo(BeEmpty())
				g.Expect(loginURL).To(ContainSubstring("/lc/"))
				g.Expect(loginURL).To(ContainSubstring(token))
				g.Expect(expiresAt).NotTo(BeEmpty())

				parsed, err := time.Parse(time.RFC3339, expiresAt)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(parsed.After(time.Now().Add(-time.Second))).To(BeTrue())
			}, time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should create a user with explicit values", func() {
			const userName = "test-explicit-user"

			By("creating user with all fields")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
spec:
  username:
    value: explicit-username
  firstName:
    value: John
  lastName:
    value: Doe
  email:
    value: john.doe@example.com
  displayName:
    value: John Doe
  admin: false
`, userName, testNS))

			By("verifying user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying status reflects provided values")
			Expect(kubectlGet("pocketiduser", userName, "-n", testNS,
				"-o", "jsonpath={.status.username}")).To(Equal("explicit-username"))
			Expect(kubectlGet("pocketiduser", userName, "-n", testNS,
				"-o", "jsonpath={.status.email}")).To(Equal("john.doe@example.com"))
			Expect(kubectlGet("pocketiduser", userName, "-n", testNS,
				"-o", "jsonpath={.status.displayName}")).To(Equal("John Doe"))
			// isAdmin is omitempty, so false values are omitted from JSON
			Expect(kubectlGet("pocketiduser", userName, "-n", testNS,
				"-o", "jsonpath={.status.isAdmin}")).To(BeEmpty())
		})

		It("should create a user with API key and store token in secret", func() {
			const userName = "test-apikey-user"
			const apiKeyName = "my-api-key"

			By("creating user with API key")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
spec:
  admin: false
  apiKeys:
  - name: %s
    description: Test API key
`, userName, testNS, apiKeyName))

			By("verifying user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying API key appears in status")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.apiKeys[0].name}")
				g.Expect(output).To(Equal(apiKeyName))
			}).Should(Succeed())

			By("verifying API key has ID from Pocket-ID")
			output := kubectlGet("pocketiduser", userName, "-n", testNS,
				"-o", "jsonpath={.status.apiKeys[0].id}")
			Expect(output).NotTo(BeEmpty(), "API key should have ID from Pocket-ID")

			By("verifying secret was created with token")
			secretName := fmt.Sprintf("%s-%s-key", userName, apiKeyName)
			Eventually(func(g Gomega) {
				output := kubectlGet("secret", secretName, "-n", testNS,
					"-o", "jsonpath={.data.token}")
				g.Expect(output).NotTo(BeEmpty(), "Secret should contain token")
			}).Should(Succeed())

			By("verifying secret reference in status")
			output = kubectlGet("pocketiduser", userName, "-n", testNS,
				"-o", "jsonpath={.status.apiKeys[0].secretName}")
			Expect(output).To(Equal(secretName))
		})

		It("should create an API key owned by the target user", func() {
			const userName = "test-apikey-owner-user"
			const apiKeyName = "owner-key"
			const podName = "api-key-owner-test"

			By("creating user with API key")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
spec:
  admin: false
  apiKeys:
  - name: %s
    description: Owner API key
`, userName, testNS, apiKeyName))

			By("verifying user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			secretName := fmt.Sprintf("%s-%s-key", userName, apiKeyName)
			var tokenBase64 string
			By("reading the API key token from the secret")
			Eventually(func(g Gomega) {
				tokenBase64 = kubectlGet("secret", secretName, "-n", testNS,
					"-o", "jsonpath={.data.token}")
				g.Expect(tokenBase64).NotTo(BeEmpty())
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("creating a curl pod to verify the token belongs to the user")
			applyYAML(fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
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
      curl -sf -H "X-API-KEY: $TOKEN" http://e2e-instance.%s.svc.cluster.local:1411/api/users/me | grep -q '"username":"%s"'
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      runAsUser: 1000
`, podName, testNS, tokenBase64, testNS, userName))

			By("waiting for API key owner pod to succeed")
			Eventually(func(g Gomega) {
				output := kubectlGet("pod", podName, "-n", testNS,
					"-o", "jsonpath={.status.phase}")
				g.Expect(output).To(Equal("Succeeded"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should create an admin user", func() {
			const userName = "test-admin-user"

			By("creating admin user")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
spec:
  admin: true
`, userName, testNS))

			By("verifying user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying isAdmin is true in status")
			output := kubectlGet("pocketiduser", userName, "-n", testNS,
				"-o", "jsonpath={.status.isAdmin}")
			Expect(output).To(Equal("true"))
		})

		It("should update user when spec changes", func() {
			const userName = "test-update-user"

			By("creating initial user")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
spec:
  firstName:
    value: Original
  admin: false
`, userName, testNS))

			By("waiting for user to be Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("updating user to admin")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
spec:
  firstName:
    value: Updated
  admin: true
`, userName, testNS))

			By("verifying isAdmin becomes true")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", testNS,
					"-o", "jsonpath={.status.isAdmin}")
				g.Expect(output).To(Equal("true"))
			}, time.Minute, 2*time.Second).Should(Succeed())
		})
	})

	Context("Auth Switch Safeguards", func() {
		It("should delay auth switch until the target user is Ready", func() {
			const unreadyUserName = "auth-unready-user"
			const unreadyAPIKeyName = "auth-unready-key"
			const unreadySecretName = "auth-unready-user-secret"

			By("creating a user that cannot reconcile yet")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
spec:
  username:
    valueFrom:
      name: %s
      key: username
  firstName:
    value: Auth
  email:
    value: auth-unready@example.local
  admin: true
  apiKeys:
  - name: %s
`, unreadyUserName, testNS, unreadySecretName, unreadyAPIKeyName))

			By("verifying the user is not Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", unreadyUserName, "-n", testNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("False"))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("attempting to switch instance auth to the unready user")
			patch := fmt.Sprintf(`{"spec":{"auth":{"userRef":"%s","apiKeyName":"%s"}}}`, unreadyUserName, unreadyAPIKeyName)
			cmd := exec.Command("kubectl", "patch", "pocketidinstance", instanceName, "-n", testNS, "--type=merge", "-p", patch)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying auth switch is delayed")
			Consistently(func() string {
				return kubectlGet("pocketidinstance", instanceName, "-n", testNS,
					"-o", "jsonpath={.status.authUserRef}")
			}, 20*time.Second, 2*time.Second).Should(Equal(operatorUserName))

			By("creating the missing secret to allow user reconciliation")
			applyYAML(fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque
data:
  username: %s
`, unreadySecretName, testNS, "YXV0aC11bnJlYWR5LXVzZXI="))

			By("verifying the user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", unreadyUserName, "-n", testNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying instance authUserRef switches to the ready user")
			Eventually(func(g Gomega) {
				userRef := kubectlGet("pocketidinstance", instanceName, "-n", testNS,
					"-o", "jsonpath={.status.authUserRef}")
				g.Expect(userRef).To(Equal(unreadyUserName))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("switching instance auth back to the operator user")
			patch = fmt.Sprintf(`{"spec":{"auth":{"userRef":"%s","apiKeyName":"%s"}}}`, operatorUserName, "pocket-id-operator")
			cmd = exec.Command("kubectl", "patch", "pocketidinstance", instanceName, "-n", testNS, "--type=merge", "-p", patch)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying instance authUserRef switches back to the operator user")
			Eventually(func(g Gomega) {
				userRef := kubectlGet("pocketidinstance", instanceName, "-n", testNS,
					"-o", "jsonpath={.status.authUserRef}")
				g.Expect(userRef).To(Equal(operatorUserName))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})
	})

	Context("Auth User Finalizer", func() {
		It("should block deletion of the auth user until instance auth changes", func() {
			const newUserName = "auth-switch-user"
			const newAPIKeyName = "auth-switch-key"

			By("creating a new admin user for auth switching")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
spec:
  admin: true
  apiKeys:
  - name: %s
`, newUserName, testNS, newAPIKeyName))

			By("verifying new auth user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", newUserName, "-n", testNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying new auth user API key secret exists")
			secretName := fmt.Sprintf("%s-%s-key", newUserName, newAPIKeyName)
			Eventually(func(g Gomega) {
				output := kubectlGet("secret", secretName, "-n", testNS,
					"-o", "jsonpath={.data.token}")
				g.Expect(output).NotTo(BeEmpty())
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("requesting deletion of the current auth user")
			cmd := exec.Command("kubectl", "delete", "pocketiduser", operatorUserName, "-n", testNS, "--wait=false")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying deletion is blocked by the auth finalizer")
			Eventually(func(g Gomega) {
				deletionTimestamp := kubectlGet("pocketiduser", operatorUserName, "-n", testNS,
					"-o", "jsonpath={.metadata.deletionTimestamp}")
				finalizers := kubectlGet("pocketiduser", operatorUserName, "-n", testNS,
					"-o", "jsonpath={.metadata.finalizers}")
				g.Expect(deletionTimestamp).NotTo(BeEmpty())
				g.Expect(finalizers).To(ContainSubstring("pocketid.internal/auth-user-finalizer"))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("switching instance auth to the new user")
			patch := fmt.Sprintf(`{"spec":{"auth":{"userRef":"%s","apiKeyName":"%s"}}}`, newUserName, newAPIKeyName)
			cmd = exec.Command("kubectl", "patch", "pocketidinstance", instanceName, "-n", testNS, "--type=merge", "-p", patch)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying instance authUserRef updates")
			Eventually(func(g Gomega) {
				userRef := kubectlGet("pocketidinstance", instanceName, "-n", testNS,
					"-o", "jsonpath={.status.authUserRef}")
				g.Expect(userRef).To(Equal(newUserName))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying the old auth user is deleted")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", operatorUserName, "-n", testNS, "-o", "name")
				g.Expect(output).To(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})
	})
})

// Helper functions

func kubectl(args ...string) *kubectlCmd {
	return &kubectlCmd{args: args}
}

type kubectlCmd struct {
	args []string
}

func (k *kubectlCmd) Apply() {
	cmd := exec.Command("kubectl", k.args...)
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred())

	cmd = exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = stringReader(output)
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred())
}

func kubectlGet(args ...string) string {
	cmdArgs := append([]string{"get"}, args...)
	cmd := exec.Command("kubectl", cmdArgs...)
	out, err := utils.Run(cmd)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func applyYAML(yaml string) {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = stringReader(yaml)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred())
}

func removeFinalizers(ns string) {
	// Remove finalizers from PocketIDUsers
	cmd := exec.Command("kubectl", "get", "pocketidusers", "-n", ns,
		"-o", "jsonpath={.items[*].metadata.name}")
	if output, err := utils.Run(cmd); err == nil && output != "" {
		for _, name := range strings.Fields(output) {
			patchCmd := exec.Command("kubectl", "patch", "pocketiduser", name,
				"-n", ns, "--type=merge", "-p", `{"metadata":{"finalizers":null}}`)
			_, _ = utils.Run(patchCmd)
		}
	}

	// Remove finalizers from PocketIDInstances
	cmd = exec.Command("kubectl", "get", "pocketidinstances", "-n", ns,
		"-o", "jsonpath={.items[*].metadata.name}")
	if output, err := utils.Run(cmd); err == nil && output != "" {
		for _, name := range strings.Fields(output) {
			patchCmd := exec.Command("kubectl", "patch", "pocketidinstance", name,
				"-n", ns, "--type=merge", "-p", `{"metadata":{"finalizers":null}}`)
			_, _ = utils.Run(patchCmd)
		}
	}
}
