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
	"encoding/base64"
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
	instanceNS       = "pocket-id-e2e-test"
	userNS           = "pocket-id-e2e-users"
)

var _ = Describe("Pocket-ID Operator", Ordered, func() {
	BeforeAll(func() {
		By("creating instance namespace")
		kubectl("create", "ns", instanceNS, "--dry-run=client", "-o", "yaml").Apply()

		By("creating user namespace")
		kubectl("create", "ns", userNS, "--dry-run=client", "-o", "yaml").Apply()

		By("creating encryption key secret")
		kubectl("create", "secret", "generic", "pocket-id-encryption",
			"--from-literal=key=e2e-test-encryption-key-32chars!",
			"-n", instanceNS, "--dry-run=client", "-o", "yaml").Apply()
	})

	AfterAll(func() {
		By("cleaning up test namespace resources")
		removeFinalizers(userNS)
		removeFinalizers(instanceNS)

		By("deleting test namespaces")
		cmd := exec.Command("kubectl", "delete", "ns", userNS, "--ignore-not-found", "--timeout=5s")
		_, _ = utils.Run(cmd)
		cmd = exec.Command("kubectl", "delete", "ns", instanceNS, "--ignore-not-found", "--timeout=5s")
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
`, operatorUserName, userNS))

			By("creating a PocketIDInstance")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDInstance
metadata:
  name: %s
  namespace: %s
spec:
  image: ghcr.io/pocket-id/pocket-id:latest
  auth:
    userRef:
      name: %s
      namespace: %s
    apiKeyName: pocket-id-operator
  encryptionKey:
    valueFrom:
      secretKeyRef:
        name: pocket-id-encryption
        key: key
  appUrl: "http://%s.%s.svc.cluster.local:1411"
`, instanceName, instanceNS, operatorUserName, userNS, instanceName, instanceNS))
		})

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

		It("should become Available", func() {
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidinstance", instanceName, "-n", instanceNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Available')].status}")
				g.Expect(output).To(Equal("True"))
			}, 5*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should bootstrap and set status.bootstrapped=true", func() {
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidinstance", instanceName, "-n", instanceNS,
					"-o", "jsonpath={.status.bootstrapped}")
				g.Expect(output).To(Equal("true"))
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should create the operator API key secret", func() {
			// Secret name format: {userRef}-{apiKeyName}-key
			secretName := "pocket-id-operator-pocket-id-operator-key"
			Eventually(func(g Gomega) {
				output := kubectlGet("secret", secretName, "-n", userNS,
					"-o", "jsonpath={.data.token}")
				g.Expect(output).NotTo(BeEmpty(), "API key token should exist")
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
		})

		It("should set authUserRef and authAPIKeyName in instance status", func() {
			Eventually(func(g Gomega) {
				userRef := kubectlGet("pocketidinstance", instanceName, "-n", instanceNS,
					"-o", "jsonpath={.status.authUserRef}")
				userRefNS := kubectlGet("pocketidinstance", instanceName, "-n", instanceNS,
					"-o", "jsonpath={.status.authUserNamespace}")
				apiKeyName := kubectlGet("pocketidinstance", instanceName, "-n", instanceNS,
					"-o", "jsonpath={.status.authApiKeyName}")
				g.Expect(userRef).To(Equal(operatorUserName))
				g.Expect(userRefNS).To(Equal(userNS))
				g.Expect(apiKeyName).To(Equal("pocket-id-operator"))
			}).Should(Succeed())
		})

		It("should set userID in operator user status", func() {
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", operatorUserName, "-n", userNS,
					"-o", "jsonpath={.status.userID}")
				g.Expect(output).NotTo(BeEmpty(), "User should have userID from Pocket-ID")
			}).Should(Succeed())
		})

		It("should set one-time login details in operator user status", func() {
			Eventually(func(g Gomega) {
				token := kubectlGet("pocketiduser", operatorUserName, "-n", userNS,
					"-o", "jsonpath={.status.oneTimeLoginToken}")
				loginURL := kubectlGet("pocketiduser", operatorUserName, "-n", userNS,
					"-o", "jsonpath={.status.oneTimeLoginURL}")
				expiresAt := kubectlGet("pocketiduser", operatorUserName, "-n", userNS,
					"-o", "jsonpath={.status.oneTimeLoginExpiresAt}")
				g.Expect(token).NotTo(BeEmpty())
				g.Expect(loginURL).To(ContainSubstring("/lc/"))
				g.Expect(loginURL).To(ContainSubstring(token))
				g.Expect(expiresAt).NotTo(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should set operator user Ready condition to True", func() {
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", operatorUserName, "-n", userNS,
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
`, userName, userNS))

			By("verifying user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying userID is set")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.userID}")
				g.Expect(output).NotTo(BeEmpty())
			}).Should(Succeed())

			By("verifying user info secret is set")
			secretName := kubectlGet("pocketiduser", userName, "-n", userNS,
				"-o", "jsonpath={.status.userInfoSecretName}")
			Expect(secretName).To(Equal(userName + "-user-data"))

			By("verifying username defaults to CR name")
			output := kubectlGetSecretData(secretName, userNS, "username")
			Expect(output).To(Equal(userName))

			By("verifying email has placeholder default")
			output = kubectlGetSecretData(secretName, userNS, "email")
			Expect(output).To(Equal(userName + "@placeholder.local"))

			By("verifying one-time login status fields are set")
			Eventually(func(g Gomega) {
				token := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.oneTimeLoginToken}")
				loginURL := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.oneTimeLoginURL}")
				expiresAt := kubectlGet("pocketiduser", userName, "-n", userNS,
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
`, userName, userNS))

			By("verifying user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			var token string
			By("reading the one-time login token from status")
			Eventually(func(g Gomega) {
				token = kubectlGet("pocketiduser", userName, "-n", userNS,
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
`, userNS, token, instanceNS, instanceNS, userName))

			By("waiting for token exchange pod to succeed")
			Eventually(func(g Gomega) {
				output := kubectlGet("pod", "login-token-exchange-test", "-n", userNS,
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
`, userName, userNS))

			By("verifying user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying one-time login status fields are populated and future-dated")
			Eventually(func(g Gomega) {
				token := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.oneTimeLoginToken}")
				loginURL := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.oneTimeLoginURL}")
				expiresAt := kubectlGet("pocketiduser", userName, "-n", userNS,
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
`, userName, userNS))

			By("verifying user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying secret reflects provided values")
			secretName := kubectlGet("pocketiduser", userName, "-n", userNS,
				"-o", "jsonpath={.status.userInfoSecretName}")
			Expect(secretName).To(Equal(userName + "-user-data"))
			Expect(kubectlGetSecretData(secretName, userNS, "username")).To(Equal("explicit-username"))
			Expect(kubectlGetSecretData(secretName, userNS, "email")).To(Equal("john.doe@example.com"))
			Expect(kubectlGetSecretData(secretName, userNS, "displayName")).To(Equal("John Doe"))
			// isAdmin is omitempty, so false values are omitted from JSON
			Expect(kubectlGet("pocketiduser", userName, "-n", userNS,
				"-o", "jsonpath={.status.isAdmin}")).To(BeEmpty())
		})

		It("should merge userInfoSecretRef with explicit overrides", func() {
			const userName = "test-secret-override-user"
			const secretName = "user-info-source"

			By("creating a secret with user info")
			applyYAML(fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque
stringData:
  username: secret-username
  firstName: Secret
  lastName: User
  email: secret@example.com
  displayName: Secret User
`, secretName, userNS))

			By("creating a user referencing the secret with overrides")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
spec:
  userInfoSecretRef:
    name: %s
  username:
    value: override-username
  displayName:
    value: Override Name
`, userName, userNS, secretName))

			By("verifying user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying output secret reflects overrides and secret defaults")
			Eventually(func(g Gomega) {
				outSecret := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.userInfoSecretName}")
				g.Expect(outSecret).To(Equal(userName + "-user-data"))
				g.Expect(kubectlGetSecretData(outSecret, userNS, "username")).To(Equal("override-username"))
				g.Expect(kubectlGetSecretData(outSecret, userNS, "displayName")).To(Equal("Override Name"))
				g.Expect(kubectlGetSecretData(outSecret, userNS, "firstName")).To(Equal("Secret"))
				g.Expect(kubectlGetSecretData(outSecret, userNS, "lastName")).To(Equal("User"))
				g.Expect(kubectlGetSecretData(outSecret, userNS, "email")).To(Equal("secret@example.com"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
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
`, userName, userNS, apiKeyName))

			By("verifying user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying API key appears in status")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.apiKeys[0].name}")
				g.Expect(output).To(Equal(apiKeyName))
			}).Should(Succeed())

			By("verifying API key has ID from Pocket-ID")
			output := kubectlGet("pocketiduser", userName, "-n", userNS,
				"-o", "jsonpath={.status.apiKeys[0].id}")
			Expect(output).NotTo(BeEmpty(), "API key should have ID from Pocket-ID")

			By("verifying secret was created with token")
			secretName := fmt.Sprintf("%s-%s-key", userName, apiKeyName)
			Eventually(func(g Gomega) {
				output := kubectlGet("secret", secretName, "-n", userNS,
					"-o", "jsonpath={.data.token}")
				g.Expect(output).NotTo(BeEmpty(), "Secret should contain token")
			}).Should(Succeed())

			By("verifying secret reference in status")
			output = kubectlGet("pocketiduser", userName, "-n", userNS,
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
`, userName, userNS, apiKeyName))

			By("verifying user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			secretName := fmt.Sprintf("%s-%s-key", userName, apiKeyName)
			var tokenBase64 string
			By("reading the API key token from the secret")
			Eventually(func(g Gomega) {
				tokenBase64 = kubectlGet("secret", secretName, "-n", userNS,
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
`, podName, userNS, tokenBase64, instanceNS, userName))

			By("waiting for API key owner pod to succeed")
			Eventually(func(g Gomega) {
				output := kubectlGet("pod", podName, "-n", userNS,
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
`, userName, userNS))

			By("verifying user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying isAdmin is true in status")
			output := kubectlGet("pocketiduser", userName, "-n", userNS,
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
`, userName, userNS))

			By("waiting for user to be Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", userNS,
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
`, userName, userNS))

			By("verifying isAdmin becomes true")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.isAdmin}")
				g.Expect(output).To(Equal("true"))
			}, time.Minute, 2*time.Second).Should(Succeed())
		})
	})

	Context("User Groups and OIDC Clients", func() {
		const (
			groupUserName        = "test-group-user"
			groupName            = "test-user-group"
			oidcClientName       = "test-oidc-client"
			recoveryUserName     = "test-group-recovery-user"
			recoveryGroupName    = "test-user-group-recovery"
			recoveryOIDCName     = "test-oidc-client-recovery"
			recoveryOIDCGroup    = "test-oidc-group-recovery"
			recoveryOIDCGroupAlt = "test-oidc-group-recovery-alt"
		)

		BeforeAll(func() {
			By("creating a user to add to the group")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
spec:
  firstName:
    value: Group
  email:
    value: group-user@example.local
`, groupUserName, userNS))

			By("waiting for the group user to be Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", groupUserName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("creating a user group with custom claims and user refs")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUserGroup
metadata:
  name: %s
  namespace: %s
spec:
  name: e2e-group
  friendlyName: E2E Group
  customClaims:
  - key: department
    value: engineering
  userRefs:
  - name: %s
    namespace: %s
`, groupName, userNS, groupUserName, userNS))
		})

		It("should reconcile the user group and surface claims in status", func() {
			By("verifying the group ID is set")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.groupId}")
				g.Expect(output).NotTo(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying custom claims are reflected in status")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.customClaims[?(@.key=='department')].value}")
				g.Expect(output).To(Equal("engineering"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should create an OIDC client restricted to the user group", func() {
			By("creating an OIDC client that references the group")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: %s
  namespace: %s
spec:
  callbackUrls:
  - https://example.com/callback
  logoutCallbackUrls:
  - https://example.com/logout
  allowedUserGroups:
  - name: %s
`, oidcClientName, userNS, groupName))

			By("verifying the OIDC client ID is set")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidoidcclient", oidcClientName, "-n", userNS,
					"-o", "jsonpath={.status.clientId}")
				g.Expect(output).NotTo(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying the allowed group IDs include the group")
			groupID := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
				"-o", "jsonpath={.status.groupId}")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidoidcclient", oidcClientName, "-n", userNS,
					"-o", "jsonpath={.status.allowedUserGroupIds[*]}")
				g.Expect(output).To(ContainSubstring(groupID))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should recover a user group when the referenced user becomes ready", func() {
			By("creating a user group with a missing user ref")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUserGroup
metadata:
  name: %s
  namespace: %s
spec:
  name: recovery-group
  friendlyName: Recovery Group
  customClaims:
  - key: team
    value: alpha
  userRefs:
  - name: %s
    namespace: %s
`, recoveryGroupName, userNS, recoveryUserName, userNS))

			By("verifying the group reports a reconcile error")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidusergroup", recoveryGroupName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].reason}")
				g.Expect(output).To(Equal("ReconcileError"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("creating the missing user")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
spec:
  firstName:
    value: Recovery
  email:
    value: recovery-user@example.local
`, recoveryUserName, userNS))

			By("waiting for the user to be Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", recoveryUserName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying the group becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidusergroup", recoveryGroupName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("updating group custom claims")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUserGroup
metadata:
  name: %s
  namespace: %s
spec:
  name: recovery-group
  friendlyName: Recovery Group
  customClaims:
  - key: team
    value: beta
`, recoveryGroupName, userNS))

			By("verifying custom claims are updated in status")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidusergroup", recoveryGroupName, "-n", userNS,
					"-o", "jsonpath={.status.customClaims[?(@.key=='team')].value}")
				g.Expect(output).To(Equal("beta"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should recover an OIDC client when allowed groups become ready and update allowed groups", func() {
			By("creating an OIDC client that references a missing group")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: %s
  namespace: %s
spec:
  callbackUrls:
  - https://example.com/recovery/callback
  logoutCallbackUrls:
  - https://example.com/recovery/logout
  allowedUserGroups:
  - name: %s
`, recoveryOIDCName, userNS, recoveryOIDCGroup))

			By("verifying the OIDC client reports a reconcile error")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidoidcclient", recoveryOIDCName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].reason}")
				g.Expect(output).To(Equal("ReconcileError"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("creating the missing allowed group")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUserGroup
metadata:
  name: %s
  namespace: %s
spec:
  name: recovery-oidc-group
  friendlyName: Recovery OIDC Group
`, recoveryOIDCGroup, userNS))

			By("waiting for the allowed group to be Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidusergroup", recoveryOIDCGroup, "-n", userNS,
					"-o", "jsonpath={.status.groupId}")
				g.Expect(output).NotTo(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying the OIDC client becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidoidcclient", recoveryOIDCName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("creating an additional allowed group")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUserGroup
metadata:
  name: %s
  namespace: %s
spec:
  name: recovery-oidc-group-alt
  friendlyName: Recovery OIDC Group Alt
`, recoveryOIDCGroupAlt, userNS))

			By("waiting for the additional group to be Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidusergroup", recoveryOIDCGroupAlt, "-n", userNS,
					"-o", "jsonpath={.status.groupId}")
				g.Expect(output).NotTo(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("updating the OIDC client to include both groups")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: %s
  namespace: %s
spec:
  callbackUrls:
  - https://example.com/recovery/callback
  logoutCallbackUrls:
  - https://example.com/recovery/logout
  allowedUserGroups:
  - name: %s
  - name: %s
`, recoveryOIDCName, userNS, recoveryOIDCGroup, recoveryOIDCGroupAlt))

			groupID := kubectlGet("pocketidusergroup", recoveryOIDCGroup, "-n", userNS,
				"-o", "jsonpath={.status.groupId}")
			groupIDAlt := kubectlGet("pocketidusergroup", recoveryOIDCGroupAlt, "-n", userNS,
				"-o", "jsonpath={.status.groupId}")

			By("verifying allowed group IDs include both groups")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidoidcclient", recoveryOIDCName, "-n", userNS,
					"-o", "jsonpath={.status.allowedUserGroupIds[*]}")
				g.Expect(output).To(ContainSubstring(groupID))
				g.Expect(output).To(ContainSubstring(groupIDAlt))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})
	})

	Context("OIDC Client Secrets", func() {
		const (
			secretClientName       = "test-oidc-secret-client"
			customSecretClientName = "test-oidc-custom-secret"
			publicClientName       = "test-oidc-public-client"
			disabledSecretClient   = "test-oidc-disabled-secret"
			regenerateSecretClient = "test-oidc-regenerate-secret"
		)

		It("should create a secret with default name and keys", func() {
			By("creating an OIDC client with default secret config")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: %s
  namespace: %s
spec:
  callbackUrls:
  - https://example.com/callback
  logoutCallbackUrls:
  - https://example.com/logout
`, secretClientName, userNS))

			By("verifying the OIDC client becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidoidcclient", secretClientName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying the default secret is created")
			defaultSecretName := secretClientName + "-oidc-credentials"
			Eventually(func(g Gomega) {
				output := kubectlGet("secret", defaultSecretName, "-n", userNS, "-o", "name")
				g.Expect(output).To(Equal("secret/" + defaultSecretName))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("verifying the secret contains client_id")
			clientID := kubectlGet("pocketidoidcclient", secretClientName, "-n", userNS,
				"-o", "jsonpath={.status.clientId}")
			Eventually(func(g Gomega) {
				secretClientID := kubectlGetSecretData(defaultSecretName, userNS, "client_id")
				g.Expect(secretClientID).To(Equal(clientID))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("verifying the secret contains client_secret")
			Eventually(func(g Gomega) {
				clientSecret := kubectlGetSecretData(defaultSecretName, userNS, "client_secret")
				g.Expect(clientSecret).NotTo(BeEmpty())
				g.Expect(len(clientSecret)).To(BeNumerically(">", 20))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("verifying the secret contains issuer_url")
			Eventually(func(g Gomega) {
				issuerURL := kubectlGetSecretData(defaultSecretName, userNS, "issuer_url")
				g.Expect(issuerURL).To(ContainSubstring(instanceName))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("verifying the secret contains callback_urls as JSON")
			Eventually(func(g Gomega) {
				callbackURLs := kubectlGetSecretData(defaultSecretName, userNS, "callback_urls")
				g.Expect(callbackURLs).To(ContainSubstring("https://example.com/callback"))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("verifying the secret contains logout_callback_urls as JSON")
			Eventually(func(g Gomega) {
				logoutURLs := kubectlGetSecretData(defaultSecretName, userNS, "logout_callback_urls")
				g.Expect(logoutURLs).To(ContainSubstring("https://example.com/logout"))
			}, time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should create a secret with custom name and keys", func() {
			By("creating an OIDC client with custom secret configuration")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: %s
  namespace: %s
spec:
  callbackUrls:
  - https://custom.example.com/callback
  secret:
    name: my-custom-secret
    keys:
      clientId: OIDC_CLIENT_ID
      clientSecret: OIDC_CLIENT_SECRET
      issuerUrl: OIDC_ISSUER
      callbackUrls: OIDC_CALLBACKS
      logoutCallbackUrls: OIDC_LOGOUT_URLS
`, customSecretClientName, userNS))

			By("verifying the OIDC client becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidoidcclient", customSecretClientName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying the custom secret is created")
			Eventually(func(g Gomega) {
				output := kubectlGet("secret", "my-custom-secret", "-n", userNS, "-o", "name")
				g.Expect(output).To(Equal("secret/my-custom-secret"))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("verifying custom key names are used")
			Eventually(func(g Gomega) {
				clientID := kubectlGetSecretData("my-custom-secret", userNS, "OIDC_CLIENT_ID")
				g.Expect(clientID).NotTo(BeEmpty())

				clientSecret := kubectlGetSecretData("my-custom-secret", userNS, "OIDC_CLIENT_SECRET")
				g.Expect(clientSecret).NotTo(BeEmpty())

				issuer := kubectlGetSecretData("my-custom-secret", userNS, "OIDC_ISSUER")
				g.Expect(issuer).NotTo(BeEmpty())

				callbacks := kubectlGetSecretData("my-custom-secret", userNS, "OIDC_CALLBACKS")
				g.Expect(callbacks).NotTo(BeEmpty())
			}, time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should not include client_secret for public clients", func() {
			By("creating a public OIDC client")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: %s
  namespace: %s
spec:
  isPublic: true
  callbackUrls:
  - https://public.example.com/callback
`, publicClientName, userNS))

			By("verifying the OIDC client becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidoidcclient", publicClientName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			publicSecretName := publicClientName + "-oidc-credentials"
			By("verifying the secret exists")
			Eventually(func(g Gomega) {
				output := kubectlGet("secret", publicSecretName, "-n", userNS, "-o", "name")
				g.Expect(output).To(Equal("secret/" + publicSecretName))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("verifying client_secret is not present in the secret")
			cmd := exec.Command("kubectl", "get", "secret", publicSecretName, "-n", userNS,
				"-o", "jsonpath={.data.client_secret}")
			output, _ := utils.Run(cmd)
			Expect(strings.TrimSpace(output)).To(BeEmpty())

			By("verifying client_id is still present")
			Eventually(func(g Gomega) {
				clientID := kubectlGetSecretData(publicSecretName, userNS, "client_id")
				g.Expect(clientID).NotTo(BeEmpty())
			}, time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should not create a secret when disabled", func() {
			By("creating an OIDC client with secret creation disabled")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: %s
  namespace: %s
spec:
  callbackUrls:
  - https://disabled.example.com/callback
  secret:
    enabled: false
`, disabledSecretClient, userNS))

			By("verifying the OIDC client becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidoidcclient", disabledSecretClient, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			disabledSecretName := disabledSecretClient + "-oidc-credentials"
			By("verifying the secret does not exist")
			Consistently(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "secret", disabledSecretName, "-n", userNS)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred())
			}, 10*time.Second, 2*time.Second).Should(Succeed())
		})

		It("should preserve client_secret across reconciles", func() {
			By("creating an OIDC client")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: %s
  namespace: %s
spec:
  callbackUrls:
  - https://preserve.example.com/callback
`, regenerateSecretClient, userNS))

			By("verifying the OIDC client becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidoidcclient", regenerateSecretClient, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			preserveSecretName := regenerateSecretClient + "-oidc-credentials"
			var originalSecret string
			By("reading the original client_secret")
			Eventually(func(g Gomega) {
				originalSecret = kubectlGetSecretData(preserveSecretName, userNS, "client_secret")
				g.Expect(originalSecret).NotTo(BeEmpty())
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("triggering a reconcile by updating the spec")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: %s
  namespace: %s
spec:
  callbackUrls:
  - https://preserve.example.com/callback
  - https://preserve.example.com/callback2
`, regenerateSecretClient, userNS))

			By("waiting for reconcile to complete")
			time.Sleep(5 * time.Second)

			By("verifying the client_secret is unchanged")
			Consistently(func(g Gomega) {
				currentSecret := kubectlGetSecretData(preserveSecretName, userNS, "client_secret")
				g.Expect(currentSecret).To(Equal(originalSecret))
			}, 20*time.Second, 2*time.Second).Should(Succeed())
		})

		It("should regenerate client_secret when annotation is added", func() {
			preserveSecretName := regenerateSecretClient + "-oidc-credentials"
			var originalSecret string
			By("reading the current client_secret")
			Eventually(func(g Gomega) {
				originalSecret = kubectlGetSecretData(preserveSecretName, userNS, "client_secret")
				g.Expect(originalSecret).NotTo(BeEmpty())
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("adding the regenerate annotation")
			cmd := exec.Command("kubectl", "annotate", "pocketidoidcclient", regenerateSecretClient,
				"-n", userNS, "pocketid.internal/regenerate-secret=true", "--overwrite")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the client_secret is regenerated")
			Eventually(func(g Gomega) {
				currentSecret := kubectlGetSecretData(preserveSecretName, userNS, "client_secret")
				g.Expect(currentSecret).NotTo(BeEmpty())
				g.Expect(currentSecret).NotTo(Equal(originalSecret))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying the annotation is removed")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidoidcclient", regenerateSecretClient, "-n", userNS,
					"-o", "jsonpath={.metadata.annotations.pocketid\\.internal/regenerate-secret}")
				g.Expect(output).To(BeEmpty())
			}, time.Minute, 2*time.Second).Should(Succeed())
		})
	})

	Context("Reference Finalizers", func() {
		It("should block deletion of a user group while referenced by an OIDC client", func() {
			const finalizerGroupName = "finalizer-oidc-group"
			const finalizerOIDCName = "finalizer-oidc-client"

			By("creating a user group for OIDC finalizer testing")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUserGroup
metadata:
  name: %s
  namespace: %s
spec:
  name: finalizer-group
  friendlyName: Finalizer Group
`, finalizerGroupName, userNS))

			By("waiting for the user group to be Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidusergroup", finalizerGroupName, "-n", userNS,
					"-o", "jsonpath={.status.groupId}")
				g.Expect(output).NotTo(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("creating an OIDC client that references the group")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDOIDCClient
metadata:
  name: %s
  namespace: %s
spec:
  callbackUrls:
  - https://example.com/finalizer/callback
  logoutCallbackUrls:
  - https://example.com/finalizer/logout
  allowedUserGroups:
  - name: %s
`, finalizerOIDCName, userNS, finalizerGroupName))

			By("waiting for the OIDC client to be Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidoidcclient", finalizerOIDCName, "-n", userNS,
					"-o", "jsonpath={.status.clientId}")
				g.Expect(output).NotTo(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("requesting deletion of the user group")
			cmd := exec.Command("kubectl", "delete", "pocketidusergroup", finalizerGroupName, "-n", userNS, "--wait=false")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying deletion is blocked by the OIDC client finalizer")
			Eventually(func(g Gomega) {
				deletionTimestamp := kubectlGet("pocketidusergroup", finalizerGroupName, "-n", userNS,
					"-o", "jsonpath={.metadata.deletionTimestamp}")
				finalizers := kubectlGet("pocketidusergroup", finalizerGroupName, "-n", userNS,
					"-o", "jsonpath={.metadata.finalizers}")
				g.Expect(deletionTimestamp).NotTo(BeEmpty())
				g.Expect(finalizers).To(ContainSubstring("pocketid.internal/oidc-client-finalizer"))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("deleting the OIDC client")
			cmd = exec.Command("kubectl", "delete", "pocketidoidcclient", finalizerOIDCName, "-n", userNS)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the user group is deleted")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidusergroup", finalizerGroupName, "-n", userNS, "-o", "name")
				g.Expect(output).To(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should block deletion of a user while referenced by a user group", func() {
			const finalizerUserName = "finalizer-user"
			const finalizerUserGroupName = "finalizer-user-group"

			By("creating a user for user group finalizer testing")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
spec:
  firstName:
    value: Finalizer
  email:
    value: finalizer-user@example.local
`, finalizerUserName, userNS))

			By("waiting for the user to be Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", finalizerUserName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("creating a user group that references the user")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUserGroup
metadata:
  name: %s
  namespace: %s
spec:
  name: finalizer-user-group
  friendlyName: Finalizer User Group
  userRefs:
  - name: %s
    namespace: %s
`, finalizerUserGroupName, userNS, finalizerUserName, userNS))

			By("waiting for the user group to be Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidusergroup", finalizerUserGroupName, "-n", userNS,
					"-o", "jsonpath={.status.groupId}")
				g.Expect(output).NotTo(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("requesting deletion of the user")
			cmd := exec.Command("kubectl", "delete", "pocketiduser", finalizerUserName, "-n", userNS, "--wait=false")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying deletion is blocked by the user group finalizer")
			Eventually(func(g Gomega) {
				deletionTimestamp := kubectlGet("pocketiduser", finalizerUserName, "-n", userNS,
					"-o", "jsonpath={.metadata.deletionTimestamp}")
				finalizers := kubectlGet("pocketiduser", finalizerUserName, "-n", userNS,
					"-o", "jsonpath={.metadata.finalizers}")
				g.Expect(deletionTimestamp).NotTo(BeEmpty())
				g.Expect(finalizers).To(ContainSubstring("pocketid.internal/user-group-finalizer"))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("deleting the user group")
			cmd = exec.Command("kubectl", "delete", "pocketidusergroup", finalizerUserGroupName, "-n", userNS)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the user is deleted")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", finalizerUserName, "-n", userNS, "-o", "name")
				g.Expect(output).To(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
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
`, unreadyUserName, userNS, unreadySecretName, unreadyAPIKeyName))

			By("verifying the user is not Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", unreadyUserName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("False"))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("attempting to switch instance auth to the unready user")
			patch := fmt.Sprintf(`{"spec":{"auth":{"userRef":{"name":"%s","namespace":"%s"},"apiKeyName":"%s"}}}`, unreadyUserName, userNS, unreadyAPIKeyName)
			cmd := exec.Command("kubectl", "patch", "pocketidinstance", instanceName, "-n", instanceNS, "--type=merge", "-p", patch)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying auth switch is delayed")
			Consistently(func() string {
				return kubectlGet("pocketidinstance", instanceName, "-n", instanceNS,
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
`, unreadySecretName, userNS, "YXV0aC11bnJlYWR5LXVzZXI="))

			By("verifying the user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", unreadyUserName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying instance authUserRef switches to the ready user")
			Eventually(func(g Gomega) {
				userRef := kubectlGet("pocketidinstance", instanceName, "-n", instanceNS,
					"-o", "jsonpath={.status.authUserRef}")
				g.Expect(userRef).To(Equal(unreadyUserName))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("switching instance auth back to the operator user")
			patch = fmt.Sprintf(`{"spec":{"auth":{"userRef":{"name":"%s","namespace":"%s"},"apiKeyName":"%s"}}}`, operatorUserName, userNS, "pocket-id-operator")
			cmd = exec.Command("kubectl", "patch", "pocketidinstance", instanceName, "-n", instanceNS, "--type=merge", "-p", patch)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying instance authUserRef switches back to the operator user")
			Eventually(func(g Gomega) {
				userRef := kubectlGet("pocketidinstance", instanceName, "-n", instanceNS,
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
`, newUserName, userNS, newAPIKeyName))

			By("verifying new auth user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", newUserName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying new auth user API key secret exists")
			secretName := fmt.Sprintf("%s-%s-key", newUserName, newAPIKeyName)
			Eventually(func(g Gomega) {
				output := kubectlGet("secret", secretName, "-n", userNS,
					"-o", "jsonpath={.data.token}")
				g.Expect(output).NotTo(BeEmpty())
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("requesting deletion of the current auth user")
			cmd := exec.Command("kubectl", "delete", "pocketiduser", operatorUserName, "-n", userNS, "--wait=false")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying deletion is blocked by the auth finalizer")
			Eventually(func(g Gomega) {
				deletionTimestamp := kubectlGet("pocketiduser", operatorUserName, "-n", userNS,
					"-o", "jsonpath={.metadata.deletionTimestamp}")
				finalizers := kubectlGet("pocketiduser", operatorUserName, "-n", userNS,
					"-o", "jsonpath={.metadata.finalizers}")
				g.Expect(deletionTimestamp).NotTo(BeEmpty())
				g.Expect(finalizers).To(ContainSubstring("pocketid.internal/auth-user-finalizer"))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("switching instance auth to the new user")
			patch := fmt.Sprintf(`{"spec":{"auth":{"userRef":{"name":"%s","namespace":"%s"},"apiKeyName":"%s"}}}`, newUserName, userNS, newAPIKeyName)
			cmd = exec.Command("kubectl", "patch", "pocketidinstance", instanceName, "-n", instanceNS, "--type=merge", "-p", patch)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying instance authUserRef updates")
			Eventually(func(g Gomega) {
				userRef := kubectlGet("pocketidinstance", instanceName, "-n", instanceNS,
					"-o", "jsonpath={.status.authUserRef}")
				g.Expect(userRef).To(Equal(newUserName))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying the old auth user is deleted")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", operatorUserName, "-n", userNS, "-o", "name")
				g.Expect(output).To(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})
	})

	Context("Instance Selector", func() {
		It("should reconcile a labeled instance with a matching user selector", func() {
			const secondaryInstanceName = "e2e-instance-secondary"
			const secondaryUserName = "secondary-auth-user"
			const secondaryAPIKeyName = "secondary-api-key"

			By("creating the auth user with an instance selector")
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
  instanceSelector:
    matchLabels:
      instance-group: secondary
`, secondaryUserName, userNS, secondaryAPIKeyName))

			By("creating a labeled PocketIDInstance")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDInstance
metadata:
  name: %s
  namespace: %s
  labels:
    instance-group: secondary
spec:
  deploymentType: StatefulSet
  image: ghcr.io/pocket-id/pocket-id:latest
  auth:
    userRef:
      name: %s
      namespace: %s
    apiKeyName: %s
  encryptionKey:
    valueFrom:
      secretKeyRef:
        name: pocket-id-encryption
        key: key
  appUrl: "http://%s.%s.svc.cluster.local:1411"
`, secondaryInstanceName, instanceNS, secondaryUserName, userNS, secondaryAPIKeyName, secondaryInstanceName, instanceNS))

			By("verifying the secondary instance becomes Available")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidinstance", secondaryInstanceName, "-n", instanceNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Available')].status}")
				g.Expect(output).To(Equal("True"))
			}, 5*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the secondary instance bootstraps")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidinstance", secondaryInstanceName, "-n", instanceNS,
					"-o", "jsonpath={.status.bootstrapped}")
				g.Expect(output).To(Equal("true"))
			}, 3*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the auth user becomes Ready")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", secondaryUserName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(output).To(Equal("True"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying the auth user API key secret exists")
			secretName := fmt.Sprintf("%s-%s-key", secondaryUserName, secondaryAPIKeyName)
			Eventually(func(g Gomega) {
				output := kubectlGet("secret", secretName, "-n", userNS,
					"-o", "jsonpath={.data.token}")
				g.Expect(output).NotTo(BeEmpty())
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("verifying emptyDir is mounted for the main deployment")
			Eventually(func(g Gomega) {
				emptyDir := kubectlGet("deployment", instanceName, "-n", instanceNS,
					"-o", "jsonpath={.spec.template.spec.volumes[?(@.name=='data')].emptyDir}")
				mountPath := kubectlGet("deployment", instanceName, "-n", instanceNS,
					"-o", "jsonpath={.spec.template.spec.containers[0].volumeMounts[?(@.name=='data')].mountPath}")
				g.Expect(emptyDir).NotTo(BeEmpty())
				g.Expect(mountPath).To(Equal("/app/data"))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("verifying emptyDir is mounted for the secondary StatefulSet")
			Eventually(func(g Gomega) {
				emptyDir := kubectlGet("statefulset", secondaryInstanceName, "-n", instanceNS,
					"-o", "jsonpath={.spec.template.spec.volumes[?(@.name=='data')].emptyDir}")
				mountPath := kubectlGet("statefulset", secondaryInstanceName, "-n", instanceNS,
					"-o", "jsonpath={.spec.template.spec.containers[0].volumeMounts[?(@.name=='data')].mountPath}")
				g.Expect(emptyDir).NotTo(BeEmpty())
				g.Expect(mountPath).To(Equal("/app/data"))
			}, time.Minute, 2*time.Second).Should(Succeed())
		})
	})

	Context("Storage Persistence", func() {
		It("should provision storage when persistence is enabled", func() {
			const deployInstanceName = "persist-deploy-instance"
			const deployUserName = "persist-deploy-user"
			const deployAPIKeyName = "persist-deploy-key"
			const stsInstanceName = "persist-sts-instance"
			const stsUserName = "persist-sts-user"
			const stsAPIKeyName = "persist-sts-key"

			By("creating users with instance selectors")
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
  instanceSelector:
    matchLabels:
      instance-group: persist-deploy
---
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
spec:
  admin: true
  apiKeys:
  - name: %s
  instanceSelector:
    matchLabels:
      instance-group: persist-sts
`, deployUserName, userNS, deployAPIKeyName, stsUserName, userNS, stsAPIKeyName))

			By("creating deployment and statefulset instances with persistence enabled")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDInstance
metadata:
  name: %s
  namespace: %s
  labels:
    instance-group: persist-deploy
spec:
  image: ghcr.io/pocket-id/pocket-id:latest
  auth:
    userRef:
      name: %s
      namespace: %s
    apiKeyName: %s
  persistence:
    enabled: true
  encryptionKey:
    valueFrom:
      secretKeyRef:
        name: pocket-id-encryption
        key: key
  appUrl: "http://%s.%s.svc.cluster.local:1411"
---
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDInstance
metadata:
  name: %s
  namespace: %s
  labels:
    instance-group: persist-sts
spec:
  deploymentType: StatefulSet
  image: ghcr.io/pocket-id/pocket-id:latest
  auth:
    userRef:
      name: %s
      namespace: %s
    apiKeyName: %s
  persistence:
    enabled: true
  encryptionKey:
    valueFrom:
      secretKeyRef:
        name: pocket-id-encryption
        key: key
  appUrl: "http://%s.%s.svc.cluster.local:1411"
`, deployInstanceName, instanceNS, deployUserName, userNS, deployAPIKeyName, deployInstanceName, instanceNS,
				stsInstanceName, instanceNS, stsUserName, userNS, stsAPIKeyName, stsInstanceName, instanceNS))

			By("verifying deployment mounts a dynamically provisioned PVC")
			Eventually(func(g Gomega) {
				claimName := kubectlGet("deployment", deployInstanceName, "-n", instanceNS,
					"-o", "jsonpath={.spec.template.spec.volumes[?(@.name=='data')].persistentVolumeClaim.claimName}")
				mountPath := kubectlGet("deployment", deployInstanceName, "-n", instanceNS,
					"-o", "jsonpath={.spec.template.spec.containers[0].volumeMounts[?(@.name=='data')].mountPath}")
				g.Expect(claimName).To(Equal(deployInstanceName + "-data"))
				g.Expect(mountPath).To(Equal("/app/data"))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("verifying deployment PVC exists")
			Eventually(func(g Gomega) {
				output := kubectlGet("pvc", deployInstanceName+"-data", "-n", instanceNS, "-o", "name")
				g.Expect(output).NotTo(BeEmpty())
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("verifying StatefulSet uses a volumeClaimTemplate")
			Eventually(func(g Gomega) {
				claimTemplate := kubectlGet("statefulset", stsInstanceName, "-n", instanceNS,
					"-o", "jsonpath={.spec.volumeClaimTemplates[0].metadata.name}")
				mountPath := kubectlGet("statefulset", stsInstanceName, "-n", instanceNS,
					"-o", "jsonpath={.spec.template.spec.containers[0].volumeMounts[?(@.name=='data')].mountPath}")
				g.Expect(claimTemplate).To(Equal("data"))
				g.Expect(mountPath).To(Equal("/app/data"))
			}, time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should mount existing claims when configured", func() {
			const deployInstanceName = "existing-deploy-instance"
			const deployUserName = "existing-deploy-user"
			const deployAPIKeyName = "existing-deploy-key"
			const deployPVCName = "existing-deploy-claim"
			const stsInstanceName = "existing-sts-instance"
			const stsUserName = "existing-sts-user"
			const stsAPIKeyName = "existing-sts-key"
			const stsPVCName = "existing-sts-claim"

			By("creating existing PVCs")
			applyYAML(fmt.Sprintf(`
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: %s
  namespace: %s
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: %s
  namespace: %s
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
`, deployPVCName, instanceNS, stsPVCName, instanceNS))

			By("creating users with instance selectors")
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
  instanceSelector:
    matchLabels:
      instance-group: existing-deploy
---
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDUser
metadata:
  name: %s
  namespace: %s
spec:
  admin: true
  apiKeys:
  - name: %s
  instanceSelector:
    matchLabels:
      instance-group: existing-sts
`, deployUserName, userNS, deployAPIKeyName, stsUserName, userNS, stsAPIKeyName))

			By("creating instances that reference existing claims")
			applyYAML(fmt.Sprintf(`
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDInstance
metadata:
  name: %s
  namespace: %s
  labels:
    instance-group: existing-deploy
spec:
  image: ghcr.io/pocket-id/pocket-id:latest
  auth:
    userRef:
      name: %s
      namespace: %s
    apiKeyName: %s
  persistence:
    enabled: true
    existingClaim: %s
  encryptionKey:
    valueFrom:
      secretKeyRef:
        name: pocket-id-encryption
        key: key
  appUrl: "http://%s.%s.svc.cluster.local:1411"
---
apiVersion: pocketid.internal/v1alpha1
kind: PocketIDInstance
metadata:
  name: %s
  namespace: %s
  labels:
    instance-group: existing-sts
spec:
  deploymentType: StatefulSet
  image: ghcr.io/pocket-id/pocket-id:latest
  auth:
    userRef:
      name: %s
      namespace: %s
    apiKeyName: %s
  persistence:
    enabled: true
    existingClaim: %s
  encryptionKey:
    valueFrom:
      secretKeyRef:
        name: pocket-id-encryption
        key: key
  appUrl: "http://%s.%s.svc.cluster.local:1411"
`, deployInstanceName, instanceNS, deployUserName, userNS, deployAPIKeyName, deployPVCName, deployInstanceName, instanceNS,
				stsInstanceName, instanceNS, stsUserName, userNS, stsAPIKeyName, stsPVCName, stsInstanceName, instanceNS))

			By("verifying deployment mounts the existing claim")
			Eventually(func(g Gomega) {
				claimName := kubectlGet("deployment", deployInstanceName, "-n", instanceNS,
					"-o", "jsonpath={.spec.template.spec.volumes[?(@.name=='data')].persistentVolumeClaim.claimName}")
				g.Expect(claimName).To(Equal(deployPVCName))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("verifying StatefulSet mounts the existing claim")
			Eventually(func(g Gomega) {
				claimName := kubectlGet("statefulset", stsInstanceName, "-n", instanceNS,
					"-o", "jsonpath={.spec.template.spec.volumes[?(@.name=='data')].persistentVolumeClaim.claimName}")
				claimTemplate := kubectlGet("statefulset", stsInstanceName, "-n", instanceNS,
					"-o", "jsonpath={.spec.volumeClaimTemplates[0].metadata.name}")
				g.Expect(claimName).To(Equal(stsPVCName))
				g.Expect(claimTemplate).To(BeEmpty())
			}, time.Minute, 2*time.Second).Should(Succeed())
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

func kubectlGetSecretData(secretName, namespace, key string) string {
	encoded := kubectlGet("secret", secretName, "-n", namespace,
		"-o", fmt.Sprintf("jsonpath={.data.%s}", key))
	if encoded == "" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	Expect(err).NotTo(HaveOccurred())
	return string(decoded)
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

	// Remove finalizers from PocketIDUserGroups
	cmd = exec.Command("kubectl", "get", "pocketidusergroups", "-n", ns,
		"-o", "jsonpath={.items[*].metadata.name}")
	if output, err := utils.Run(cmd); err == nil && output != "" {
		for _, name := range strings.Fields(output) {
			patchCmd := exec.Command("kubectl", "patch", "pocketidusergroup", name,
				"-n", ns, "--type=merge", "-p", `{"metadata":{"finalizers":null}}`)
			_, _ = utils.Run(patchCmd)
		}
	}

	// Remove finalizers from PocketIDOIDCClients
	cmd = exec.Command("kubectl", "get", "pocketidoidcclients", "-n", ns,
		"-o", "jsonpath={.items[*].metadata.name}")
	if output, err := utils.Run(cmd); err == nil && output != "" {
		for _, name := range strings.Fields(output) {
			patchCmd := exec.Command("kubectl", "patch", "pocketidoidcclient", name,
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
