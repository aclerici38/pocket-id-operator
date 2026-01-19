//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("PocketIDUser", Ordered, func() {
	Context("Minimal User", func() {
		const userName = "test-minimal-user"

		BeforeAll(func() {
			createUser(UserOptions{Name: userName})
		})

		It("should become Ready", func() {
			waitForReady("pocketiduser", userName, userNS)
		})

		It("should set userID in status", func() {
			waitForStatusFieldNotEmpty("pocketiduser", userName, userNS, ".status.userID")
		})

		It("should set userInfoSecretName in status", func() {
			waitForStatusField("pocketiduser", userName, userNS,
				".status.userInfoSecretName", userName+"-user-data")
		})

		It("should default username to CR name", func() {
			secretName := userName + "-user-data"
			Expect(kubectlGetSecretData(secretName, userNS, "username")).To(Equal(userName))
		})

		It("should set placeholder email default", func() {
			secretName := userName + "-user-data"
			Expect(kubectlGetSecretData(secretName, userNS, "email")).To(Equal(userName + "@placeholder.local"))
		})

		It("should set one-time login status fields", func() {
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
	})

	Context("Explicit Values", func() {
		const userName = "test-explicit-user"

		BeforeAll(func() {
			createUserAndWaitReady(UserOptions{
				Name:        userName,
				Username:    "explicit-username",
				FirstName:   "John",
				LastName:    "Doe",
				Email:       "john.doe@example.com",
				DisplayName: "John Doe",
				Admin:       boolPtr(false),
			})
		})

		It("should reflect provided values in secret", func() {
			secretName := userName + "-user-data"
			Expect(kubectlGetSecretData(secretName, userNS, "username")).To(Equal("explicit-username"))
			Expect(kubectlGetSecretData(secretName, userNS, "email")).To(Equal("john.doe@example.com"))
			Expect(kubectlGetSecretData(secretName, userNS, "displayName")).To(Equal("John Doe"))
		})

		It("should not show isAdmin when false", func() {
			output := kubectlGet("pocketiduser", userName, "-n", userNS,
				"-o", "jsonpath={.status.isAdmin}")
			Expect(output).To(BeEmpty())
		})
	})

	Context("Admin User", func() {
		const userName = "test-admin-user"

		BeforeAll(func() {
			createUserAndWaitReady(UserOptions{
				Name:  userName,
				Admin: boolPtr(true),
			})
		})

		It("should set isAdmin true in status", func() {
			output := kubectlGet("pocketiduser", userName, "-n", userNS,
				"-o", "jsonpath={.status.isAdmin}")
			Expect(output).To(Equal("true"))
		})
	})

	Context("User Updates", func() {
		const userName = "test-update-user"

		BeforeAll(func() {
			createUserAndWaitReady(UserOptions{
				Name:      userName,
				FirstName: "Original",
				Admin:     boolPtr(false),
			})
		})

		It("should update when spec changes", func() {
			By("updating user to admin")
			createUser(UserOptions{
				Name:      userName,
				FirstName: "Updated",
				Admin:     boolPtr(true),
			})

			By("verifying isAdmin becomes true")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.isAdmin}")
				g.Expect(output).To(Equal("true"))
			}, time.Minute, 2*time.Second).Should(Succeed())
		})
	})

	Context("UserInfoSecretRef", func() {
		It("should merge secret values with explicit overrides", func() {
			const userName = "test-secret-override-user"
			const secretName = "user-info-source"

			By("creating a secret with user info")
			applyYAML(createSecretYAML(secretName, userNS, map[string]string{
				"username":    "secret-username",
				"firstName":   "Secret",
				"lastName":    "User",
				"email":       "secret@example.com",
				"displayName": "Secret User",
			}))

			By("creating a user referencing the secret with overrides")
			createUserAndWaitReady(UserOptions{
				Name:           userName,
				UserInfoSecret: secretName,
				Username:       "override-username",
				DisplayName:    "Override Name",
			})

			By("verifying overrides take precedence")
			outSecret := userName + "-user-data"
			Expect(kubectlGetSecretData(outSecret, userNS, "username")).To(Equal("override-username"))
			Expect(kubectlGetSecretData(outSecret, userNS, "displayName")).To(Equal("Override Name"))

			By("verifying secret defaults are used for non-overridden values")
			Expect(kubectlGetSecretData(outSecret, userNS, "firstName")).To(Equal("Secret"))
			Expect(kubectlGetSecretData(outSecret, userNS, "lastName")).To(Equal("User"))
			Expect(kubectlGetSecretData(outSecret, userNS, "email")).To(Equal("secret@example.com"))
		})

		It("should apply defaults for missing keys in partial secret", func() {
			const userName = "test-partial-secret-user"
			const secretName = "partial-user-info"

			By("creating a secret with only some fields")
			applyYAML(createSecretYAML(secretName, userNS, map[string]string{
				"firstName": "Partial",
				"lastName":  "User",
				"email":     "partial@example.com",
			}))

			By("creating a user referencing the partial secret")
			createUserAndWaitReady(UserOptions{
				Name:           userName,
				UserInfoSecret: secretName,
			})

			By("verifying defaults are applied for missing keys")
			outSecret := userName + "-user-data"
			Expect(kubectlGetSecretData(outSecret, userNS, "firstName")).To(Equal("Partial"))
			Expect(kubectlGetSecretData(outSecret, userNS, "lastName")).To(Equal("User"))
			Expect(kubectlGetSecretData(outSecret, userNS, "email")).To(Equal("partial@example.com"))
			Expect(kubectlGetSecretData(outSecret, userNS, "username")).To(Equal(userName))
			Expect(kubectlGetSecretData(outSecret, userNS, "displayName")).To(Equal("Partial User"))
		})

		It("should apply defaults for empty string values", func() {
			const userName = "test-empty-secret-user"
			const secretName = "empty-user-info"

			By("creating a secret with empty values")
			applyYAML(createSecretYAML(secretName, userNS, map[string]string{
				"username":    "",
				"firstName":   "",
				"lastName":    "",
				"email":       "",
				"displayName": "",
			}))

			By("creating a user referencing the empty secret")
			createUserAndWaitReady(UserOptions{
				Name:           userName,
				UserInfoSecret: secretName,
			})

			By("verifying defaults are applied")
			outSecret := userName + "-user-data"
			Expect(kubectlGetSecretData(outSecret, userNS, "username")).To(Equal(userName))
			Expect(kubectlGetSecretData(outSecret, userNS, "firstName")).To(Equal(userName))
			Expect(kubectlGetSecretData(outSecret, userNS, "email")).To(Equal(userName + "@placeholder.local"))
		})
	})

	Context("API Keys", func() {
		It("should create API key and store token in secret", func() {
			const userName = "test-apikey-user"
			const apiKeyName = "my-api-key"

			createUserAndWaitReady(UserOptions{
				Name:  userName,
				Admin: boolPtr(false),
				APIKeys: []APIKeySpec{
					{Name: apiKeyName, Description: "Test API key"},
				},
			})

			By("verifying API key appears in status")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.apiKeys[0].name}")
				g.Expect(output).To(Equal(apiKeyName))
			}).Should(Succeed())

			By("verifying API key has ID from Pocket-ID")
			output := kubectlGet("pocketiduser", userName, "-n", userNS,
				"-o", "jsonpath={.status.apiKeys[0].id}")
			Expect(output).NotTo(BeEmpty())

			By("verifying secret was created with token")
			secretName := kubectlGet("pocketiduser", userName, "-n", userNS,
				"-o", "jsonpath={.status.apiKeys[0].secretName}")
			Expect(secretName).NotTo(BeEmpty())
			waitForSecretKey(secretName, userNS, "token")
		})

		It("should create API key owned by the target user", func() {
			const userName = "test-apikey-owner-user"
			const apiKeyName = "owner-key"
			const podName = "api-key-owner-test"

			createUserAndWaitReady(UserOptions{
				Name:  userName,
				Admin: boolPtr(false),
				APIKeys: []APIKeySpec{
					{Name: apiKeyName, Description: "Owner API key"},
				},
			})

			By("getting secret name and token")
			secretName := kubectlGet("pocketiduser", userName, "-n", userNS,
				"-o", fmt.Sprintf("jsonpath={.status.apiKeys[?(@.name=='%s')].secretName}", apiKeyName))
			Expect(secretName).NotTo(BeEmpty())

			tokenBase64 := kubectlGet("secret", secretName, "-n", userNS,
				"-o", "jsonpath={.data.token}")
			Expect(tokenBase64).NotTo(BeEmpty())

			By("creating a curl pod to verify the token belongs to the user")
			script := fmt.Sprintf(`TOKEN=$(echo '%s' | base64 -d)
curl -sf -H "X-API-KEY: $TOKEN" %s/api/users/me | grep -q '"username":"%s"'`,
				tokenBase64, formatInstanceURL(), userName)
			applyYAML(createCurlPodYAML(podName, userNS, script))

			waitForPodSucceeded(podName, userNS)
		})
	})

	Context("One-Time Login Token", func() {
		It("should store login details in status with future expiry", func() {
			const userName = "test-login-token-user"

			createUserAndWaitReady(UserOptions{Name: userName})

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

		It("should exchange the one-time access token for a session", func() {
			const userName = "test-login-token-exchange"
			const podName = "login-token-exchange-test"

			createUserAndWaitReady(UserOptions{Name: userName})

			var token string
			Eventually(func(g Gomega) {
				token = kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.oneTimeLoginToken}")
				g.Expect(token).NotTo(BeEmpty())
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("creating a curl pod to exchange the token")
			script := fmt.Sprintf(`TOKEN='%s'
curl -sf -D /tmp/headers -o /tmp/user.json -X POST %s/api/one-time-access-token/$TOKEN
COOKIE=$(awk -F': ' 'tolower($1)=="set-cookie" && $2 ~ /access_token=/ {print $2; exit}' /tmp/headers)
if [ -z "$COOKIE" ]; then
  echo "missing access token cookie" >&2
  exit 1
fi
COOKIE_PAIR=$(echo "$COOKIE" | cut -d';' -f1)
curl -sf -H "Cookie: $COOKIE_PAIR" %s/api/users/me | grep -q '"username":"%s"'`,
				token, formatInstanceURL(), formatInstanceURL(), userName)

			applyYAML(createCurlPodYAML(podName, userNS, script))
			waitForPodSucceeded(podName, userNS)
		})
	})
})
