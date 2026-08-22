//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"net/http"
	"time"

	"github.com/aclerici38/pocket-id-operator/internal/controller/user"
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

			token := kubectlGetSecretData(secretName, userNS, "token")
			Expect(token).NotTo(BeEmpty())

			By("verifying the token authenticates as that user")
			Expect(pocketIDUsernameForAPIKey(token)).To(Equal(userName))
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

		// Pocket-ID derives the login code's length from the TTL requested when minting
		// it: a TTL of 15m or less yields the short 6-character code built for the email
		// login flow, anything longer yields the long link code. The page behind
		// status.oneTimeLoginURL only submits a 6-character code when
		// emailOneTimeAccessAsUnauthenticatedEnabled is on, so a short code leaves the
		// link unusable in a browser even though the exchange endpoint still accepts it.
		// That is why the session-exchange test below cannot catch this on its own.
		It("should issue the long link login code", func() {
			const userName = "test-login-code-length"
			const podName = "login-code-config-check"
			// Pocket-ID's shortTokenLength, the code the browser login page cannot submit.
			const shortLoginCodeLength = 6

			createUserAndWaitReady(UserOptions{Name: userName})

			token := waitForStatusFieldNotEmpty("pocketiduser", userName, userNS,
				".status.oneTimeLoginToken")

			By("confirming email one-time access is off, so the page requires the long code")
			Expect(getAppConfigFieldFromPocketID("emailOneTimeAccessAsUnauthenticatedEnabled")).To(Equal("false"))

			Expect(len(token)).To(BeNumerically(">", shortLoginCodeLength),
				"expected the long link code; a %d-character code means either "+
					"DefaultLoginTokenExpiryMin dropped to Pocket-ID's short-code threshold "+
					"or Pocket-ID raised that threshold past the TTL we request",
				shortLoginCodeLength)
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

			By("redeeming the token and verifying the session belongs to that user")
			Expect(pocketIDUsernameForOneTimeToken(token)).To(Equal(userName))
		})
	})

	Context("User Deletion Behavior", func() {
		It("should NOT delete user from Pocket-ID when annotation is missing", func() {
			const userName = "test-delete-no-annotation"
			const podName = "check-user-exists-no-annotation"

			By("creating a user without the delete annotation")
			createUserAndWaitReady(UserOptions{Name: userName})

			By("getting the userID from status")
			userID := waitForStatusFieldNotEmpty("pocketiduser", userName, userNS, ".status.userID")

			By("deleting the PocketIDUser resource")
			kubectlDelete("pocketiduser", userName, userNS)
			waitForResourceDeleted("pocketiduser", userName, userNS)

			By("verifying user still exists in Pocket-ID")
			Expect(getFromPocketID("/api/users/" + userID)).To(ContainSubstring(userID))
		})

		It("should NOT delete user from Pocket-ID when annotation is set to false", func() {
			const userName = "test-delete-annotation-false"
			const podName = "check-user-exists-annotation-false"

			By("creating a user with annotation set to false")
			createUserAndWaitReady(UserOptions{
				Name: userName,
				Annotations: map[string]string{
					user.DeleteFromPocketIDAnnotation: "false",
				},
			})

			By("getting the userID from status")
			userID := waitForStatusFieldNotEmpty("pocketiduser", userName, userNS, ".status.userID")

			By("deleting the PocketIDUser resource")
			kubectlDelete("pocketiduser", userName, userNS)
			waitForResourceDeleted("pocketiduser", userName, userNS)

			By("verifying user still exists in Pocket-ID")
			Expect(getFromPocketID("/api/users/" + userID)).To(ContainSubstring(userID))
		})

		It("should delete user from Pocket-ID when annotation is set to true", func() {
			const userName = "test-delete-annotation-true"
			const podName = "check-user-deleted-annotation-true"

			By("creating a user with annotation set to true")
			createUserAndWaitReady(UserOptions{
				Name: userName,
				Annotations: map[string]string{
					user.DeleteFromPocketIDAnnotation: "true",
				},
			})

			By("getting the userID from status")
			userID := waitForStatusFieldNotEmpty("pocketiduser", userName, userNS, ".status.userID")

			By("deleting the PocketIDUser resource")
			kubectlDelete("pocketiduser", userName, userNS)
			waitForResourceDeleted("pocketiduser", userName, userNS)

			By("verifying user no longer exists in Pocket-ID (expect 404)")
			Expect(getStatusFromPocketID("/api/users/"+userID)).To(Equal(http.StatusNotFound),
				"the user should have been deleted from Pocket-ID")
		})

		It("should delete user from Pocket-ID when annotation is added before deletion", func() {
			const userName = "test-delete-add-annotation"
			const podName = "check-user-deleted-add-annotation"

			By("creating a user without annotation")
			createUserAndWaitReady(UserOptions{Name: userName})

			By("getting the userID from status")
			userID := waitForStatusFieldNotEmpty("pocketiduser", userName, userNS, ".status.userID")

			By("adding the delete annotation")
			Expect(kubectlAnnotate("pocketiduser", userName, userNS,
				user.DeleteFromPocketIDAnnotation+"=true")).To(Succeed())

			By("deleting the PocketIDUser resource")
			kubectlDelete("pocketiduser", userName, userNS)
			waitForResourceDeleted("pocketiduser", userName, userNS)

			By("verifying user no longer exists in Pocket-ID (expect 404)")
			Expect(getStatusFromPocketID("/api/users/"+userID)).To(Equal(http.StatusNotFound),
				"the user should have been deleted from Pocket-ID")
		})
	})
})
