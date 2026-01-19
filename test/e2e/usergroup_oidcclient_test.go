//go:build e2e
// +build e2e

package e2e

import (
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aclerici38/pocket-id-operator/test/utils"
)

var _ = Describe("PocketIDUserGroup and PocketIDOIDCClient", Ordered, func() {
	const (
		groupUserName  = "test-group-user"
		groupName      = "test-user-group"
		oidcClientName = "test-oidc-client"
	)

	BeforeAll(func() {
		By("creating a user to add to the group")
		createUserAndWaitReady(UserOptions{
			Name:      groupUserName,
			FirstName: "Group",
			Email:     "group-user@example.local",
		})

		By("creating a user group with custom claims and user refs")
		createUserGroup(UserGroupOptions{
			Name:         groupName,
			GroupName:    "e2e-group",
			FriendlyName: "E2E Group",
			CustomClaims: []CustomClaim{{Key: "department", Value: "engineering"}},
			UserRefs:     []ResourceRef{{Name: groupUserName, Namespace: userNS}},
		})
	})

	Context("User Group Reconciliation", func() {
		It("should set groupId in status", func() {
			waitForStatusFieldNotEmpty("pocketidusergroup", groupName, userNS, ".status.groupId")
		})

		It("should reflect custom claims in status", func() {
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.customClaims[?(@.key=='department')].value}")
				g.Expect(output).To(Equal("engineering"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})
	})

	Context("OIDC Client with Group Restriction", func() {
		BeforeAll(func() {
			By("creating an OIDC client that references the group")
			createOIDCClient(OIDCClientOptions{
				Name:               oidcClientName,
				CallbackURLs:       []string{"https://example.com/callback"},
				LogoutCallbackURLs: []string{"https://example.com/logout"},
				AllowedUserGroups:  []string{groupName},
			})
		})

		It("should set clientId in status", func() {
			waitForStatusFieldNotEmpty("pocketidoidcclient", oidcClientName, userNS, ".status.clientId")
		})

		It("should include the group in allowedUserGroupIds", func() {
			groupID := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
				"-o", "jsonpath={.status.groupId}")

			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidoidcclient", oidcClientName, "-n", userNS,
					"-o", "jsonpath={.status.allowedUserGroupIds[*]}")
				g.Expect(output).To(ContainSubstring(groupID))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})
	})

	Context("Recovery from Missing References", func() {
		const (
			recoveryUserName  = "test-group-recovery-user"
			recoveryGroupName = "test-user-group-recovery"
		)

		It("should recover user group when referenced user becomes ready", func() {
			By("creating a user group with a missing user ref")
			createUserGroup(UserGroupOptions{
				Name:         recoveryGroupName,
				GroupName:    "recovery-group",
				FriendlyName: "Recovery Group",
				CustomClaims: []CustomClaim{{Key: "team", Value: "alpha"}},
				UserRefs:     []ResourceRef{{Name: recoveryUserName, Namespace: userNS}},
			})

			By("verifying the group reports a reconcile error")
			waitForConditionReason("pocketidusergroup", recoveryGroupName, userNS, "Ready", "ReconcileError")

			By("creating the missing user")
			createUserAndWaitReady(UserOptions{
				Name:      recoveryUserName,
				FirstName: "Recovery",
				Email:     "recovery-user@example.local",
			})

			By("verifying the group becomes Ready")
			waitForReady("pocketidusergroup", recoveryGroupName, userNS)
		})

		It("should update custom claims when spec changes", func() {
			By("updating group custom claims")
			createUserGroup(UserGroupOptions{
				Name:         recoveryGroupName,
				GroupName:    "recovery-group",
				FriendlyName: "Recovery Group",
				CustomClaims: []CustomClaim{{Key: "team", Value: "beta"}},
			})

			By("verifying custom claims are updated")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidusergroup", recoveryGroupName, "-n", userNS,
					"-o", "jsonpath={.status.customClaims[?(@.key=='team')].value}")
				g.Expect(output).To(Equal("beta"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})
	})

	Context("OIDC Client Recovery and Updates", func() {
		const (
			recoveryOIDCName     = "test-oidc-client-recovery"
			recoveryOIDCGroup    = "test-oidc-group-recovery"
			recoveryOIDCGroupAlt = "test-oidc-group-recovery-alt"
		)

		It("should recover when allowed groups become ready", func() {
			By("creating an OIDC client that references a missing group")
			createOIDCClient(OIDCClientOptions{
				Name:               recoveryOIDCName,
				CallbackURLs:       []string{"https://example.com/recovery/callback"},
				LogoutCallbackURLs: []string{"https://example.com/recovery/logout"},
				AllowedUserGroups:  []string{recoveryOIDCGroup},
			})

			By("verifying the OIDC client reports a reconcile error")
			waitForConditionReason("pocketidoidcclient", recoveryOIDCName, userNS, "Ready", "ReconcileError")

			By("creating the missing allowed group")
			createUserGroupAndWaitReady(UserGroupOptions{
				Name:         recoveryOIDCGroup,
				GroupName:    "recovery-oidc-group",
				FriendlyName: "Recovery OIDC Group",
			})

			By("verifying the OIDC client becomes Ready")
			waitForReady("pocketidoidcclient", recoveryOIDCName, userNS)
		})

		It("should update allowed groups when spec changes", func() {
			By("creating an additional allowed group")
			createUserGroupAndWaitReady(UserGroupOptions{
				Name:         recoveryOIDCGroupAlt,
				GroupName:    "recovery-oidc-group-alt",
				FriendlyName: "Recovery OIDC Group Alt",
			})

			By("updating the OIDC client to include both groups")
			createOIDCClient(OIDCClientOptions{
				Name:               recoveryOIDCName,
				CallbackURLs:       []string{"https://example.com/recovery/callback"},
				LogoutCallbackURLs: []string{"https://example.com/recovery/logout"},
				AllowedUserGroups:  []string{recoveryOIDCGroup, recoveryOIDCGroupAlt},
			})

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
})

var _ = Describe("OIDC Client Secrets", Ordered, func() {
	Context("Default Secret Configuration", func() {
		const secretClientName = "test-oidc-secret-client"

		BeforeAll(func() {
			createOIDCClientAndWaitReady(OIDCClientOptions{
				Name:               secretClientName,
				CallbackURLs:       []string{"https://example.com/callback"},
				LogoutCallbackURLs: []string{"https://example.com/logout"},
			})
		})

		It("should create secret with default name", func() {
			defaultSecretName := secretClientName + "-oidc-credentials"
			waitForSecretExists(defaultSecretName, userNS)
		})

		It("should include client_id in secret", func() {
			defaultSecretName := secretClientName + "-oidc-credentials"
			clientID := waitForStatusFieldNotEmpty("pocketidoidcclient", secretClientName, userNS, ".status.clientId")

			secretClientID := waitForSecretKey(defaultSecretName, userNS, "client_id")
			Expect(secretClientID).To(Equal(clientID))
		})

		It("should include client_secret in secret", func() {
			defaultSecretName := secretClientName + "-oidc-credentials"
			clientSecret := waitForSecretKey(defaultSecretName, userNS, "client_secret")
			Expect(len(clientSecret)).To(BeNumerically(">", 20))
		})

		It("should include issuer_url in secret", func() {
			defaultSecretName := secretClientName + "-oidc-credentials"
			issuerURL := waitForSecretKey(defaultSecretName, userNS, "issuer_url")
			Expect(issuerURL).To(ContainSubstring(instanceName))
		})

		It("should include callback_urls as JSON in secret", func() {
			defaultSecretName := secretClientName + "-oidc-credentials"
			callbackURLs := waitForSecretKey(defaultSecretName, userNS, "callback_urls")
			Expect(callbackURLs).To(ContainSubstring("https://example.com/callback"))
		})

		It("should include logout_callback_urls as JSON in secret", func() {
			defaultSecretName := secretClientName + "-oidc-credentials"
			logoutURLs := waitForSecretKey(defaultSecretName, userNS, "logout_callback_urls")
			Expect(logoutURLs).To(ContainSubstring("https://example.com/logout"))
		})
	})

	Context("Custom Secret Configuration", func() {
		const customSecretClientName = "test-oidc-custom-secret"
		const customSecretName = "my-custom-secret"

		BeforeAll(func() {
			createOIDCClientAndWaitReady(OIDCClientOptions{
				Name:         customSecretClientName,
				CallbackURLs: []string{"https://custom.example.com/callback"},
				Secret: &OIDCSecretConfig{
					Name: customSecretName,
					Keys: &OIDCSecretKeys{
						ClientID:           "OIDC_CLIENT_ID",
						ClientSecret:       "OIDC_CLIENT_SECRET",
						IssuerURL:          "OIDC_ISSUER",
						CallbackURLs:       "OIDC_CALLBACKS",
						LogoutCallbackURLs: "OIDC_LOGOUT_URLS",
					},
				},
			})
		})

		It("should create secret with custom name", func() {
			waitForSecretExists(customSecretName, userNS)
		})

		It("should use custom key names", func() {
			Expect(waitForSecretKey(customSecretName, userNS, "OIDC_CLIENT_ID")).NotTo(BeEmpty())
			Expect(waitForSecretKey(customSecretName, userNS, "OIDC_CLIENT_SECRET")).NotTo(BeEmpty())
			Expect(waitForSecretKey(customSecretName, userNS, "OIDC_ISSUER")).NotTo(BeEmpty())
			Expect(waitForSecretKey(customSecretName, userNS, "OIDC_CALLBACKS")).NotTo(BeEmpty())
		})
	})

	Context("Public Client", func() {
		const publicClientName = "test-oidc-public-client"

		BeforeAll(func() {
			createOIDCClientAndWaitReady(OIDCClientOptions{
				Name:         publicClientName,
				IsPublic:     true,
				CallbackURLs: []string{"https://public.example.com/callback"},
			})
		})

		It("should not include client_secret for public clients", func() {
			publicSecretName := publicClientName + "-oidc-credentials"
			waitForSecretExists(publicSecretName, userNS)

			cmd := exec.Command("kubectl", "get", "secret", publicSecretName, "-n", userNS,
				"-o", "jsonpath={.data.client_secret}")
			output, _ := utils.Run(cmd)
			Expect(strings.TrimSpace(output)).To(BeEmpty())
		})

		It("should still include client_id", func() {
			publicSecretName := publicClientName + "-oidc-credentials"
			Expect(waitForSecretKey(publicSecretName, userNS, "client_id")).NotTo(BeEmpty())
		})
	})

	Context("Disabled Secret", func() {
		const disabledSecretClient = "test-oidc-disabled-secret"

		BeforeAll(func() {
			createOIDCClientAndWaitReady(OIDCClientOptions{
				Name:         disabledSecretClient,
				CallbackURLs: []string{"https://disabled.example.com/callback"},
				Secret: &OIDCSecretConfig{
					Enabled: boolPtr(false),
				},
			})
		})

		It("should not create secret when disabled", func() {
			disabledSecretName := disabledSecretClient + "-oidc-credentials"
			Consistently(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "secret", disabledSecretName, "-n", userNS)
				_, err := utils.Run(cmd)
				g.Expect(err).To(HaveOccurred())
			}, 10*time.Second, 2*time.Second).Should(Succeed())
		})
	})

	Context("Secret Regeneration", func() {
		const regenerateSecretClient = "test-oidc-regenerate-client-secret"

		BeforeAll(func() {
			createOIDCClientAndWaitReady(OIDCClientOptions{
				Name:         regenerateSecretClient,
				CallbackURLs: []string{"https://preserve.example.com/callback"},
			})
		})

		It("should preserve client_secret across reconciles", func() {
			preserveSecretName := regenerateSecretClient + "-oidc-credentials"
			originalSecret := waitForSecretKey(preserveSecretName, userNS, "client_secret")

			By("triggering a reconcile by updating the spec")
			createOIDCClient(OIDCClientOptions{
				Name:         regenerateSecretClient,
				CallbackURLs: []string{"https://preserve.example.com/callback", "https://preserve.example.com/callback2"},
			})

			time.Sleep(5 * time.Second)

			By("verifying the client_secret is unchanged")
			Consistently(func(g Gomega) {
				currentSecret := kubectlGetSecretData(preserveSecretName, userNS, "client_secret")
				g.Expect(currentSecret).To(Equal(originalSecret))
			}, 20*time.Second, 2*time.Second).Should(Succeed())
		})

		It("should regenerate client_secret when annotation is added", func() {
			preserveSecretName := regenerateSecretClient + "-oidc-credentials"
			originalSecret := waitForSecretKey(preserveSecretName, userNS, "client_secret")

			By("adding the regenerate annotation")
			Expect(kubectlAnnotate("pocketidoidcclient", regenerateSecretClient, userNS,
				"pocketid.internal/regenerate-client-secret=true")).To(Succeed())

			By("verifying the client_secret is regenerated")
			Eventually(func(g Gomega) {
				currentSecret := kubectlGetSecretData(preserveSecretName, userNS, "client_secret")
				g.Expect(currentSecret).NotTo(BeEmpty())
				g.Expect(currentSecret).NotTo(Equal(originalSecret))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying the annotation is removed")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidoidcclient", regenerateSecretClient, "-n", userNS,
					"-o", "jsonpath={.metadata.annotations.pocketid\\.internal/regenerate-client-secret}")
				g.Expect(output).To(BeEmpty())
			}, time.Minute, 2*time.Second).Should(Succeed())
		})
	})
})
