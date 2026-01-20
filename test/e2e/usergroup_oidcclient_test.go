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
		It("should set groupID in status", func() {
			waitForStatusFieldNotEmpty("pocketidusergroup", groupName, userNS, ".status.groupID")
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

		It("should set clientID in status", func() {
			waitForStatusFieldNotEmpty("pocketidoidcclient", oidcClientName, userNS, ".status.clientID")
		})

		It("should include the group in allowedUserGroupIDs", func() {
			groupID := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
				"-o", "jsonpath={.status.groupID}")

			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidoidcclient", oidcClientName, "-n", userNS,
					"-o", "jsonpath={.status.allowedUserGroupIDs[*]}")
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
				"-o", "jsonpath={.status.groupID}")
			groupIDAlt := kubectlGet("pocketidusergroup", recoveryOIDCGroupAlt, "-n", userNS,
				"-o", "jsonpath={.status.groupID}")

			By("verifying allowed group IDs include both groups")
			Eventually(func(g Gomega) {
				output := kubectlGet("pocketidoidcclient", recoveryOIDCName, "-n", userNS,
					"-o", "jsonpath={.status.allowedUserGroupIDs[*]}")
				g.Expect(output).To(ContainSubstring(groupID))
				g.Expect(output).To(ContainSubstring(groupIDAlt))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})
	})
})

var _ = Describe("UserGroup with Usernames and UserIds", Ordered, func() {
	const (
		usernameGroupName   = "test-username-group"
		userIdGroupName     = "test-userid-group"
		mixedGroupName      = "test-mixed-group"
		usernameTestUser    = "username-lookup-user"
		userIdTestUser      = "userid-lookup-user"
		mixedUserRefsUser   = "mixed-userrefs-user"
		mixedUsernameUser   = "mixed-username-user"
		mixedUserIdUser     = "mixed-userid-user"
	)

	Context("User Group with Usernames", func() {
		BeforeAll(func() {
			By("creating a user that will be looked up by username")
			createUserAndWaitReady(UserOptions{
				Name:      usernameTestUser,
				Username:  "e2e-username-lookup",
				FirstName: "Username",
				LastName:  "Lookup",
				Email:     "username-lookup@example.local",
			})
		})

		It("should resolve username and add user to group", func() {
			By("getting the user's ID from status")
			userID := waitForStatusFieldNotEmpty("pocketiduser", usernameTestUser, userNS, ".status.userID")

			By("creating a user group with usernames")
			createUserGroup(UserGroupOptions{
				Name:         usernameGroupName,
				GroupName:    "username-lookup-group",
				FriendlyName: "Username Lookup Group",
				Usernames:    []string{"e2e-username-lookup"},
			})

			By("verifying the group becomes Ready")
			waitForReady("pocketidusergroup", usernameGroupName, userNS)

			By("verifying the group has the correct user")
			Eventually(func(g Gomega) {
				userIDs := kubectlGet("pocketidusergroup", usernameGroupName, "-n", userNS,
					"-o", "jsonpath={.status.userIDs[*]}")
				g.Expect(userIDs).To(ContainSubstring(userID))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should report error for non-existent username", func() {
			nonExistentGroupName := "test-nonexistent-username-group"

			By("creating a user group with a non-existent username")
			createUserGroup(UserGroupOptions{
				Name:         nonExistentGroupName,
				GroupName:    "nonexistent-username-group",
				FriendlyName: "Non-existent Username Group",
				Usernames:    []string{"this-user-does-not-exist-12345"},
			})

			By("verifying the group reports a reconcile error")
			waitForConditionReason("pocketidusergroup", nonExistentGroupName, userNS, "Ready", "ReconcileError")
		})
	})

	Context("User Group with UserIds", func() {
		var userID string

		BeforeAll(func() {
			By("creating a user to get its ID")
			createUserAndWaitReady(UserOptions{
				Name:      userIdTestUser,
				Username:  "e2e-userid-lookup",
				FirstName: "UserId",
				LastName:  "Lookup",
				Email:     "userid-lookup@example.local",
			})

			By("getting the user's ID from status")
			userID = waitForStatusFieldNotEmpty("pocketiduser", userIdTestUser, userNS, ".status.userID")
		})

		It("should add user by ID directly to group", func() {
			By("creating a user group with userIds")
			createUserGroup(UserGroupOptions{
				Name:         userIdGroupName,
				GroupName:    "userid-lookup-group",
				FriendlyName: "UserId Lookup Group",
				UserIds:      []string{userID},
			})

			By("verifying the group becomes Ready")
			waitForReady("pocketidusergroup", userIdGroupName, userNS)

			By("verifying the group has the correct user")
			Eventually(func(g Gomega) {
				userIDs := kubectlGet("pocketidusergroup", userIdGroupName, "-n", userNS,
					"-o", "jsonpath={.status.userIDs[*]}")
				g.Expect(userIDs).To(ContainSubstring(userID))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})
	})

	Context("User Group with Mixed User Specifications", func() {
		var mixedUserIdUserID string

		BeforeAll(func() {
			By("creating users for mixed specification test")
			createUserAndWaitReady(UserOptions{
				Name:      mixedUserRefsUser,
				Username:  "e2e-mixed-userrefs",
				FirstName: "Mixed",
				LastName:  "UserRefs",
				Email:     "mixed-userrefs@example.local",
			})

			createUserAndWaitReady(UserOptions{
				Name:      mixedUsernameUser,
				Username:  "e2e-mixed-username",
				FirstName: "Mixed",
				LastName:  "Username",
				Email:     "mixed-username@example.local",
			})

			createUserAndWaitReady(UserOptions{
				Name:      mixedUserIdUser,
				Username:  "e2e-mixed-userid",
				FirstName: "Mixed",
				LastName:  "UserId",
				Email:     "mixed-userid@example.local",
			})

			By("getting the userId for direct ID reference")
			mixedUserIdUserID = waitForStatusFieldNotEmpty("pocketiduser", mixedUserIdUser, userNS, ".status.userID")
		})

		It("should resolve all three user specification types", func() {
			By("getting user IDs for verification")
			userRefsUserID := waitForStatusFieldNotEmpty("pocketiduser", mixedUserRefsUser, userNS, ".status.userID")
			usernameUserID := waitForStatusFieldNotEmpty("pocketiduser", mixedUsernameUser, userNS, ".status.userID")

			By("creating a user group with userRefs, usernames, and userIds")
			createUserGroup(UserGroupOptions{
				Name:         mixedGroupName,
				GroupName:    "mixed-users-group",
				FriendlyName: "Mixed Users Group",
				UserRefs:     []ResourceRef{{Name: mixedUserRefsUser, Namespace: userNS}},
				Usernames:    []string{"e2e-mixed-username"},
				UserIds:      []string{mixedUserIdUserID},
			})

			By("verifying the group becomes Ready")
			waitForReady("pocketidusergroup", mixedGroupName, userNS)

			By("verifying the group has all 3 users")
			Eventually(func(g Gomega) {
				userIDs := kubectlGet("pocketidusergroup", mixedGroupName, "-n", userNS,
					"-o", "jsonpath={.status.userIDs[*]}")
				g.Expect(userIDs).To(ContainSubstring(userRefsUserID))
				g.Expect(userIDs).To(ContainSubstring(usernameUserID))
				g.Expect(userIDs).To(ContainSubstring(mixedUserIdUserID))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should deduplicate users specified multiple ways", func() {
			dedupeGroupName := "test-dedupe-group"

			By("getting userId of the username user")
			usernameUserID := waitForStatusFieldNotEmpty("pocketiduser", mixedUsernameUser, userNS, ".status.userID")

			By("creating a user group that references the same user via userRef, username, and userId")
			createUserGroup(UserGroupOptions{
				Name:         dedupeGroupName,
				GroupName:    "dedupe-users-group",
				FriendlyName: "Dedupe Users Group",
				UserRefs:     []ResourceRef{{Name: mixedUsernameUser, Namespace: userNS}},
				Usernames:    []string{"e2e-mixed-username"},
				UserIds:      []string{usernameUserID},
			})

			By("verifying the group becomes Ready")
			waitForReady("pocketidusergroup", dedupeGroupName, userNS)

			By("verifying the group has only 1 user (deduplicated)")
			Eventually(func(g Gomega) {
				userIDs := kubectlGet("pocketidusergroup", dedupeGroupName, "-n", userNS,
					"-o", "jsonpath={.status.userIDs[*]}")
				// Should contain the user ID exactly once (no duplicates)
				g.Expect(userIDs).To(Equal(usernameUserID))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})
	})

	Context("User Group Recovery with Usernames", func() {
		const (
			recoveryUsernameGroupName = "test-recovery-username-group"
			recoveryUsernameUserName  = "recovery-username-user"
		)

		It("should recover when user with matching username is created", func() {
			By("creating a user group with a non-existent username")
			createUserGroup(UserGroupOptions{
				Name:         recoveryUsernameGroupName,
				GroupName:    "recovery-username-group",
				FriendlyName: "Recovery Username Group",
				Usernames:    []string{"e2e-recovery-username"},
			})

			By("verifying the group reports a reconcile error")
			waitForConditionReason("pocketidusergroup", recoveryUsernameGroupName, userNS, "Ready", "ReconcileError")

			By("creating the user with the matching username")
			createUserAndWaitReady(UserOptions{
				Name:      recoveryUsernameUserName,
				Username:  "e2e-recovery-username",
				FirstName: "Recovery",
				LastName:  "Username",
				Email:     "recovery-username@example.local",
			})

			By("getting the user's ID")
			userID := waitForStatusFieldNotEmpty("pocketiduser", recoveryUsernameUserName, userNS, ".status.userID")

			By("verifying the group becomes Ready")
			waitForReady("pocketidusergroup", recoveryUsernameGroupName, userNS)

			By("verifying the group has the correct user")
			Eventually(func(g Gomega) {
				userIDs := kubectlGet("pocketidusergroup", recoveryUsernameGroupName, "-n", userNS,
					"-o", "jsonpath={.status.userIDs[*]}")
				g.Expect(userIDs).To(ContainSubstring(userID))
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
			clientID := waitForStatusFieldNotEmpty("pocketidoidcclient", secretClientName, userNS, ".status.clientID")

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
