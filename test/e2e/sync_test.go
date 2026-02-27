//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// These tests verify that state-diff reconciliation correctly syncs changes to Pocket-ID
// and clears removed fields. They guard the key behaviors introduced in the refactor:
//   - Users: only calls UpdateUser when desired != current (no spurious updates)
//   - UserGroups: only calls the specific field endpoint that changed
//   - Clearing a field (removing users/claims) sends an empty array, not nil

var _ = Describe("User State Sync", func() {
	Context("User field update propagates to Pocket-ID", Ordered, func() {
		const userName = "sync-user-field-update"

		BeforeAll(func() {
			By("creating a user with initial firstName")
			createUserAndWaitReady(UserOptions{
				Name:        userName,
				Username:    "sync-field-update",
				FirstName:   "OriginalFirst",
				LastName:    "Sync",
				Email:       "sync-field@example.local",
				DisplayName: "OriginalFirst Sync",
			})
		})

		It("should reflect firstName change in user-data secret", func() {
			secretName := userName + "-user-data"

			By("verifying initial firstName in user-data secret")
			Expect(kubectlGetSecretData(secretName, userNS, "firstName")).To(Equal("OriginalFirst"))

			By("updating the firstName in spec")
			createUser(UserOptions{
				Name:        userName,
				Username:    "sync-field-update",
				FirstName:   "UpdatedFirst",
				LastName:    "Sync",
				Email:       "sync-field@example.local",
				DisplayName: "UpdatedFirst Sync",
			})

			By("verifying the updated firstName appears in the user-data secret")
			Eventually(func(g Gomega) {
				g.Expect(kubectlGetSecretData(secretName, userNS, "firstName")).To(Equal("UpdatedFirst"))
			}, time.Minute, 2*time.Second).Should(Succeed())
		})

		It("should reflect displayName change in user-data secret", func() {
			secretName := userName + "-user-data"

			By("updating the displayName in spec")
			createUser(UserOptions{
				Name:        userName,
				Username:    "sync-field-update",
				FirstName:   "UpdatedFirst",
				LastName:    "Sync",
				Email:       "sync-field@example.local",
				DisplayName: "Totally New Name",
			})

			By("verifying the updated displayName appears in the user-data secret")
			Eventually(func(g Gomega) {
				g.Expect(kubectlGetSecretData(secretName, userNS, "displayName")).To(Equal("Totally New Name"))
			}, time.Minute, 2*time.Second).Should(Succeed())
		})
	})
})

var _ = Describe("UserGroup State Sync", Ordered, func() {
	// Shared user created once for all tests in this Describe.
	const syncTestUser = "sync-group-test-user"

	BeforeAll(func() {
		By("creating a shared user for group membership tests")
		createUserAndWaitReady(UserOptions{
			Name:  syncTestUser,
			Email: "sync-group-user@example.local",
		})
	})

	Context("User removal from group clears status.userIDs", func() {
		const groupName = "sync-remove-users-group"

		It("should clear userIDs in status when all users are removed from spec", func() {
			By("creating a user group with a member")
			createUserGroupAndWaitReady(UserGroupOptions{
				Name:      groupName,
				GroupName: "sync-remove-users",
				UserRefs:  []ResourceRef{{Name: syncTestUser}},
			})

			By("verifying the user appears in status.userIDs")
			userID := waitForStatusFieldNotEmpty("pocketiduser", syncTestUser, userNS, ".status.userID")
			Eventually(func(g Gomega) {
				ids := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.userIDs[*]}")
				g.Expect(ids).To(ContainSubstring(userID))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("removing all users from the spec")
			createUserGroup(UserGroupOptions{
				Name:      groupName,
				GroupName: "sync-remove-users",
				// UserRefs intentionally absent — all users removed
			})

			By("verifying status.userIDs becomes empty")
			Eventually(func(g Gomega) {
				ids := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.userIDs}")
				g.Expect(ids).To(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			waitForReady("pocketidusergroup", groupName, userNS)
		})
	})

	Context("Custom claims removal clears status.customClaims", func() {
		const groupName = "sync-remove-claims-group"

		It("should clear customClaims in status when all claims are removed from spec", func() {
			By("creating a user group with a custom claim")
			createUserGroupAndWaitReady(UserGroupOptions{
				Name:         groupName,
				GroupName:    "sync-remove-claims",
				CustomClaims: []CustomClaim{{Key: "env", Value: "staging"}},
			})

			By("verifying the claim appears in status.customClaims")
			Eventually(func(g Gomega) {
				val := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.customClaims[?(@.key=='env')].value}")
				g.Expect(val).To(Equal("staging"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("removing all custom claims from the spec")
			createUserGroup(UserGroupOptions{
				Name:      groupName,
				GroupName: "sync-remove-claims",
				// CustomClaims intentionally absent — all claims removed
			})

			By("verifying status.customClaims becomes empty")
			Eventually(func(g Gomega) {
				val := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.customClaims}")
				g.Expect(val).To(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			waitForReady("pocketidusergroup", groupName, userNS)
		})
	})

	Context("Group name and friendlyName update syncs to status", func() {
		const groupName = "sync-rename-group"

		It("should reflect updated name and friendlyName in status", func() {
			By("creating a user group with original name")
			createUserGroupAndWaitReady(UserGroupOptions{
				Name:         groupName,
				GroupName:    "sync-original-name",
				FriendlyName: "Original Friendly",
			})

			By("verifying initial name in status")
			waitForStatusField("pocketidusergroup", groupName, userNS, ".status.name", "sync-original-name")

			By("updating the group name and friendlyName in spec")
			createUserGroup(UserGroupOptions{
				Name:         groupName,
				GroupName:    "sync-updated-name",
				FriendlyName: "Updated Friendly",
			})

			By("verifying status reflects the updated name")
			Eventually(func(g Gomega) {
				name := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.name}")
				g.Expect(name).To(Equal("sync-updated-name"))
				friendly := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.friendlyName}")
				g.Expect(friendly).To(Equal("Updated Friendly"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			waitForReady("pocketidusergroup", groupName, userNS)
		})
	})

	Context("Name-only update does not disrupt existing users or claims", func() {
		const groupName = "sync-name-only-group"

		It("should preserve users and claims when only the name changes", func() {
			By("creating a user group with a user and a claim")
			createUserGroupAndWaitReady(UserGroupOptions{
				Name:         groupName,
				GroupName:    "sync-name-only-orig",
				FriendlyName: "Name Only Orig",
				CustomClaims: []CustomClaim{{Key: "tier", Value: "gold"}},
				UserRefs:     []ResourceRef{{Name: syncTestUser}},
			})

			userID := waitForStatusFieldNotEmpty("pocketiduser", syncTestUser, userNS, ".status.userID")

			By("verifying initial user and claim are present")
			Eventually(func(g Gomega) {
				ids := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.userIDs[*]}")
				g.Expect(ids).To(ContainSubstring(userID))
				val := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.customClaims[?(@.key=='tier')].value}")
				g.Expect(val).To(Equal("gold"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("updating only the name (preserving users and claims in spec)")
			createUserGroup(UserGroupOptions{
				Name:         groupName,
				GroupName:    "sync-name-only-new",
				FriendlyName: "Name Only New",
				CustomClaims: []CustomClaim{{Key: "tier", Value: "gold"}},
				UserRefs:     []ResourceRef{{Name: syncTestUser}},
			})

			By("verifying the name updated in status")
			Eventually(func(g Gomega) {
				name := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.name}")
				g.Expect(name).To(Equal("sync-name-only-new"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying users and claims are still present")
			Eventually(func(g Gomega) {
				ids := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.userIDs[*]}")
				g.Expect(ids).To(ContainSubstring(userID))
				val := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.customClaims[?(@.key=='tier')].value}")
				g.Expect(val).To(Equal("gold"))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			waitForReady("pocketidusergroup", groupName, userNS)
		})
	})
})

var _ = Describe("EmailVerified Preservation", Ordered, func() {
	// Verifies that the operator never resets a user's emailVerified status in Pocket-ID.
	// A user created directly via the Pocket-ID API with emailVerified=true is adopted by
	// a CR, and after multiple reconcile cycles the flag must remain true.

	const (
		crName   = "sync-email-verified"
		username = "sync-email-verified-user"
	)

	BeforeAll(func() {
		By("creating a user directly in Pocket-ID with emailVerified=true")
		createUserInPocketIDWithVerifiedEmail("create-verified-user", userNS, username, "sync-verified@example.local")
	})

	It("should adopt the pre-existing user and reflect emailVerified=true in status", func() {
		By("creating a PocketIDUser CR whose username matches the pre-existing user")
		createUserAndWaitReady(UserOptions{
			Name:      crName,
			Username:  username,
			FirstName: "Verified",
			LastName:  "User",
			Email:     "sync-verified@example.local",
		})

		By("verifying status.emailVerified is true after adoption")
		waitForStatusField("pocketiduser", crName, userNS, ".status.emailVerified", "true")
	})

	It("should preserve emailVerified=true across multiple reconcile cycles", func() {
		By("waiting for at least 2 reconcile cycles at RESYNC_INTERVAL=5s")
		time.Sleep(15 * time.Second)

		By("verifying status.emailVerified is still true")
		Expect(kubectlGet("pocketiduser", crName, "-n", userNS,
			"-o", "jsonpath={.status.emailVerified}")).To(Equal("true"))

		By("verifying Pocket-ID still has emailVerified=true for the user")
		userID := kubectlGet("pocketiduser", crName, "-n", userNS,
			"-o", "jsonpath={.status.userID}")
		Expect(getUserEmailVerified("check-email-verified", userNS, userID)).To(Equal("true"))
	})

	AfterAll(func() {
		kubectlDelete("pocketiduser", crName, userNS)
		waitForResourceDeleted("pocketiduser", crName, userNS)
		kubectlDelete("pod", "create-verified-user", userNS)
		kubectlDelete("pod", "check-email-verified", userNS)
	})
})

// --- User API Helpers ---

// createUserInPocketIDWithVerifiedEmail creates a user directly in Pocket-ID via the API
// with emailVerified=true and waits for the curl pod to succeed.
func createUserInPocketIDWithVerifiedEmail(podName, namespace, username, email string) {
	staticSecretName := instanceName + "-static-api-key"
	apiKeyBase64 := kubectlGet("secret", staticSecretName, "-n", instanceNS,
		"-o", "jsonpath={.data.token}")
	Expect(apiKeyBase64).NotTo(BeEmpty(), "static API key secret should exist")

	script := fmt.Sprintf(`API_KEY=$(echo '%s' | base64 -d)
BODY=$(curl -s -X POST \
  -H "X-API-KEY: $API_KEY" -H "Content-Type: application/json" \
  -d '{"username":"%s","firstName":"%s","displayName":"%s","email":"%s","emailVerified":true}' \
  -o /tmp/body -w '%%{http_code}' \
  %s/api/users)
HTTP_CODE="$BODY"
BODY=$(cat /tmp/body)
if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "201" ]; then
  echo "Failed to create user: HTTP $HTTP_CODE: $BODY" >&2
  exit 1
fi`,
		apiKeyBase64, username, username, username, email, formatInstanceURL())

	applyYAML(createCurlPodYAML(podName, namespace, script))
	waitForPodSucceeded(podName, namespace)
}

// getUserEmailVerified queries Pocket-ID for a user by ID and returns "true" or "false"
// based on the emailVerified field.
func getUserEmailVerified(podName, namespace, userID string) string {
	staticSecretName := instanceName + "-static-api-key"
	apiKeyBase64 := kubectlGet("secret", staticSecretName, "-n", instanceNS,
		"-o", "jsonpath={.data.token}")
	Expect(apiKeyBase64).NotTo(BeEmpty(), "static API key secret should exist")

	script := fmt.Sprintf(`API_KEY=$(echo '%s' | base64 -d)
BODY=$(curl -s -H "X-API-KEY: $API_KEY" %s/api/users/%s)
if echo "$BODY" | grep -q '"emailVerified":true'; then
  echo "true"
else
  echo "false"
fi`,
		apiKeyBase64, formatInstanceURL(), userID)

	applyYAML(createCurlPodYAML(podName, namespace, script))
	waitForPodSucceeded(podName, namespace)
	return kubectlLogs(podName, namespace)
}
