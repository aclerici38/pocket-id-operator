//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("External Deletion Recovery", Ordered, func() {
	// These tests verify that when a resource is deleted directly from Pocket-ID
	// (e.g., via UI or API), the operator detects this and recreates the resource.

	Context("User External Deletion", func() {
		const userName = "test-external-delete-user"

		It("should recreate user after external deletion from Pocket-ID", func() {
			By("creating a user and waiting for it to be ready")
			createUserAndWaitReady(UserOptions{
				Name:      userName,
				Username:  "external-delete-user",
				FirstName: "External",
				LastName:  "Delete",
				Email:     "external-delete@example.local",
			})

			By("getting the original user ID")
			originalUserID := waitForStatusFieldNotEmpty("pocketiduser", userName, userNS, ".status.userID")

			By("deleting the user directly from Pocket-ID via API")
			deleteFromPocketID(fmt.Sprintf("/api/users/%s", originalUserID))

			By("waiting for the operator to detect deletion and recreate the user")
			Eventually(func(g Gomega) {
				// The user should become ready again with a new ID
				newUserID := kubectlGet("pocketiduser", userName, "-n", userNS,
					"-o", "jsonpath={.status.userID}")
				g.Expect(newUserID).NotTo(BeEmpty())
				g.Expect(newUserID).NotTo(Equal(originalUserID), "user should have a new ID after recreation")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the user is ready")
			waitForReady("pocketiduser", userName, userNS)
		})
	})

	Context("UserGroup External Deletion", func() {
		const groupName = "test-external-delete-group"

		It("should recreate user group after external deletion from Pocket-ID", func() {
			By("creating a user group and waiting for it to be ready")
			createUserGroupAndWaitReady(UserGroupOptions{
				Name:         groupName,
				GroupName:    "external-delete-group",
				FriendlyName: "External Delete Group",
			})

			By("getting the original group ID")
			originalGroupID := waitForStatusFieldNotEmpty("pocketidusergroup", groupName, userNS, ".status.groupID")

			By("deleting the group directly from Pocket-ID via API")
			deleteFromPocketID(fmt.Sprintf("/api/user-groups/%s", originalGroupID))

			By("waiting for the operator to detect deletion and recreate the group")
			Eventually(func(g Gomega) {
				// The group should become ready again with a new ID
				newGroupID := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.groupID}")
				g.Expect(newGroupID).NotTo(BeEmpty())
				g.Expect(newGroupID).NotTo(Equal(originalGroupID), "group should have a new ID after recreation")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the group is ready")
			waitForReady("pocketidusergroup", groupName, userNS)
		})
	})

	Context("OIDCClient External Deletion", func() {
		const clientName = "test-external-delete-oidc"

		It("should recreate OIDC client after external deletion from Pocket-ID", func() {
			By("creating an OIDC client and waiting for it to be ready")
			createOIDCClientAndWaitReady(OIDCClientOptions{
				Name:         clientName,
				CallbackURLs: []string{"https://external-delete.example.com/callback"},
			})

			By("getting the original client ID")
			originalClientID := waitForStatusFieldNotEmpty("pocketidoidcclient", clientName, userNS, ".status.clientID")

			By("deleting the client directly from Pocket-ID via API")
			deleteFromPocketID(fmt.Sprintf("/api/oidc/clients/%s", originalClientID))

			By("waiting for the operator to detect deletion and recreate the client")
			Eventually(func(g Gomega) {
				// The client should become ready again
				// Note: OIDC client IDs may be the same if specified in spec, so we check ready state
				condition := kubectlGet("pocketidoidcclient", clientName, "-n", userNS,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				g.Expect(condition).To(Equal("True"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("verifying the client secret still exists")
			secretName := clientName + "-oidc-credentials"
			waitForSecretExists(secretName, userNS)
		})
	})
})
