//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// These tests verify the non-destructive (merge-based) membership reconciliation
// for user groups. The operator should only manage users declared in the CR and
// never remove externally-added users.

var _ = Describe("UserGroup Membership Merge Behavior", Ordered, func() {
	const (
		managedUser    = "merge-managed-user"
		managedUser2   = "merge-managed-user-2"
		externalUser   = "merge-external-user"
		mergeGroupName = "merge-test-group"
	)

	BeforeAll(func() {
		By("creating users for membership merge tests")
		createUserAndWaitReady(UserOptions{
			Name:  managedUser,
			Email: "merge-managed@example.local",
		})
		createUserAndWaitReady(UserOptions{
			Name:  managedUser2,
			Email: "merge-managed-2@example.local",
		})
		createUserAndWaitReady(UserOptions{
			Name:  externalUser,
			Email: "merge-external@example.local",
		})
	})

	Context("External users are preserved across reconciles", func() {
		It("should not remove a user added via the Pocket-ID UI", func() {
			managedUserID := waitForStatusFieldNotEmpty("pocketiduser", managedUser, userNS, ".status.userID")
			externalUserID := waitForStatusFieldNotEmpty("pocketiduser", externalUser, userNS, ".status.userID")

			By("creating a user group with one managed user")
			createUserGroupAndWaitReady(UserGroupOptions{
				Name:      mergeGroupName,
				GroupName: "merge-test",
				UserRefs:  []ResourceRef{{Name: managedUser}},
			})

			By("verifying the managed user is in status.managedUserIDs")
			Eventually(func(g Gomega) {
				ids := kubectlGet("pocketidusergroup", mergeGroupName, "-n", userNS,
					"-o", "jsonpath={.status.managedUserIDs[*]}")
				g.Expect(ids).To(ContainSubstring(managedUserID))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			groupID := waitForStatusFieldNotEmpty("pocketidusergroup", mergeGroupName, userNS, ".status.groupID")

			By("adding an external user directly via the Pocket-ID API")
			addUserToGroupInPocketID("add-external-user", userNS, groupID, externalUserID)

			By("verifying the external user exists in Pocket-ID")
			Eventually(func(g Gomega) {
				members := getGroupMembersFromPocketID("check-members-1", userNS, groupID)
				g.Expect(members).To(ContainSubstring(externalUserID))
				g.Expect(members).To(ContainSubstring(managedUserID))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("triggering a reconcile by updating the group friendlyName")
			createUserGroup(UserGroupOptions{
				Name:         mergeGroupName,
				GroupName:    "merge-test",
				FriendlyName: "Merge Test Updated",
				UserRefs:     []ResourceRef{{Name: managedUser}},
			})
			waitForReady("pocketidusergroup", mergeGroupName, userNS)

			By("verifying the external user is still in the group in Pocket-ID after reconcile")
			Eventually(func(g Gomega) {
				members := getGroupMembersFromPocketID("check-members-2", userNS, groupID)
				g.Expect(members).To(ContainSubstring(externalUserID),
					"external user should be preserved after reconcile")
				g.Expect(members).To(ContainSubstring(managedUserID),
					"managed user should still be present")
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying status.managedUserIDs only contains the managed user")
			ids := kubectlGet("pocketidusergroup", mergeGroupName, "-n", userNS,
				"-o", "jsonpath={.status.managedUserIDs[*]}")
			Expect(ids).To(ContainSubstring(managedUserID))
			Expect(ids).NotTo(ContainSubstring(externalUserID),
				"external user should NOT appear in managedUserIDs")
		})

		AfterAll(func() {
			kubectlDelete("pod", "add-external-user", userNS)
			kubectlDelete("pod", "check-members-1", userNS)
			kubectlDelete("pod", "check-members-2", userNS)
		})
	})

	Context("Removing a managed user preserves external users", func() {
		const groupName = "merge-remove-managed-group"

		It("should remove only the managed user dropped from CR, keeping external users", func() {
			managedUserID := waitForStatusFieldNotEmpty("pocketiduser", managedUser, userNS, ".status.userID")
			managedUser2ID := waitForStatusFieldNotEmpty("pocketiduser", managedUser2, userNS, ".status.userID")
			externalUserID := waitForStatusFieldNotEmpty("pocketiduser", externalUser, userNS, ".status.userID")

			By("creating a user group with two managed users")
			createUserGroupAndWaitReady(UserGroupOptions{
				Name:      groupName,
				GroupName: "merge-remove-managed",
				UserRefs:  []ResourceRef{{Name: managedUser}, {Name: managedUser2}},
			})

			groupID := waitForStatusFieldNotEmpty("pocketidusergroup", groupName, userNS, ".status.groupID")

			By("adding an external user directly via the Pocket-ID API")
			addUserToGroupInPocketID("add-ext-for-remove", userNS, groupID, externalUserID)

			By("verifying all three users are in the group")
			Eventually(func(g Gomega) {
				members := getGroupMembersFromPocketID("check-3-members", userNS, groupID)
				g.Expect(members).To(ContainSubstring(managedUserID))
				g.Expect(members).To(ContainSubstring(managedUser2ID))
				g.Expect(members).To(ContainSubstring(externalUserID))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("removing managedUser2 from the CR")
			createUserGroup(UserGroupOptions{
				Name:      groupName,
				GroupName: "merge-remove-managed",
				UserRefs:  []ResourceRef{{Name: managedUser}}, // managedUser2 removed
			})
			waitForReady("pocketidusergroup", groupName, userNS)

			By("verifying managedUser2 was removed but external user and managedUser are preserved")
			Eventually(func(g Gomega) {
				members := getGroupMembersFromPocketID("check-after-remove", userNS, groupID)
				g.Expect(members).To(ContainSubstring(managedUserID),
					"remaining managed user should still be present")
				g.Expect(members).To(ContainSubstring(externalUserID),
					"external user should be preserved")
				g.Expect(members).NotTo(ContainSubstring(managedUser2ID),
					"removed managed user should be gone")
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying status.managedUserIDs reflects only the remaining managed user")
			Eventually(func(g Gomega) {
				ids := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.managedUserIDs[*]}")
				g.Expect(ids).To(ContainSubstring(managedUserID))
				g.Expect(ids).NotTo(ContainSubstring(managedUser2ID))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})

		AfterAll(func() {
			for _, pod := range []string{"add-ext-for-remove", "check-3-members", "check-after-remove"} {
				kubectlDelete("pod", pod, userNS)
			}
		})
	})

	Context("Clearing all managed users preserves external users", func() {
		const groupName = "merge-clear-all-group"

		It("should remove all managed users but preserve external users when spec.users is cleared", func() {
			managedUserID := waitForStatusFieldNotEmpty("pocketiduser", managedUser, userNS, ".status.userID")
			externalUserID := waitForStatusFieldNotEmpty("pocketiduser", externalUser, userNS, ".status.userID")

			By("creating a user group with a managed user")
			createUserGroupAndWaitReady(UserGroupOptions{
				Name:      groupName,
				GroupName: "merge-clear-all",
				UserRefs:  []ResourceRef{{Name: managedUser}},
			})

			groupID := waitForStatusFieldNotEmpty("pocketidusergroup", groupName, userNS, ".status.groupID")

			By("adding an external user directly via the Pocket-ID API")
			addUserToGroupInPocketID("add-ext-for-clear", userNS, groupID, externalUserID)

			By("verifying both users are in the group")
			Eventually(func(g Gomega) {
				members := getGroupMembersFromPocketID("check-before-clear", userNS, groupID)
				g.Expect(members).To(ContainSubstring(managedUserID))
				g.Expect(members).To(ContainSubstring(externalUserID))
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("clearing all users from the CR spec")
			createUserGroup(UserGroupOptions{
				Name:      groupName,
				GroupName: "merge-clear-all",
				// UserRefs intentionally absent — all managed users removed
			})
			waitForReady("pocketidusergroup", groupName, userNS)

			By("verifying managed user was removed but external user is preserved in Pocket-ID")
			Eventually(func(g Gomega) {
				members := getGroupMembersFromPocketID("check-after-clear", userNS, groupID)
				g.Expect(members).To(ContainSubstring(externalUserID),
					"external user should be preserved")
				g.Expect(members).NotTo(ContainSubstring(managedUserID),
					"managed user should be removed")
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying status.managedUserIDs is empty")
			Eventually(func(g Gomega) {
				ids := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.managedUserIDs}")
				g.Expect(ids).To(BeEmpty())
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		})

		AfterAll(func() {
			for _, pod := range []string{"add-ext-for-clear", "check-before-clear", "check-after-clear"} {
				kubectlDelete("pod", pod, userNS)
			}
		})
	})

	Context("Adoption preserves existing group members", func() {
		const (
			adoptGroupName    = "merge-adopt-group"
			adoptPocketIDName = "merge-adopt-test"
			adoptUser         = "merge-adopt-user"
		)

		It("should adopt a group with existing users and not remove them", func() {
			By("creating a user that will be pre-existing in the group")
			createUserAndWaitReady(UserOptions{
				Name:  adoptUser,
				Email: "merge-adopt@example.local",
			})
			preExistingUserID := waitForStatusFieldNotEmpty("pocketiduser", adoptUser, userNS, ".status.userID")
			managedUserID := waitForStatusFieldNotEmpty("pocketiduser", managedUser, userNS, ".status.userID")

			By("creating a group directly in Pocket-ID with a user")
			groupID := createUserGroupInPocketID("create-adopt-merge-group", userNS, adoptPocketIDName, "Merge Adopt Group")

			By("adding the pre-existing user to the group via API")
			addUserToGroupInPocketID("add-pre-existing", userNS, groupID, preExistingUserID)

			By("creating a CR that adopts the group and adds a managed user")
			createUserGroupAndWaitReady(UserGroupOptions{
				Name:      adoptGroupName,
				GroupName: adoptPocketIDName,
				UserRefs:  []ResourceRef{{Name: managedUser}},
			})

			By("verifying the operator adopted the group (same group ID)")
			adoptedGroupID := waitForStatusFieldNotEmpty("pocketidusergroup", adoptGroupName, userNS, ".status.groupID")
			Expect(adoptedGroupID).To(Equal(groupID), "operator should adopt the existing group")

			By("verifying both the pre-existing and managed users are in the group")
			Eventually(func(g Gomega) {
				members := getGroupMembersFromPocketID("check-adopt-members", userNS, groupID)
				g.Expect(members).To(ContainSubstring(preExistingUserID),
					"pre-existing user should be preserved after adoption")
				g.Expect(members).To(ContainSubstring(managedUserID),
					"managed user should be added to the group")
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying status.managedUserIDs only contains the CR-declared user")
			ids := kubectlGet("pocketidusergroup", adoptGroupName, "-n", userNS,
				"-o", "jsonpath={.status.managedUserIDs[*]}")
			Expect(ids).To(ContainSubstring(managedUserID))
			Expect(ids).NotTo(ContainSubstring(preExistingUserID),
				"pre-existing user should NOT be in managedUserIDs")
		})

		AfterAll(func() {
			kubectlDelete("pocketidusergroup", adoptGroupName, userNS)
			waitForResourceDeleted("pocketidusergroup", adoptGroupName, userNS)
			for _, pod := range []string{"create-adopt-merge-group", "add-pre-existing", "check-adopt-members"} {
				kubectlDelete("pod", pod, userNS)
			}
		})
	})

	Context("TotalUserCount reflects all members including external", func() {
		const groupName = "merge-count-group"

		It("should report totalUserCount including external users", func() {
			managedUserID := waitForStatusFieldNotEmpty("pocketiduser", managedUser, userNS, ".status.userID")
			externalUserID := waitForStatusFieldNotEmpty("pocketiduser", externalUser, userNS, ".status.userID")

			By("creating a user group with one managed user")
			createUserGroupAndWaitReady(UserGroupOptions{
				Name:      groupName,
				GroupName: "merge-count",
				UserRefs:  []ResourceRef{{Name: managedUser}},
			})

			By("verifying totalUserCount is 1")
			waitForStatusField("pocketidusergroup", groupName, userNS, ".status.totalUserCount", "1")

			groupID := waitForStatusFieldNotEmpty("pocketidusergroup", groupName, userNS, ".status.groupID")

			By(fmt.Sprintf("adding external user %s to group %s via Pocket-ID API", externalUserID, groupID))
			addUserToGroupInPocketID("add-ext-for-count", userNS, groupID, externalUserID)

			By("triggering a reconcile and verifying totalUserCount reflects 2 users")
			// Trigger reconcile by re-applying the same spec (friendlyName change)
			createUserGroup(UserGroupOptions{
				Name:         groupName,
				GroupName:    "merge-count",
				FriendlyName: "Merge Count Updated",
				UserRefs:     []ResourceRef{{Name: managedUser}},
			})
			waitForReady("pocketidusergroup", groupName, userNS)

			Eventually(func(g Gomega) {
				count := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
					"-o", "jsonpath={.status.totalUserCount}")
				g.Expect(count).To(Equal("2"),
					"totalUserCount should include both managed and external users")
			}, 2*time.Minute, 2*time.Second).Should(Succeed())

			By("verifying managedUserIDs still only has 1 entry")
			ids := kubectlGet("pocketidusergroup", groupName, "-n", userNS,
				"-o", "jsonpath={.status.managedUserIDs[*]}")
			Expect(strings.Fields(ids)).To(HaveLen(1))
			Expect(ids).To(ContainSubstring(managedUserID))
		})

		AfterAll(func() {
			kubectlDelete("pod", "add-ext-for-count", userNS)
		})
	})
})
