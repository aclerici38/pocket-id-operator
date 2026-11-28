//go:build e2e

package e2e

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// When spec.users is set the operator owns the group's full member list, so members added
// outside it are removed. When it is unset, membership is never touched.

var _ = Describe("UserGroup Membership Ownership", Ordered, func() {
	const (
		managedUser  = "membership-managed-user"
		externalUser = "membership-external-user"
	)

	var managedUserID, externalUserID string

	BeforeAll(func() {
		By("creating users for membership tests")
		createUserAndWaitReady(UserOptions{Name: managedUser, Email: "membership-managed@example.local"})
		createUserAndWaitReady(UserOptions{Name: externalUser, Email: "membership-external@example.local"})
		managedUserID = waitForStatusFieldNotEmpty("pocketiduser", managedUser, userNS, ".status.userID")
		externalUserID = waitForStatusFieldNotEmpty("pocketiduser", externalUser, userNS, ".status.userID")
	})

	// reconcileWithFriendlyName re-applies the group with a new friendly name, which bumps the
	// generation and so forces a reconcile.
	reconcileWithFriendlyName := func(opts UserGroupOptions, friendlyName string) {
		opts.FriendlyName = friendlyName
		createUserGroup(opts)
		waitForStatusField("pocketidusergroup", opts.Name, userNS, ".status.friendlyName", friendlyName)
		waitForReady("pocketidusergroup", opts.Name, userNS)
	}

	It("should remove members added in the UI when spec.users is set", func() {
		opts := UserGroupOptions{
			Name:      "membership-owned-group",
			GroupName: "membership-owned",
			UserRefs:  []ResourceRef{{Name: managedUser}},
		}
		createUserGroupAndWaitReady(opts)
		groupID := waitForStatusFieldNotEmpty("pocketidusergroup", opts.Name, userNS, ".status.groupID")

		By("adding a user directly via the Pocket-ID API")
		addUserToGroupInPocketID(groupID, externalUserID)
		Expect(getGroupMembersFromPocketID(groupID)).To(ContainSubstring(externalUserID))

		reconcileWithFriendlyName(opts, "Membership Owned Updated")

		Eventually(func(g Gomega) {
			members := getGroupMembersFromPocketID(groupID)
			g.Expect(members).To(Equal(managedUserID), "only the spec's members should remain")
		}).Should(Succeed())
		waitForStatusField("pocketidusergroup", opts.Name, userNS, ".status.totalUserCount", "1")
	})

	It("should keep members added in the UI when spec.users is unset", func() {
		opts := UserGroupOptions{
			Name:      "membership-unowned-group",
			GroupName: "membership-unowned",
		}
		createUserGroupAndWaitReady(opts)
		groupID := waitForStatusFieldNotEmpty("pocketidusergroup", opts.Name, userNS, ".status.groupID")

		By("adding a user directly via the Pocket-ID API")
		addUserToGroupInPocketID(groupID, externalUserID)

		reconcileWithFriendlyName(opts, "Membership Unowned Updated")

		Consistently(func() string {
			return getGroupMembersFromPocketID(groupID)
		}, "10s", "2s").Should(Equal(externalUserID), "members must not be touched without spec.users")
		waitForStatusField("pocketidusergroup", opts.Name, userNS, ".status.totalUserCount", "1")
	})

	It("should replace the members of an adopted group with spec.users", func() {
		const pocketIDName = "membership-adopt"
		groupID := createUserGroupInPocketID(pocketIDName, "Membership Adopt Group")
		addUserToGroupInPocketID(groupID, externalUserID)

		opts := UserGroupOptions{
			Name:      "membership-adopt-group",
			GroupName: pocketIDName,
			UserRefs:  []ResourceRef{{Name: managedUser}},
		}
		createUserGroupAndWaitReady(opts)
		Expect(waitForStatusFieldNotEmpty("pocketidusergroup", opts.Name, userNS, ".status.groupID")).
			To(Equal(groupID), "operator should adopt the existing group")

		Eventually(func() string {
			return getGroupMembersFromPocketID(groupID)
		}).Should(Equal(managedUserID))
	})

	cleanupAfterAll(func() {
		for _, name := range []string{"membership-owned-group", "membership-unowned-group", "membership-adopt-group"} {
			deleteObject("pocketidusergroup", name, userNS)
			waitForResourceDeleted("pocketidusergroup", name, userNS)
		}
	})
})
