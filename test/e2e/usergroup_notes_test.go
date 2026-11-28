//go:build e2e

package e2e

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("UserGroup Notes", Ordered, func() {
	const groupName = "test-group-notes"

	It("should write spec.notes and clear the notes once it is unset", func() {
		opts := UserGroupOptions{Name: groupName, Notes: "managed by the operator"}
		createUserGroupAndWaitReady(opts)
		groupID := waitForStatusFieldNotEmpty("pocketidusergroup", groupName, userNS, ".status.groupID")
		groupBody := func() string { return getFromPocketID("/api/admin/user-groups/" + groupID) }
		Expect(groupBody()).To(ContainSubstring(`"notes":"managed by the operator"`))

		By("removing spec.notes, with a new friendly name to force a reconcile")
		opts.Notes, opts.FriendlyName = "", "Notes Updated"
		createUserGroup(opts)
		waitForStatusField("pocketidusergroup", groupName, userNS, ".status.friendlyName", "Notes Updated")
		Expect(groupBody()).To(ContainSubstring(`"notes":""`), "notes should be cleared once spec.notes is unset")
	})

	cleanupAfterAll(func() {
		deleteObject("pocketidusergroup", groupName, userNS)
		waitForResourceDeleted("pocketidusergroup", groupName, userNS)
	})
})
