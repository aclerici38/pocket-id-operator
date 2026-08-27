//go:build e2e
// +build e2e

package e2e

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Reference Finalizers", Ordered, func() {
	Context("User Group blocks OIDC Client deletion", func() {
		const (
			finalizerGroupName = "finalizer-oidc-group"
			finalizerOIDCName  = "finalizer-oidc-client"
		)

		It("should block deletion of a user group while referenced by an OIDC client", func() {
			By("creating a user group for OIDC finalizer testing")
			createUserGroupAndWaitReady(UserGroupOptions{
				Name:         finalizerGroupName,
				GroupName:    "finalizer-group",
				FriendlyName: "Finalizer Group",
			})

			By("creating an OIDC client that references the group")
			createOIDCClientAndWaitReady(OIDCClientOptions{
				Name:               finalizerOIDCName,
				CallbackURLs:       []string{"https://example.com/finalizer/callback"},
				LogoutCallbackURLs: []string{"https://example.com/finalizer/logout"},
				AllowedUserGroups:  []string{finalizerGroupName},
			})

			By("waiting for the OIDC client finalizer to land on the user group")
			waitForFinalizer("pocketidusergroup", finalizerGroupName, userNS,
				"pocketid.internal/oidc-client-finalizer")

			By("requesting deletion of the user group")
			deleteObject("pocketidusergroup", finalizerGroupName, userNS)

			By("verifying deletion is blocked by the OIDC client finalizer")
			Eventually(func(g Gomega) {
				deletionTimestamp := getField("pocketidusergroup", finalizerGroupName, userNS, ".metadata.deletionTimestamp")
				finalizers := getField("pocketidusergroup", finalizerGroupName, userNS, ".metadata.finalizers")
				g.Expect(deletionTimestamp).NotTo(BeEmpty())
				g.Expect(finalizers).To(ContainSubstring("pocketid.internal/oidc-client-finalizer"))
			}).Should(Succeed())

			By("deleting the OIDC client")
			deleteObject("pocketidoidcclient", finalizerOIDCName, userNS)

			By("verifying the user group is deleted")
			waitForResourceDeleted("pocketidusergroup", finalizerGroupName, userNS)
		})
	})

	Context("OIDC Client blocks User Group deletion (reverse direction)", func() {
		const (
			revFinalizerGroupName = "rev-finalizer-group"
			revFinalizerOIDCName  = "rev-finalizer-oidc-client"
		)

		It("should block deletion of an OIDC client while referenced by a user group's allowedOIDCClients", func() {
			By("creating an OIDC client")
			createOIDCClientAndWaitReady(OIDCClientOptions{
				Name:         revFinalizerOIDCName,
				CallbackURLs: []string{"https://example.com/rev-finalizer/callback"},
			})

			By("creating a user group that references the OIDC client via allowedOIDCClients")
			createUserGroupAndWaitReady(UserGroupOptions{
				Name:               revFinalizerGroupName,
				GroupName:          "rev-finalizer-group",
				FriendlyName:       "Rev Finalizer Group",
				AllowedOIDCClients: []ResourceRef{{Name: revFinalizerOIDCName}},
			})

			By("waiting for the user group finalizer to land on the OIDC client")
			waitForFinalizer("pocketidoidcclient", revFinalizerOIDCName, userNS,
				"pocketid.internal/user-group-oidc-client-finalizer")

			By("requesting deletion of the OIDC client")
			deleteObject("pocketidoidcclient", revFinalizerOIDCName, userNS)

			By("verifying deletion is blocked by the user group finalizer")
			Eventually(func(g Gomega) {
				deletionTimestamp := getField("pocketidoidcclient", revFinalizerOIDCName, userNS, ".metadata.deletionTimestamp")
				finalizers := getField("pocketidoidcclient", revFinalizerOIDCName, userNS, ".metadata.finalizers")
				g.Expect(deletionTimestamp).NotTo(BeEmpty())
				g.Expect(finalizers).To(ContainSubstring("pocketid.internal/user-group-oidc-client-finalizer"))
			}).Should(Succeed())

			By("deleting the user group")
			deleteObject("pocketidusergroup", revFinalizerGroupName, userNS)

			By("verifying the OIDC client is deleted")
			waitForResourceDeleted("pocketidoidcclient", revFinalizerOIDCName, userNS)
		})
	})

	Context("User blocks User Group deletion", func() {
		const (
			finalizerUserName      = "finalizer-user"
			finalizerUserGroupName = "finalizer-user-group"
		)

		It("should block deletion of a user while referenced by a user group", func() {
			By("creating a user for user group finalizer testing")
			createUserAndWaitReady(UserOptions{
				Name:      finalizerUserName,
				FirstName: "Finalizer",
				Email:     "finalizer-user@example.local",
			})

			By("creating a user group that references the user")
			createUserGroupAndWaitReady(UserGroupOptions{
				Name:         finalizerUserGroupName,
				GroupName:    "finalizer-user-group",
				FriendlyName: "Finalizer User Group",
				UserRefs:     []ResourceRef{{Name: finalizerUserName, Namespace: userNS}},
			})

			By("waiting for the user group finalizer to land on the user")
			waitForFinalizer("pocketiduser", finalizerUserName, userNS,
				"pocketid.internal/user-group-finalizer")

			By("requesting deletion of the user")
			deleteObject("pocketiduser", finalizerUserName, userNS)

			By("verifying deletion is blocked by the user group finalizer")
			Eventually(func(g Gomega) {
				deletionTimestamp := getField("pocketiduser", finalizerUserName, userNS, ".metadata.deletionTimestamp")
				finalizers := getField("pocketiduser", finalizerUserName, userNS, ".metadata.finalizers")
				g.Expect(deletionTimestamp).NotTo(BeEmpty())
				g.Expect(finalizers).To(ContainSubstring("pocketid.internal/user-group-finalizer"))
			}).Should(Succeed())

			By("deleting the user group")
			deleteObject("pocketidusergroup", finalizerUserGroupName, userNS)

			By("verifying the user is deleted")
			waitForResourceDeleted("pocketiduser", finalizerUserName, userNS)
		})
	})
})
