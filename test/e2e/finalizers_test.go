//go:build e2e
// +build e2e

package e2e

import (
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aclerici38/pocket-id-operator/test/utils"
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

			By("requesting deletion of the user group")
			cmd := exec.Command("kubectl", "delete", "pocketidusergroup", finalizerGroupName,
				"-n", userNS, "--wait=false")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying deletion is blocked by the OIDC client finalizer")
			Eventually(func(g Gomega) {
				deletionTimestamp := kubectlGet("pocketidusergroup", finalizerGroupName, "-n", userNS,
					"-o", "jsonpath={.metadata.deletionTimestamp}")
				finalizers := kubectlGet("pocketidusergroup", finalizerGroupName, "-n", userNS,
					"-o", "jsonpath={.metadata.finalizers}")
				g.Expect(deletionTimestamp).NotTo(BeEmpty())
				g.Expect(finalizers).To(ContainSubstring("pocketid.internal/oidc-client-finalizer"))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("deleting the OIDC client")
			cmd = exec.Command("kubectl", "delete", "pocketidoidcclient", finalizerOIDCName, "-n", userNS)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

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

			By("requesting deletion of the OIDC client")
			cmd := exec.Command("kubectl", "delete", "pocketidoidcclient", revFinalizerOIDCName,
				"-n", userNS, "--wait=false")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying deletion is blocked by the user group finalizer")
			Eventually(func(g Gomega) {
				deletionTimestamp := kubectlGet("pocketidoidcclient", revFinalizerOIDCName, "-n", userNS,
					"-o", "jsonpath={.metadata.deletionTimestamp}")
				finalizers := kubectlGet("pocketidoidcclient", revFinalizerOIDCName, "-n", userNS,
					"-o", "jsonpath={.metadata.finalizers}")
				g.Expect(deletionTimestamp).NotTo(BeEmpty())
				g.Expect(finalizers).To(ContainSubstring("pocketid.internal/user-group-oidc-client-finalizer"))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("deleting the user group")
			cmd = exec.Command("kubectl", "delete", "pocketidusergroup", revFinalizerGroupName, "-n", userNS)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

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

			By("requesting deletion of the user")
			cmd := exec.Command("kubectl", "delete", "pocketiduser", finalizerUserName,
				"-n", userNS, "--wait=false")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying deletion is blocked by the user group finalizer")
			Eventually(func(g Gomega) {
				deletionTimestamp := kubectlGet("pocketiduser", finalizerUserName, "-n", userNS,
					"-o", "jsonpath={.metadata.deletionTimestamp}")
				finalizers := kubectlGet("pocketiduser", finalizerUserName, "-n", userNS,
					"-o", "jsonpath={.metadata.finalizers}")
				g.Expect(deletionTimestamp).NotTo(BeEmpty())
				g.Expect(finalizers).To(ContainSubstring("pocketid.internal/user-group-finalizer"))
			}, time.Minute, 2*time.Second).Should(Succeed())

			By("deleting the user group")
			cmd = exec.Command("kubectl", "delete", "pocketidusergroup", finalizerUserGroupName, "-n", userNS)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the user is deleted")
			waitForResourceDeleted("pocketiduser", finalizerUserName, userNS)
		})
	})
})
